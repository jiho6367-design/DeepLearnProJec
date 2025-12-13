import base64
import html
import os
import re
from typing import Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from backend.app.config import get_settings
from backend.app.models.tables import OAuthToken, User
from backend.app.security.crypto import decrypt_token, encrypt_token

settings = get_settings()


async def ensure_access_token(user: User, db: Session) -> str:
    token_row: Optional[OAuthToken] = (
        db.query(OAuthToken).filter(OAuthToken.user_id == user.id).first()
    )
    if not token_row:
        raise ValueError("Refresh token not found for user")

    refresh_token = decrypt_token(token_row.refresh_token_enc)
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()
    access_token = data["access_token"]
    expires_in = data.get("expires_in")
    token_row.access_token_enc = encrypt_token(access_token)
    if expires_in:
        from datetime import datetime, timedelta

        token_row.token_expiry = datetime.utcnow() + timedelta(seconds=int(expires_in))
    db.commit()
    return access_token


async def _get_user_info(access_token: str) -> Dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


async def list_messages(user: User, db: Session, page_token: Optional[str] = None) -> Dict:
    access_token = await ensure_access_token(user, db)
    params = {"maxResults": 10, "labelIds": "INBOX"}
    if page_token:
        params["pageToken"] = page_token
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            params=params,
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        message_ids = data.get("messages", [])
        messages = []
        for msg in message_ids:
            meta = await _fetch_message_metadata(client, access_token, msg["id"])
            messages.append(meta)
        return {"messages": messages, "nextPageToken": data.get("nextPageToken")}


async def _fetch_message_metadata(client: httpx.AsyncClient, access_token: str, message_id: str):
    resp = await client.get(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
        params={"format": "metadata", "metadataHeaders": ["Subject", "From", "Date"]},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    resp.raise_for_status()
    data = resp.json()
    headers = {h["name"].lower(): h["value"] for h in data.get("payload", {}).get("headers", [])}
    return {
        "id": data.get("id"),
        "subject": headers.get("subject"),
        "from": headers.get("from"),
        "date": headers.get("date"),
        "snippet": data.get("snippet"),
    }


async def get_message_detail(user: User, db: Session, message_id: str) -> Dict:
    access_token = await ensure_access_token(user, db)
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
            params={"format": "full"},
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        body = extract_body(data.get("payload", {}))
        cleaned = clean_html(body) if body else ""
        meta_headers = {h["name"].lower(): h["value"] for h in data.get("payload", {}).get("headers", [])}
        return {
            "id": data.get("id"),
            "subject": meta_headers.get("subject"),
            "from": meta_headers.get("from"),
            "date": meta_headers.get("date"),
            "body": cleaned,
        }


def extract_body(payload: Dict) -> str:
    if not payload:
        return ""
    mime_type = payload.get("mimeType", "")
    data = payload.get("body", {}).get("data")
    if data:
        decoded = base64.urlsafe_b64decode(data.encode()).decode(errors="ignore")
        if mime_type == "text/html":
            return decoded
        return decoded
    parts: List[Dict] = payload.get("parts", [])
    texts = []
    htmls = []
    for part in parts:
        part_mime = part.get("mimeType", "")
        part_data = part.get("body", {}).get("data")
        if part_data:
            decoded = base64.urlsafe_b64decode(part_data.encode()).decode(errors="ignore")
            if part_mime == "text/plain":
                texts.append(decoded)
            elif part_mime == "text/html":
                htmls.append(decoded)
        nested = extract_body(part)
        if nested:
            if "html" in part_mime:
                htmls.append(nested)
            else:
                texts.append(nested)
    if texts:
        return "\n".join(texts)
    if htmls:
        return "\n".join(htmls)
    return ""


def clean_html(raw: str) -> str:
    no_script = re.sub(r"<(script|style)[^>]*>.*?</\\1>", "", raw, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", no_script)
    text = html.unescape(text)
    text = re.sub(r"\\s+", " ", text)
    return text.strip()


__all__ = [
    "ensure_access_token",
    "list_messages",
    "get_message_detail",
    "_get_user_info",
    "clean_html",
    "extract_body",
]
