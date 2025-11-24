from __future__ import annotations

import base64
import os
from typing import Any, Dict, List

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_URI = "https://oauth2.googleapis.com/token"


class GmailAuthError(RuntimeError):
    """Raised when Gmail credentials are not configured."""


def _get_credentials() -> Credentials:
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    refresh_token = os.getenv("GOOGLE_REFRESH_TOKEN")

    if not all([client_id, client_secret, refresh_token]):
        raise GmailAuthError("Gmail OAuth2 credentials are missing in environment variables.")

    return Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=TOKEN_URI,
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )


def _extract_header(headers: List[Dict[str, str]], name: str) -> str:
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def _parse_authentication_results(headers: List[Dict[str, str]]) -> Dict[str, bool]:
    """Extract coarse SPF/DKIM/DMARC pass signals from Authentication-Results header."""

    auth_header = _extract_header(headers, "Authentication-Results").lower()
    if not auth_header:
        return {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False}

    return {
        "spf_pass": "spf=pass" in auth_header,
        "dkim_pass": "dkim=pass" in auth_header,
        "dmarc_pass": "dmarc=pass" in auth_header,
    }


def _decode_body(part: Dict[str, Any]) -> str:
    data = part.get("body", {}).get("data")
    if not data:
        return ""
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="ignore")


def _walk_parts(part: Dict[str, Any], body_acc: List[str], attachments: List[Dict[str, str]]) -> None:
    mime_type = part.get("mimeType", "")
    filename = part.get("filename")
    body_data = _decode_body(part)

    if filename:
        attachments.append(
            {
                "filename": filename,
                "mimeType": mime_type,
            }
        )

    if mime_type.startswith("text/") and body_data:
        body_acc.append(body_data)

    for child in part.get("parts", []) or []:
        _walk_parts(child, body_acc, attachments)


def get_unread_emails(max_results: int = 10) -> List[Dict[str, Any]]:
    """Return list of unread Gmail messages including subject, body, and attachment metadata."""
    creds = _get_credentials()
    try:
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        messages_response = (
            service.users()
            .messages()
            .list(userId="me", labelIds=["INBOX"], q="is:unread", maxResults=max_results)
            .execute()
            or {}
        )
    except HttpError as exc:
        raise RuntimeError(f"Gmail API error: {exc}") from exc

    message_items = messages_response.get("messages", []) or []
    emails: List[Dict[str, Any]] = []

    for message_meta in message_items:
        msg_id = message_meta.get("id")
        if not msg_id:
            continue
        try:
            message = (
                service.users()
                .messages()
                .get(userId="me", id=msg_id, format="full")
                .execute()
                or {}
            )
        except HttpError:
            continue

        payload = message.get("payload", {}) or {}
        headers = payload.get("headers", []) or []

        subject = _extract_header(headers, "Subject")
        body_segments: List[str] = []
        attachments: List[Dict[str, str]] = []

        if payload:
            _walk_parts(payload, body_segments, attachments)

        auth_signals = _parse_authentication_results(headers)
        label_ids = message.get("labelIds", []) or []

        emails.append(
            {
                "id": msg_id,
                "subject": subject,
                "body": "\n".join(body_segments).strip(),
                "attachments": attachments,
                "gmail_labels": label_ids,
                "auth_results": auth_signals,
            }
        )

    return emails
