from __future__ import annotations

import base64
import logging
import os
from typing import Any, Dict, List, Optional

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

from mail_service import GmailAuthError

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_URI = "https://oauth2.googleapis.com/token"

logger = logging.getLogger(__name__)


class GmailClientError(RuntimeError):
    """Raised when Gmail API calls fail."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


def _read_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise GmailAuthError(f"Missing required environment variable: {name}")
    return value


def _build_credentials() -> Credentials:
    client_id = _read_env("GOOGLE_CLIENT_ID")
    client_secret = _read_env("GOOGLE_CLIENT_SECRET")
    refresh_token = _read_env("GOOGLE_REFRESH_TOKEN")

    credentials = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=TOKEN_URI,
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )

    try:
        if not credentials.valid:
            credentials.refresh(Request())
    except RefreshError as exc:
        logger.error("Failed to refresh Gmail credentials: %s", exc)
        raise GmailAuthError("Unable to refresh Gmail credentials. Check refresh token.") from exc
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Unexpected credential error: %s", exc)
        raise

    return credentials


def get_gmail_service():
    """Create and return an authenticated Gmail service client."""
    try:
        credentials = _build_credentials()
        service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        return service
    except GmailAuthError:
        raise
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.error("Failed to build Gmail service: %s", exc)
        raise GmailClientError("Unable to initialize Gmail service.") from exc


def _decode_body(data: Optional[str]) -> str:
    if not data:
        return ""
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="ignore")


def _extract_header(headers: List[Dict[str, str]], name: str) -> str:
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def _collect_text_parts(part: Dict[str, Any], accumulator: List[str]) -> None:
    mime_type = part.get("mimeType", "")
    body_data = part.get("body", {}) or {}

    if mime_type.startswith("text/"):
        text = _decode_body(body_data.get("data"))
        if text:
            accumulator.append(text)

    for child in part.get("parts", []) or []:
        _collect_text_parts(child, accumulator)


def fetch_recent_messages(limit: int = 20) -> List[Dict[str, Any]]:
    """Return a list of recent messages with basic metadata."""
    limit = max(1, min(int(limit or 20), 100))
    service = get_gmail_service()
    try:
        response = (
            service.users()
            .messages()
            .list(userId="me", maxResults=limit)
            .execute()
            or {}
        )
    except HttpError as exc:
        logger.error("Gmail list messages failed: %s", exc)
        status = getattr(exc, "status_code", None) or getattr(getattr(exc, "resp", None), "status", 502)
        raise GmailClientError("Failed to fetch message list.", status_code=int(status)) from exc

    messages = []
    for item in response.get("messages", []) or []:
        msg_id = item.get("id")
        if not msg_id:
            continue
        try:
            message = (
                service.users()
                .messages()
                .get(userId="me", id=msg_id, format="metadata")
                .execute()
                or {}
            )
        except HttpError as exc:
            logger.warning("Skipping message %s due to fetch error: %s", msg_id, exc)
            continue

        messages.append(
            {
                "id": message.get("id", msg_id),
                "threadId": message.get("threadId"),
                "internalDate": message.get("internalDate"),
                "snippet": message.get("snippet", ""),
            }
        )

    return messages


def fetch_message_detail(message_id: str) -> Dict[str, Any]:
    """Return detailed message content including headers and body text."""
    service = get_gmail_service()
    try:
        message = (
            service.users()
            .messages()
            .get(userId="me", id=message_id, format="full")
            .execute()
            or {}
        )
    except HttpError as exc:
        status = getattr(exc, "status_code", None) or getattr(getattr(exc, "resp", None), "status", 502)
        logger.error("Failed to fetch message %s: %s", message_id, exc)
        raise GmailClientError("Failed to fetch message detail.", status_code=int(status)) from exc

    payload = message.get("payload", {}) or {}
    headers = payload.get("headers", []) or []
    body_parts: List[str] = []

    if payload:
        _collect_text_parts(payload, body_parts)
    elif "body" in message:
        body_parts.append(_decode_body(message.get("body", {}).get("data")))

    body_text = "\n".join(part for part in body_parts if part).strip()

    logger.debug(
        "Fetched message %s with body length %d characters", message_id, len(body_text)
    )

    return {
        "id": message.get("id", message_id),
        "subject": _extract_header(headers, "Subject"),
        "sender": _extract_header(headers, "From"),
        "date": _extract_header(headers, "Date"),
        "snippet": message.get("snippet", ""),
        "body": body_text,
    }
