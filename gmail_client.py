from __future__ import annotations

from typing import Any, Dict, List

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from mail_service import GmailAuthError, _extract_header, _get_credentials, _walk_parts


def fetch_message_detail(message_id: str) -> Dict[str, Any]:
    """Fetch a single Gmail message with subject, sender, body preview, and attachments."""
    if not message_id:
        raise ValueError("message_id is required")

    creds = _get_credentials()
    try:
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        message = (
            service.users()
            .messages()
            .get(userId="me", id=message_id, format="full")
            .execute()
            or {}
        )
    except HttpError as exc:
        raise RuntimeError(f"Gmail API error: {exc}") from exc

    payload = message.get("payload", {}) or {}
    headers = payload.get("headers", []) or []

    subject = _extract_header(headers, "Subject")
    sender = _extract_header(headers, "From")

    body_segments: List[str] = []
    attachments: List[Dict[str, str]] = []
    if payload:
        _walk_parts(payload, body_segments, attachments)

    return {
        "id": message_id,
        "subject": subject,
        "sender": sender,
        "body": "\n".join(body_segments).strip(),
        "attachments": attachments,
    }
