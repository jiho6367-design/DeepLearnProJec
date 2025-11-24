import base64
from types import SimpleNamespace

import mail_service


def _encode_text(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8")


class DummyRequest:
    def __init__(self, payload):
        self.payload = payload

    def execute(self):
        return self.payload


class DummyMessages:
    def __init__(self, list_payload, detail_payload):
        self.list_payload = list_payload
        self.detail_payload = detail_payload

    def list(self, **_kwargs):
        return DummyRequest(self.list_payload)

    def get(self, **_kwargs):
        return DummyRequest(self.detail_payload)


class DummyService:
    def __init__(self, list_payload, detail_payload):
        self._messages = DummyMessages(list_payload, detail_payload)

    def users(self):
        return SimpleNamespace(messages=lambda: self._messages)


def test_get_unread_emails_returns_structure(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("GOOGLE_REFRESH_TOKEN", "refresh")

    list_payload = {"messages": [{"id": "abc123"}]}
    detail_payload = {
        "payload": {
            "headers": [{"name": "Subject", "value": "Test subject"}],
            "mimeType": "multipart/mixed",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": _encode_text("Hello world")},
                },
                {
                    "filename": "danger.docm",
                    "mimeType": "application/msword",
                    "body": {"data": _encode_text("")},
                },
            ],
        }
    }

    dummy_service = DummyService(list_payload, detail_payload)
    monkeypatch.setattr(mail_service, "build", lambda *args, **kwargs: dummy_service)

    emails = mail_service.get_unread_emails(max_results=5)

    assert len(emails) == 1
    email = emails[0]
    assert email["subject"] == "Test subject"
    assert "Hello world" in email["body"]
    assert email["attachments"][0]["filename"] == "danger.docm"
