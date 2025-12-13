import base64
import importlib

import pytest


class DummyResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class DummyAsyncClient:
    def __init__(self, *_, **__):
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, data=None, headers=None):
        self.calls.append(("post", url, data))
        return DummyResponse({"access_token": "access-token", "expires_in": 3600})

    async def get(self, url, params=None, headers=None):
        self.calls.append(("get", url, params))
        if url.endswith("/messages"):
            return DummyResponse({"messages": [{"id": "m1"}], "nextPageToken": None})
        if "metadata" in url:
            return DummyResponse(
                {
                    "id": "m1",
                    "snippet": "hello",
                    "payload": {
                        "headers": [
                            {"name": "Subject", "value": "Hi"},
                            {"name": "From", "value": "a@example.com"},
                            {"name": "Date", "value": "Fri"},
                        ]
                    },
                }
            )
        return DummyResponse(
            {
                "id": "m1",
                "payload": {
                    "headers": [
                        {"name": "Subject", "value": "Hi"},
                        {"name": "From", "value": "a@example.com"},
                        {"name": "Date", "value": "Fri"},
                    ],
                    "body": {"data": base64.urlsafe_b64encode(b"Hello world").decode()},
                },
                "snippet": "Hello world",
            }
        )


@pytest.mark.anyio
async def test_list_messages_and_detail(monkeypatch, tmp_path):
    # Prepare env and reload modules
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'gmail.db'}")
    monkeypatch.setenv("ENCRYPTION_KEY", base64.urlsafe_b64encode(b"2" * 32).decode())
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")

    from backend.app import config

    config.get_settings.cache_clear()
    import sys

    for module_name in [
        "backend.app.models.tables",
        "backend.app.services.gmail_service",
        "backend.app.db.session",
    ]:
        if module_name in sys.modules:
            sys.modules.pop(module_name)

    import backend.app.db.session as db_session
    from backend.app.db.session import Base, SessionLocal, engine
    import backend.app.models.tables as models_tables
    import backend.app.services.gmail_service as gmail_service

    # Patch crypto to avoid real Fernet
    monkeypatch.setattr(gmail_service, "decrypt_token", lambda value: "refresh-token")
    monkeypatch.setattr(gmail_service, "encrypt_token", lambda value: value)
    monkeypatch.setattr(gmail_service.httpx, "AsyncClient", DummyAsyncClient)

    from backend.app.models.tables import OAuthToken, User

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        user = User(email="u@example.com", google_sub="sub123")
        db.add(user)
        db.flush()
        db.add(OAuthToken(user_id=user.id, refresh_token_enc="encrypted"))
        db.commit()

        messages = await gmail_service.list_messages(user, db)
        assert messages["messages"][0]["subject"] == "Hi"
        detail = await gmail_service.get_message_detail(user, db, "m1")
        assert "Hello world" in detail["body"]
    finally:
        db.close()
