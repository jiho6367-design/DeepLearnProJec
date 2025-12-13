import base64
import importlib
import os

import pytest
from fastapi.testclient import TestClient


def _reload_backend(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path/'auth_test.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("ENCRYPTION_KEY", base64.urlsafe_b64encode(b"1" * 32).decode())
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("FRONTEND_BASE_URL", "http://localhost:3000")
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:3000")

    import sys
    from backend.app import config

    config.get_settings.cache_clear()
    for module_name in [
        "backend.app.models.tables",
        "backend.app.api.auth",
        "backend.app.main",
        "backend.app.db.session",
    ]:
        if module_name in sys.modules:
            sys.modules.pop(module_name)

    import backend.app.db.session as db_session
    from backend.app.db.session import Base, engine
    import backend.app.models.tables  # noqa: F401 ensures models are registered
    import backend.app.api.auth  # noqa: F401
    import backend.app.main as main

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return main.app


@pytest.fixture
def client(monkeypatch, tmp_path):
    app = _reload_backend(monkeypatch, tmp_path)
    return TestClient(app)


def test_google_login_returns_auth_url_with_scope(client):
    response = client.get("/api/auth/google/login")
    assert response.status_code == 200
    data = response.json()
    assert "gmail.readonly" in data["auth_url"]
    assert data["state"]

    from backend.app.db.session import SessionLocal
    from backend.app.models.tables import OAuthState

    db = SessionLocal()
    try:
        state_row = db.query(OAuthState).filter(OAuthState.state == data["state"]).first()
        assert state_row is not None
    finally:
        db.close()


def test_state_save_and_consume(monkeypatch, tmp_path):
    _reload_backend(monkeypatch, tmp_path)
    from backend.app.security.session import consume_oauth_state, save_oauth_state
    from backend.app.db.session import SessionLocal
    from backend.app.models.tables import OAuthState

    db = SessionLocal()
    try:
        state_value = "sample-state"
        save_oauth_state(db, state_value, ttl_minutes=1)
        assert consume_oauth_state(db, state_value) is True
        # second consume should fail
        assert consume_oauth_state(db, state_value) is False
        # expired state path
        from datetime import datetime, timedelta

        expired = OAuthState(state="expired", expires_at=datetime.utcnow() - timedelta(minutes=5))
        db.add(expired)
        db.commit()
        assert consume_oauth_state(db, "expired") is False
    finally:
        db.close()
