import base64
import importlib
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient


def _setup_app(monkeypatch, tmp_path):
    db_url = f"sqlite:///{tmp_path/'auth_me.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("ENCRYPTION_KEY", base64.urlsafe_b64encode(b"3" * 32).decode())
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("FRONTEND_BASE_URL", "http://localhost:3000")
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:3000")

    from backend.app import config

    config.get_settings.cache_clear()
    for module_name in [
        "backend.app.models.tables",
        "backend.app.api.auth",
        "backend.app.api.emails",
        "backend.app.main",
        "backend.app.db.session",
        "backend.app.security.session",
    ]:
        if module_name in sys.modules:
            sys.modules.pop(module_name)

    import backend.app.db.session as db_session
    from backend.app.db.session import Base, engine
    import backend.app.models.tables as models_tables  # noqa: F401
    import backend.app.api.auth  # noqa: F401
    import backend.app.api.emails  # noqa: F401
    import backend.app.main as main

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return main.app


def _seed_user_session(SessionLocal):
    from backend.app.models.tables import Session as SessionModel, User

    db = SessionLocal()
    email = "user@example.com"
    user = User(email=email, google_sub="sub-1")
    db.add(user)
    db.flush()
    session_id = "test-session"
    db.add(
        SessionModel(
            session_id=session_id,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=30),
        )
    )
    db.commit()
    db.close()
    return session_id, email


def test_me_requires_valid_session(monkeypatch, tmp_path):
    app = _setup_app(monkeypatch, tmp_path)
    from backend.app.db.session import SessionLocal

    session_id, email = _seed_user_session(SessionLocal)
    client = TestClient(app)
    client.cookies.set("session", session_id)
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == email
    assert data["id"]


def test_me_without_session_returns_401(monkeypatch, tmp_path):
    app = _setup_app(monkeypatch, tmp_path)
    client = TestClient(app)
    res = client.get("/api/auth/me")
    assert res.status_code == 401


def test_logout_clears_session(monkeypatch, tmp_path):
    app = _setup_app(monkeypatch, tmp_path)
    from backend.app.db.session import SessionLocal
    from backend.app.models.tables import Session as SessionModel

    session_id, _ = _seed_user_session(SessionLocal)
    client = TestClient(app)
    client.cookies.set("session", session_id)
    res = client.post("/api/auth/logout")
    assert res.status_code == 200
    assert res.json()["ok"] is True

    res_after = client.get("/api/auth/me")
    assert res_after.status_code == 401

    db = SessionLocal()
    try:
        assert db.query(SessionModel).count() == 0
    finally:
        db.close()
