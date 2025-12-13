import base64
import importlib
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient


def _setup(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'analyze.db'}")
    monkeypatch.setenv("ENCRYPTION_KEY", base64.urlsafe_b64encode(b"4" * 32).decode())
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("FRONTEND_BASE_URL", "http://localhost:3000")
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:3000")

    from backend.app import config

    config.get_settings.cache_clear()
    for name in [
        "backend.app.models.tables",
        "backend.app.services.gmail_service",
        "backend.app.services.ai_service",
        "backend.app.api.analysis",
        "backend.app.api.auth",
        "backend.app.api.emails",
        "backend.app.main",
        "backend.app.db.session",
    ]:
        if name in sys.modules:
            sys.modules.pop(name)

    import backend.app.db.session as db_session
    from backend.app.db.session import Base, engine
    import backend.app.models.tables as models_tables  # noqa: F401
    import backend.app.services.gmail_service as gmail_service
    import backend.app.services.ai_service as ai_service
    import backend.app.api.analysis as analysis
    import backend.app.api.auth  # noqa: F401
    import backend.app.api.emails  # noqa: F401
    import backend.app.main as main

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return main.app, gmail_service, ai_service


def _seed_user_and_session(SessionLocal):
    from backend.app.models.tables import Session as SessionModel, User

    db = SessionLocal()
    user = User(email="u@example.com", google_sub="sub1")
    db.add(user)
    db.flush()
    user_id = user.id
    session_id = "sess-123"
    db.add(SessionModel(session_id=session_id, user_id=user.id, expires_at=datetime.utcnow() + timedelta(hours=1)))
    db.commit()
    db.close()
    return session_id, user_id


def test_analyze_deep_and_history(monkeypatch, tmp_path):
    app, gmail_service, ai_service = _setup(monkeypatch, tmp_path)
    from backend.app.db.session import SessionLocal
    from backend.app.models.tables import EmailAnalysis

    # mocks
    async def mock_get_message_detail(user, db, message_id):
        return {"id": message_id, "subject": "Hello", "from": "a@example.com", "body": "urgent verify password now"}

    async def mock_analyze_body_deep(body: str):
        return {
            "verdict": "phishing",
            "score": 0.9,
            "summary": "LLM says phishing",
            "reasons": ["contains password", "urgent tone"],
            "recommended_actions": ["Reset password", "Report"],
        }

    import backend.app.api.analysis as analysis_api

    monkeypatch.setattr(analysis_api, "get_message_detail", mock_get_message_detail)
    monkeypatch.setattr(analysis_api, "analyze_body_deep", mock_analyze_body_deep)

    session_id, user_id = _seed_user_and_session(SessionLocal)

    client = TestClient(app)
    client.cookies.set("session", session_id)
    res = client.post("/api/analyze", json={"message_id": "m1", "mode": "deep"})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "phishing"
    assert pytest.approx(data["score"], 0.01) == 0.9
    assert "reasons" in data

    # DB persisted
    db = SessionLocal()
    try:
        row = db.query(EmailAnalysis).filter(EmailAnalysis.user_id == user_id, EmailAnalysis.message_id == "m1").first()
        assert row is not None
        assert float(row.score) == 0.9
    finally:
        db.close()

    # history
    res_hist = client.get("/api/history")
    assert res_hist.status_code == 200
    hist = res_hist.json()
    assert hist["total"] == 1
    assert hist["items"][0]["message_id"] == "m1"
