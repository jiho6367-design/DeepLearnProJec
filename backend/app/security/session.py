import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as OrmSession

from backend.app.config import get_settings, Settings
from backend.app.db.session import get_db
from backend.app.models.tables import Session as SessionModel, User, OAuthState


def create_session(db: OrmSession, user_id: str, ttl_minutes: int) -> str:
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    db.add(
        SessionModel(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at,
        )
    )
    db.commit()
    return session_id


def get_current_user(
    request: Request, db: OrmSession = Depends(get_db), settings: Settings = Depends(get_settings)
) -> User:
    session_id = request.cookies.get("session")
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing session")
    session_row: Optional[SessionModel] = (
        db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    )
    if not session_row or session_row.expires_at < datetime.utcnow():
        if session_row:
            db.delete(session_row)
            db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    user = db.query(User).filter(User.id == session_row.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def save_oauth_state(db: OrmSession, state: str, ttl_minutes: int):
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    db.add(OAuthState(state=state, expires_at=expires_at))
    db.commit()


def consume_oauth_state(db: OrmSession, state: str) -> bool:
    row = db.query(OAuthState).filter(OAuthState.state == state).first()
    if not row:
        return False
    if row.expires_at < datetime.utcnow():
        db.delete(row)
        db.commit()
        return False
    db.delete(row)
    db.commit()
    return True


def clean_expired_states(db: OrmSession):
    db.query(OAuthState).filter(OAuthState.expires_at < datetime.utcnow()).delete()
    db.commit()


def clean_expired_sessions(db: OrmSession):
    db.query(SessionModel).filter(SessionModel.expires_at < datetime.utcnow()).delete()
    db.commit()
