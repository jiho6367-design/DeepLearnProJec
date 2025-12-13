import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from backend.app.config import Settings, get_settings
from backend.app.db.session import get_db
from backend.app.models.tables import OAuthToken, Session as SessionModel, User
from backend.app.security.crypto import encrypt_token
from backend.app.security.session import (
    consume_oauth_state,
    create_session,
    get_current_user,
    save_oauth_state,
)
from backend.app.services.gmail_service import _get_user_info

router = APIRouter()


@router.get("/google/login")
async def google_login(settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    state = secrets.token_urlsafe(16)
    save_oauth_state(db, state, settings.oauth_state_ttl_minutes)
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return {"auth_url": f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}", "state": state}


@router.get("/google/callback")
async def google_callback(
    code: str,
    state: str,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    if not consume_oauth_state(db, state):
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    token_resp = await _exchange_code_for_tokens(code, settings)
    access_token = token_resp.get("access_token")
    refresh_token = token_resp.get("refresh_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="access_token missing from Google response")
    userinfo = await _get_user_info(access_token)
    google_sub = userinfo.get("id") or userinfo.get("sub")
    email = userinfo.get("email")
    if not google_sub or not email:
        raise HTTPException(status_code=400, detail="Unable to retrieve user identity from Google")

    user = _upsert_user(db, google_sub, email, refresh_token)
    session_id = create_session(db, user.id, settings.session_ttl_minutes)
    redirect_url = f"{settings.frontend_base_url.rstrip('/')}/dashboard"
    response = RedirectResponse(url=redirect_url, status_code=302)
    response.set_cookie(
        "session",
        session_id,
        httponly=True,
        secure=settings.effective_cookie_secure,
        samesite=settings.effective_cookie_samesite,
        domain=settings.cookie_domain,
        max_age=int(timedelta(minutes=settings.session_ttl_minutes).total_seconds()),
    )
    return response


@router.get("/me")
async def me(user=Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "created_at": user.created_at.isoformat()}


@router.post("/logout")
async def logout(
    request: Request,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    session_id = request.cookies.get("session")
    if session_id:
        db.query(SessionModel).filter(SessionModel.session_id == session_id).delete()
        db.commit()
    response = JSONResponse({"ok": True})
    response.set_cookie(
        "session",
        "",
        httponly=True,
        secure=settings.effective_cookie_secure,
        samesite=settings.effective_cookie_samesite,
        domain=settings.cookie_domain,
        max_age=0,
    )
    return response


async def _exchange_code_for_tokens(code: str, settings: Settings) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.google_redirect_uri,
                "grant_type": "authorization_code",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return resp.json()


def _upsert_user(db: Session, google_sub: str, email: str, refresh_token: str | None) -> User:
    user = db.query(User).filter(User.google_sub == google_sub).first()
    if not user:
        user = User(google_sub=google_sub, email=email)
        db.add(user)
        db.flush()
    else:
        user.email = email

    token_row = db.query(OAuthToken).filter(OAuthToken.user_id == user.id).first()
    if refresh_token:
        enc = encrypt_token(refresh_token)
        if token_row:
            token_row.refresh_token_enc = enc
        else:
            db.add(OAuthToken(user_id=user.id, refresh_token_enc=enc))
    elif not token_row:
        # Keep existing refresh token if missing; if none exists we cannot proceed
        raise HTTPException(status_code=400, detail="Refresh token missing; re-consent required")
    db.commit()
    return user
