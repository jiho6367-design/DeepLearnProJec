import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.security.session import get_current_user
from backend.app.services.gmail_service import get_message_detail, list_messages

router = APIRouter()


@router.get("/emails")
async def get_emails(pageToken: str | None = None, user=Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return await list_messages(user, db, page_token=pageToken)
    except httpx.HTTPStatusError as exc:
        raise _map_gmail_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": {"code": "SERVER_ERROR", "message": str(exc)}})


@router.get("/emails/{message_id}")
async def get_email_detail(message_id: str, user=Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        return await get_message_detail(user, db, message_id)
    except httpx.HTTPStatusError as exc:
        raise _map_gmail_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": {"code": "SERVER_ERROR", "message": str(exc)}})


def _map_gmail_error(exc: httpx.HTTPStatusError) -> HTTPException:
    status = exc.response.status_code
    if status in (401, 403):
        code = "GMAIL_UNAUTHORIZED"
    elif status == 429:
        code = "GMAIL_RATE_LIMIT"
    elif status >= 500:
        code = "GMAIL_UPSTREAM"
        status = 502
    else:
        code = "GMAIL_ERROR"
    message = exc.response.text[:500] if exc.response is not None else str(exc)
    return HTTPException(status_code=status, detail={"error": {"code": code, "message": message}})
