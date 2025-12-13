from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.tables import EmailAnalysis
from backend.app.security.session import get_current_user
from backend.app.services.ai_service import analyze_body_deep, heuristic_analyze
from backend.app.services.gmail_service import get_message_detail

router = APIRouter()


@router.post("/analyze")
async def analyze_email(
    payload: dict,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    message_id = payload.get("message_id")
    mode = payload.get("mode", "fast")
    if not message_id:
        raise HTTPException(status_code=400, detail={"error": {"code": "BAD_REQUEST", "message": "message_id required"}})

    try:
        msg = await get_message_detail(user, db, message_id)
    except httpx.HTTPStatusError as exc:
        from backend.app.api.emails import _map_gmail_error

        raise _map_gmail_error(exc)
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": {"code": "SERVER_ERROR", "message": str(exc)}})

    body = msg.get("body", "")
    subject = msg.get("subject")
    from_addr = msg.get("from")

    llm_available = True
    if mode == "deep":
        try:
            result = await analyze_body_deep(body)
        except Exception as exc:
            llm_available = False
            result = heuristic_analyze(body)
            result["error"] = {"code": "LLM_UNAVAILABLE", "message": str(exc)}
    else:
        result = heuristic_analyze(body)
        result["llm_available"] = False

    verdict = result.get("verdict", "unknown")
    score = result.get("score", 0.0)
    summary = result.get("summary", "")
    reasons = result.get("reasons", [])
    actions = result.get("recommended_actions", [])

    existing = (
        db.query(EmailAnalysis)
        .filter(EmailAnalysis.user_id == user.id, EmailAnalysis.message_id == message_id)
        .first()
    )
    now = datetime.utcnow()
    if existing:
        existing.verdict = verdict
        existing.score = score
        existing.llm_summary = summary
        existing.from_addr = from_addr
        existing.subject = subject
        existing.updated_at = now  # type: ignore
    else:
        db.add(
            EmailAnalysis(
                user_id=user.id,
                message_id=message_id,
                subject=subject,
                from_addr=from_addr,
                verdict=verdict,
                score=score,
                llm_summary=summary,
                created_at=now,
            )
        )
    db.commit()

    response = {
        "verdict": verdict,
        "score": score,
        "summary": summary,
        "reasons": reasons,
        "recommended_actions": actions,
        "llm_available": llm_available,
    }
    if "error" in result:
        response["error"] = result["error"]
    return response


@router.get("/history")
async def history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(EmailAnalysis).filter(EmailAnalysis.user_id == user.id)
    total = q.count()
    rows = q.order_by(EmailAnalysis.created_at.desc()).limit(limit).offset(offset).all()
    items = [
        {
            "message_id": r.message_id,
            "subject": r.subject,
            "from_addr": r.from_addr,
            "verdict": r.verdict,
            "score": float(r.score) if r.score is not None else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
    return {"items": items, "total": total}
