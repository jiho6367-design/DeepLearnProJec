from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sqlite3
import re
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

import torch
import torch.nn.functional as F
from flask import Flask, jsonify, request, abort
from openai import OpenAI
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from dotenv import load_dotenv
from mail_service import GmailAuthError, get_unread_emails
from server.gmail_client import (
    GmailClientError,
    fetch_message_detail,
    fetch_recent_messages,
)
from optimized_pipeline import analyze_emails
from scoring import score_email

from prompt_version_tracker import PromptVersionTracker, PromptRun
from phishing_analysis import PhishingAnalysisStore, analyze_email_content
from history_store import (
    init_db,
    save_analysis_result,
    load_history,
    get_existing_gmail_ids,
    load_history_by_gmail_ids,
)

try:
    from optimized_pipeline import classify_batch as fast_classify_batch, feedback_async as fast_feedback_async
except Exception:
    fast_classify_batch = None
    fast_feedback_async = None

load_dotenv(".env")
os.environ.setdefault("PYTHONUTF8", "1")

MODEL_NAME = os.getenv("HF_CLASSIFIER", "distilbert-base-uncased-finetuned-sst-2-english")
THRESHOLD = float(os.getenv("PHISH_THRESHOLD", 0.30))
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
# API 토큰이 비어 있으면 OpenAI 키를 fallback 으로 허용해 로컬 실험 시 401을 줄인다.
PHISH_API_TOKEN = (os.getenv("PHISH_API_TOKEN", "")).strip()
OPENAI_API_KEY_ENV = (os.getenv("OPENAI_API_KEY", "")).strip()
API_TOKENS: List[str] = [t for t in (PHISH_API_TOKEN, OPENAI_API_KEY_ENV) if t]
API_TOKEN = API_TOKENS[0] if API_TOKENS else ""
FEEDBACK_DB = Path("data/feedback.db")
LOG_PATH = Path("logs/email_analysis.log")
SUSPICIOUS_PATTERN = re.compile(r"(zip|exe|docm|xlsm|scr|bat)", re.IGNORECASE)

LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
LOG_PATH.touch(exist_ok=True)

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
model.eval()

tracker = PromptVersionTracker()
tracker.register_prompt("v1", "Explain risk + 3 steps.")

app = Flask(__name__)
logger = logging.getLogger(__name__)
analysis_store = PhishingAnalysisStore()
# Initialize SQLite persistence
init_db()

# ingestion_workflow 에서 사용하던 프롬프트 포맷을 동일하게 활용
DEFAULT_POLICY = """
- Gmail 분류 결과(SPAM/IMPORTANT)를 참고하되 그대로 신뢰하지 않는다.
- SPF/DKIM/DMARC가 실패하거나 링크·첨부 파일이 있으면 위험 점수를 높인다.
- 발신자/도메인 위장, 급박/금전 요구, 로그인/다운로드 링크의 사회공학 패턴을 우선 검토한다.
- 조직 보안 정책에 맞춰 격리/모니터링/사용자 알림 등 후속 조치를 명시한다.
"""


def _format_signals(email: Dict[str, Any]) -> str:
    auth = email.get("auth_results", {}) or {}
    labels = email.get("gmail_labels", []) or []
    attachments = email.get("attachments", []) or []

    auth_line = (
        f"SPF={'pass' if auth.get('spf_pass') else 'fail/unknown'}, "
        f"DKIM={'pass' if auth.get('dkim_pass') else 'fail/unknown'}, "
        f"DMARC={'pass' if auth.get('dmarc_pass') else 'fail/unknown'}"
    )
    attachment_line = ", ".join(att.get("filename", "") for att in attachments) or "none"
    label_line = ", ".join(labels) if labels else "none"

    return (
        f"- Gmail labels: {label_line}\n"
        f"- Auth: {auth_line}\n"
        f"- Attachments: {attachment_line}"
    )


def _as_prompt_text(email: Dict[str, Any]) -> str:
    return (
        f"Subject: {email.get('subject', '').strip()}\n\n"
        f"Body:\n{email.get('body', '').strip()}\n\n"
        f"Signals:\n{_format_signals(email)}"
    )


def json_abort(status: int, message: str):
    response = jsonify({"error": message})
    response.status_code = status
    abort(response)


def require_api_token() -> Optional[str]:
    """Require API token if configured; accept X-API-Key or Authorization: Bearer."""
    # Allow explicit test-mode bypass when PHISHGUARD_TEST_MODE=1
    if os.environ.get("PHISHGUARD_TEST_MODE") == "1":
        return None

    if not API_TOKENS:
        return None

    header_token = (request.headers.get("X-API-Key") or "").strip()
    bearer = (request.headers.get("Authorization") or "").strip()
    if bearer.lower().startswith("bearer "):
        bearer = bearer[7:].strip()

    token = header_token or bearer
    if token not in API_TOKENS:
        expected_masks = [f"****{t[-4:]}" for t in API_TOKENS]
        got_mask = f"****{token[-4:]}" if token else "<empty>"
        print(f"[DEBUG] expected one of {expected_masks}, got={got_mask}")
        json_abort(401, "invalid_token")
    return token


def classify_email(text: str):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
    with torch.no_grad():
        logits = model(**inputs).logits
        probs = F.softmax(logits, dim=-1)
    idx = int(torch.argmax(probs))
    confidence = float(probs[0, idx])
    raw_label = model.config.id2label[idx].upper()
    label = "phishing" if raw_label.startswith("NEG") else "normal"
    return label, confidence


def generate_email_id(seed: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    digest = hashlib.sha1(f"{ts}:{seed}".encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"api-{ts}-{digest}"


def log_prompt_run(email_id: str, label: str, latency_ms: float) -> None:
    tracker.log_run(
        PromptRun(
            version="v1",
            email_id=email_id,
            predicted=label,
            actual=label,
            latency_ms=latency_ms,
        )
    )


def log_email_analysis(token: str, email_id: str, label: str, confidence: float, reason: str) -> None:
    entry = f"{datetime.utcnow().isoformat()}	{email_id}	{label}	{confidence:.4f}	{token or 'anonymous'}	{reason}\n"
    with LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(entry)


def build_feedback(email_text: str, label: str, score: float, email_id: str) -> tuple[str, float]:
    prompt = f"""
    Email Subject + Body:
    {email_text.strip()}

    Model verdict: {label} ({score:.2%})

    Explain briefly why the message is risky/benign and list three practical next steps.
    Avoid fear-mongering, stay factual, and assume the reader is non-technical.
    모든 설명과 피드백 문장은 한국어로 작성하세요.
    """
    started = time.perf_counter()
    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        temperature=0.2,
        max_tokens=320,
        messages=[
            {
                "role": "system",
                "content": "You are a calm cybersecurity analyst. 모든 설명과 피드백은 한국어로 작성하세요.",
            },
            {"role": "user", "content": textwrap.dedent(prompt).strip()},
        ],
    )
    latency_ms = (time.perf_counter() - started) * 1000
    log_prompt_run(email_id, label, latency_ms)
    return response.choices[0].message.content.strip(), latency_ms


def feedback_summary() -> Dict[str, Any]:
    if not FEEDBACK_DB.exists():
        return {
            "phishing_today": 0,
            "false_positives": 0,
            "avg_feedback_latency_ms": 0,
            "monthly_trend": [],
        }

    with sqlite3.connect(FEEDBACK_DB) as conn:
        conn.row_factory = sqlite3.Row
        phishing_today = conn.execute(
            "SELECT COUNT(*) AS c FROM feedback WHERE substr(created_at,1,10) = DATE('now') AND user_label = 'phishing'"
        ).fetchone()["c"]
        false_positives = conn.execute(
            "SELECT COUNT(*) AS c FROM feedback WHERE model_label = 'phishing' AND user_label = 'normal'"
        ).fetchone()["c"]
        trend_rows = conn.execute(
            """SELECT substr(created_at,1,7) AS month_key, COUNT(*) AS cnt
               FROM feedback
               GROUP BY month_key
               ORDER BY month_key DESC
               LIMIT 12"""
        ).fetchall()

    monthly_trend = [
        {"month": f"{row['month_key']}-01", "phishing": row["cnt"]} for row in reversed(trend_rows)
    ]
    return {
        "phishing_today": phishing_today,
        "false_positives": false_positives,
        "avg_feedback_latency_ms": 0,
        "monthly_trend": monthly_trend,
    }


def serialize_result(label: str, confidence: float, feedback: str) -> Dict[str, Any]:
    needs_review = label == "phishing" and confidence >= THRESHOLD
    now = datetime.now(timezone.utc)
    return {
        "label": label,
        "confidence": round(confidence, 4),
        "needs_human_review": needs_review,
        "threshold": THRESHOLD,
        "gpt_feedback": feedback,
        "timestamp": now.isoformat(),
        "date": now.date().isoformat(),
    }


@app.post("/api/analyze")
def analyze():
    payload = request.get_json(force=True, silent=True) or {}
    title = (payload.get("title") or "").strip()
    body = (payload.get("body") or "").strip()
    if not (title or body):
        return jsonify({"error": "title or body is required"}), 400

    token = require_api_token()

    email_meta = {
        "subject": title,
        "body": body,
        "gmail_labels": [],
        "auth_results": {},
        "attachments": [],
    }
    os.environ.setdefault("PHISHING_POLICY", DEFAULT_POLICY)
    analysis_list = analyze_emails([_as_prompt_text(email_meta)])
    analysis = analysis_list[0] if analysis_list else {}

    scoring_input = {
        "headers": {},  # no auth headers available for manual upload
        "body": {"text": body, "html": None},
        "urls": [],
        "attachments": email_meta.get("attachments", []),
        "context": {"is_first_time_sender": True},
        "auth_results": email_meta.get("auth_results", {}),
    }
    scored = score_email(scoring_input)

    email_id = generate_email_id(title + body)
    now = datetime.now(timezone.utc)
    combined_for_db = {
        "id": email_id,
        "subject": title,
        "body": body,
        "gmail_labels": [],
        "auth_results": {},
        "label": analysis.get("label"),
        "confidence": round(analysis.get("confidence", 0.0), 4),
        "feedback": analysis.get("feedback"),
        "latency_ms": analysis.get("latency_ms"),
        "timestamp": now.isoformat(),
        "date": now.date().isoformat(),
        "gmail_id": email_id,
    }
    try:
        save_analysis_result(combined_for_db)
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Failed to persist analysis result: %s", exc)

    response_body = {
        "classification": scored["classification"],
        "risk_score": scored["risk_score"],
        "severity": scored["severity"],
        "top_signals": scored["top_signals"],
        "evidence_missing": scored["evidence_missing"],
        "explanation": scored["explanation"],
        "recommended_action": scored["recommended_action"],
        "label": combined_for_db["label"],
        "confidence": combined_for_db["confidence"],
        "gpt_feedback": combined_for_db["feedback"],
        "timestamp": combined_for_db["timestamp"],
        "date": combined_for_db["date"],
    }
    return jsonify(response_body), 200


@app.post("/api/analyze_batch")
def analyze_batch():
    payload = request.get_json(force=True, silent=True) or {}
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        return jsonify({"error": "items must be a non-empty list"}), 400

    prepared: List[Dict[str, Any]] = []
    errors: Dict[int, str] = {}
    for idx, item in enumerate(items):
        title = (item.get("title") or "").strip()
        body = (item.get("body") or "").strip()
        if not (title or body):
            errors[idx] = "title or body is required"
            continue
        text = "\n".join(part for part in (title, body) if part)
        prepared.append(
            {
                "index": idx,
                "text": text,
                "email_id": generate_email_id(f"{idx}:{title}"),
            }
        )

    if not prepared:
        return jsonify({"error": "no valid items"}), 400

    token = require_api_token()

    results: List[Optional[Dict[str, Any]]] = [None] * len(items)

    use_fast = fast_classify_batch is not None and fast_feedback_async is not None
    if use_fast:
        try:
            texts = [entry["text"] for entry in prepared]
            classifications = fast_classify_batch(texts)
            feedbacks = asyncio_run_feedback(classifications)
            for entry, cls, fb in zip(prepared, classifications, feedbacks):
                needs_review = cls["label"] == "phishing" and cls["confidence"] >= THRESHOLD
                log_prompt_run(entry["email_id"], cls["label"], fb["latency_ms"])
                results[entry["index"]] = {
                    "id": entry["email_id"],
                    "label": cls["label"],
                    "confidence": round(cls["confidence"], 4),
                    "needs_human_review": needs_review,
                    "threshold": THRESHOLD,
                    "gpt_feedback": fb["content"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "date": datetime.now(timezone.utc).date().isoformat(),
                }
        except Exception:
            use_fast = False

    if not use_fast:
        for entry in prepared:
            label, confidence = classify_email(entry["text"])
            feedback, latency_ms = build_feedback(entry["text"], label, confidence, entry["email_id"])
            results[entry["index"]] = {
                "id": entry["email_id"],
                **serialize_result(label, confidence, feedback),
                "latency_ms": latency_ms,
            }

    for idx, message in errors.items():
        results[idx] = {"error": message}

    # Persist batch results (best-effort)
    for result in results:
        if not result or "error" in result:
            continue
        try:
            save_analysis_result(result)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.exception("Failed to persist batch analysis result: %s", exc)

    return jsonify({"results": results}), 200


def asyncio_run_feedback(classifications: List[Dict[str, Any]]):
    if fast_feedback_async is None:
        raise RuntimeError("optimized pipeline unavailable")
    return asyncio.run(fast_feedback_async(classifications))


@app.post("/api/fetch_and_analyze")
def fetch_and_analyze():
    token = require_api_token()

    payload = request.get_json(force=True, silent=True) or {}
    max_results = payload.get("max_results", 10)
    try:
        max_results = int(max_results)
    except (TypeError, ValueError):
        return jsonify({"error": "max_results must be an integer"}), 400
    max_results = max(1, min(max_results, 50))

    try:
        emails = get_unread_emails(max_results=max_results)
    except GmailAuthError as exc:
        logger.warning("Gmail auth error: %s", exc)
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        logger.error("Gmail API failure: %s", exc)
        return jsonify({"error": str(exc)}), 502

    if not emails:
        return jsonify({"results": []}), 200

    # In tests, avoid expensive external calls and return a minimal, deterministic response.
    if os.environ.get("PHISHGUARD_TEST_MODE") == "1":
        results: List[Dict[str, Any]] = []
        for email in emails:
            label, confidence = classify_email(_as_prompt_text(email))
            reason_parts: List[str] = []
            for att in email.get("attachments") or []:
                fname = att.get("filename", "")
                if SUSPICIOUS_PATTERN.search(fname):
                    reason_parts.append(f"suspicious attachment: {fname}")
            reason = "; ".join(reason_parts) or "analysis performed in test mode"
            results.append(
                {
                    "id": email.get("id") or generate_email_id(email.get("subject", "") or ""),
                    "subject": email.get("subject", ""),
                    "body": email.get("body", ""),
                    "label": label,
                    "confidence": confidence,
                    "reason": reason,
                }
            )
        return jsonify({"results": results}), 200

    texts = [_as_prompt_text(email) for email in emails]
    os.environ.setdefault("PHISHING_POLICY", DEFAULT_POLICY)
    model_outputs = analyze_emails(texts)

    gmail_ids = [meta.get("id") for meta in emails]
    existing_ids = set()
    try:
        existing_ids = get_existing_gmail_ids([gid for gid in gmail_ids if gid])
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to check existing gmail ids: %s", exc)

    cached_results: List[Dict[str, Any]] = []
    try:
        cached_results = load_history_by_gmail_ids(list(existing_ids))
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to load cached results: %s", exc)
        cached_results = []

    to_analyze = [(meta, idx) for idx, meta in enumerate(emails) if meta.get("id") not in existing_ids]
    analyzed_results: List[Dict[str, Any]] = []
    if to_analyze:
        texts_to_analyze = [_as_prompt_text(meta) for meta, _ in to_analyze]
        try:
            model_outputs = analyze_emails(texts_to_analyze)
        except Exception as exc:  # pragma: no cover - fall back empty
            logger.exception("Pipeline analysis failed: %s", exc)
            model_outputs = []

        for (meta, _), analysis in zip(to_analyze, model_outputs):
            now = datetime.now(timezone.utc)
            record_id = meta.get("id") or generate_email_id(meta.get("subject", "") or "")
            combined = {
                **meta,
                "id": record_id,
                "gmail_id": meta.get("id"),
                "label": analysis.get("label"),
                "confidence": round(analysis.get("confidence", 0.0), 4),
                "feedback": analysis.get("feedback"),
                "latency_ms": analysis.get("latency_ms"),
                "timestamp": now.isoformat(),
                "date": now.date().isoformat(),
                "from_cache": False,
            }
            analyzed_results.append(combined)
            try:
                save_analysis_result(combined)
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.exception("Failed to persist analysis result: %s", exc)

    results = cached_results + analyzed_results
    warnings: List[str] = []
    if cached_results:
        warnings.append(f"Reused {len(cached_results)} cached analyses.")
    if analyzed_results:
        warnings.append(f"Analyzed {len(analyzed_results)} new emails.")

    response_body: Dict[str, Any] = {"results": results}
    if warnings:
        response_body["warnings"] = warnings
    return jsonify(response_body), 200


@app.post("/api/analyze_selected")
def analyze_selected():
    require_api_token()

    payload = request.get_json(force=True, silent=True) or {}
    message_ids = payload.get("message_ids") or []
    if not isinstance(message_ids, list) or not message_ids:
        return jsonify({"error": "message_ids must be a non-empty list"}), 400

    try:
        max_results = int(payload.get("max_results", len(message_ids)))
    except (TypeError, ValueError):
        max_results = len(message_ids)
    max_results = max(1, min(max_results, 100))

    selected_ids = message_ids[:max_results]
    emails: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for msg_id in selected_ids:
        try:
            detail = fetch_message_detail(msg_id)
        except (GmailAuthError, GmailClientError, RuntimeError) as exc:
            warnings.append(f"Failed to fetch message {msg_id}: {exc}")
            continue
        emails.append(
            {
                "id": detail.get("id", msg_id),
                "gmail_id": detail.get("id", msg_id),
                "subject": detail.get("subject", ""),
                "body": detail.get("body", ""),
                "gmail_labels": detail.get("gmail_labels", []),
                "auth_results": detail.get("auth_results", {}),
                "attachments": [],
            }
        )

    if not emails:
        return jsonify({"error": "no_messages_analyzed", "warnings": warnings}), 502

    gmail_ids = [e.get("gmail_id") for e in emails]
    existing_ids = set()
    try:
        existing_ids = get_existing_gmail_ids([gid for gid in gmail_ids if gid])
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to check existing gmail ids: %s", exc)

    cached_results: List[Dict[str, Any]] = []
    try:
        cached_results = load_history_by_gmail_ids(list(existing_ids))
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to load cached results: %s", exc)
        cached_results = []

    to_analyze = [email for email in emails if email.get("gmail_id") not in existing_ids]

    analyzed_results: List[Dict[str, Any]] = []
    if to_analyze:
        texts = [_as_prompt_text(email) for email in to_analyze]
        os.environ.setdefault("PHISHING_POLICY", DEFAULT_POLICY)
        model_outputs = analyze_emails(texts)

        for meta, analysis in zip(to_analyze, model_outputs):
            now = datetime.now(timezone.utc)
            combined = {
                **meta,
                "label": analysis.get("label"),
                "confidence": round(analysis.get("confidence", 0.0), 4),
                "feedback": analysis.get("feedback"),
                "latency_ms": analysis.get("latency_ms"),
                "timestamp": now.isoformat(),
                "date": now.date().isoformat(),
                "from_cache": False,
            }
            analyzed_results.append(combined)
            try:
                save_analysis_result(combined)
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.exception("Failed to persist selected analysis result: %s", exc)

    results = cached_results + analyzed_results
    if cached_results:
        warnings.append(f"Reused {len(cached_results)} cached analyses.")
    if analyzed_results:
        warnings.append(f"Analyzed {len(analyzed_results)} new emails.")

    response_body: Dict[str, Any] = {"results": results}
    if warnings:
        response_body["warnings"] = warnings
    return jsonify(response_body), 200


@app.post("/api/emails/<message_id>/analyze")
def analyze_gmail_email(message_id: str):
    token = require_api_token()

    try:
        email = fetch_message_detail(message_id)
    except GmailAuthError as exc:
        logger.warning("Gmail auth error for %s: %s", message_id, exc)
        return jsonify({"error": str(exc)}), 400
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        logger.error("Failed to fetch Gmail message %s: %s", message_id, exc)
        return jsonify({"error": "gmail_fetch_failed"}), 502

    try:
        analysis = analyze_email_content(
            subject=email.get("subject") or "",
            sender=email.get("sender") or "",
            body=email.get("body") or "",
            client=client,
            model=OPENAI_MODEL,
        )
    except Exception as exc:  # pragma: no cover - defensive against OpenAI errors
        logger.error("Analysis failed for %s: %s", message_id, exc)
        return jsonify({"error": "analysis_failed"}), 502

    response_body = {
        "messageId": message_id,
        "isPhishing": bool(analysis.get("is_phishing")),
        "riskScore": int(analysis.get("risk_score", 0)),
        "reasons": analysis.get("reasons", []),
        "summary": analysis.get("summary", ""),
    }

    analysis_store.save(response_body)
    return jsonify(response_body), 200


@app.get("/api/list_emails")
def list_gmail_emails():
    require_api_token()

    try:
        max_results = int(request.args.get("max_results", 20))
    except (TypeError, ValueError):
        max_results = 20
    max_results = max(1, min(max_results, 100))
    label = request.args.get("label") or None

    try:
        messages = fetch_recent_messages(limit=max_results, label=label)
    except GmailAuthError as exc:
        logger.error("Gmail configuration error: %s", exc)
        return jsonify({"error": "gmail_configuration", "detail": str(exc)}), 400
    except GmailClientError as exc:
        logger.error("Gmail API error while listing messages: %s", exc)
        return jsonify({"error": str(exc)}), getattr(exc, "status_code", 502)
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Unexpected failure listing Gmail messages: %s", exc)
        return jsonify({"error": "internal_error"}), 500

    results = []
    for msg in messages:
        results.append(
            {
                "gmail_id": msg.get("id"),
                "thread_id": msg.get("threadId"),
                "date": msg.get("internalDate") or msg.get("date"),
                "from": msg.get("from") or msg.get("sender"),
                "subject": msg.get("subject", ""),
                "snippet": msg.get("snippet", ""),
                "gmail_labels": msg.get("gmail_labels", []),
            }
        )

    return jsonify({"results": results}), 200

@app.get("/api/emails")
def list_emails():
    try:
        limit = int(request.args.get("limit", 20))
    except (TypeError, ValueError):
        return jsonify({"error": "limit must be an integer"}), 400

    limit = max(1, min(limit, 100))

    try:
        messages = fetch_recent_messages(limit=limit)
    except GmailAuthError as exc:
        logger.error("Gmail configuration error: %s", exc)
        return jsonify({"error": "gmail_configuration", "detail": str(exc)}), 400
    except GmailClientError as exc:
        logger.error("Gmail API error while listing emails: %s", exc)
        return jsonify({"error": str(exc)}), getattr(exc, "status_code", 502)
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Unexpected failure listing emails: %s", exc)
        return jsonify({"error": "internal_error"}), 500

    return jsonify(messages), 200


@app.get("/api/emails/<message_id>")
def get_email_detail(message_id: str):
    try:
        detail = fetch_message_detail(message_id)
    except GmailAuthError as exc:
        logger.error("Gmail configuration error: %s", exc)
        return jsonify({"error": "gmail_configuration", "detail": str(exc)}), 400
    except GmailClientError as exc:
        logger.error("Gmail API error while fetching message %s: %s", message_id, exc)
        return jsonify({"error": str(exc)}), getattr(exc, "status_code", 502)
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Unexpected failure fetching email %s: %s", message_id, exc)
        return jsonify({"error": "internal_error"}), 500

    return jsonify(detail), 200


@app.get("/metrics/summary")
def metrics_summary():
    return jsonify(feedback_summary())


@app.get("/api/history")
def get_history():
    require_api_token()

    try:
        limit = int(request.args.get("limit", 200))
    except (TypeError, ValueError):
        limit = 200
    days_param = request.args.get("days")
    try:
        days = int(days_param) if days_param is not None else None
    except (TypeError, ValueError):
        days = None

    results = load_history(limit=limit, days=days)
    return jsonify({"results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
def verify_and_meter(token: str, cost: int = 1):
    """
    Backward-compatibility stub for tests that expect this function.
    Returns a simple plan dict and zero cost applied.
    """
    return {"plan": "free"}, 0
