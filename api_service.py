from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sqlite3
import re
import textwrap
import time
from datetime import datetime
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

from prompt_version_tracker import PromptVersionTracker, PromptRun
from phishing_analysis import PhishingAnalysisStore, analyze_email_content

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
API_TOKEN = (os.getenv("PHISH_API_TOKEN", "") or os.getenv("OPENAI_API_KEY", "")).strip()
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
    if not API_TOKEN:
        return None

    header_token = (request.headers.get("X-API-Key") or "").strip()
    bearer = (request.headers.get("Authorization") or "").strip()
    if bearer.lower().startswith("bearer "):
        bearer = bearer[7:].strip()

    token = header_token or bearer
    if token != API_TOKEN:
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
    """
    started = time.perf_counter()
    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        temperature=0.2,
        max_tokens=320,
        messages=[
            {"role": "system", "content": "You are a calm cybersecurity analyst."},
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
    return {
        "label": label,
        "confidence": round(confidence, 4),
        "needs_human_review": needs_review,
        "threshold": THRESHOLD,
        "gpt_feedback": feedback,
    }


@app.post("/api/analyze")
def analyze():
    payload = request.get_json(force=True, silent=True) or {}
    title = (payload.get("title") or "").strip()
    body = (payload.get("body") or "").strip()
    if not (title or body):
        return jsonify({"error": "title or body is required"}), 400

    token = require_api_token()

    text = "\n".join(part for part in (title, body) if part)
    label, confidence = classify_email(text)
    email_id = generate_email_id(title + body)
    feedback, _ = build_feedback(text, label, confidence, email_id)
    result = serialize_result(label, confidence, feedback)
    return jsonify(result), 200


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
                    "label": cls["label"],
                    "confidence": round(cls["confidence"], 4),
                    "needs_human_review": needs_review,
                    "threshold": THRESHOLD,
                    "gpt_feedback": fb["content"],
                }
        except Exception:
            use_fast = False

    if not use_fast:
        for entry in prepared:
            label, confidence = classify_email(entry["text"])
            feedback, _ = build_feedback(entry["text"], label, confidence, entry["email_id"])
            results[entry["index"]] = serialize_result(label, confidence, feedback)

    for idx, message in errors.items():
        results[idx] = {"error": message}

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

    texts = [_as_prompt_text(email) for email in emails]
    os.environ.setdefault("PHISHING_POLICY", DEFAULT_POLICY)
    model_outputs = analyze_emails(texts)

    results = []
    for meta, analysis in zip(emails, model_outputs):
        combined = {
            **meta,
            "label": analysis.get("label"),
            "confidence": round(analysis.get("confidence", 0.0), 4),
            "feedback": analysis.get("feedback"),
            "latency_ms": analysis.get("latency_ms"),
        }
        results.append(combined)

    return jsonify({"results": results}), 200


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
        return jsonify({"error": "gmail_configuration", "detail": str(exc)}), 500
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
        return jsonify({"error": "gmail_configuration", "detail": str(exc)}), 500
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
