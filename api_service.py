from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sqlite3
import re
import textwrap
import time
from datetime import datetime, date
from pathlib import Path
from typing import Dict, Any, List, Optional

import torch
import torch.nn.functional as F
from flask import Flask, jsonify, request, abort
from openai import OpenAI
from transformers import AutoModelForSequenceClassification, AutoTokenizer
from mail_service import GmailAuthError, get_unread_emails

from prompt_version_tracker import PromptVersionTracker, PromptRun

try:
    from optimized_pipeline import classify_batch as fast_classify_batch, feedback_async as fast_feedback_async
except Exception:
    fast_classify_batch = None
    fast_feedback_async = None

MODEL_NAME = os.getenv("HF_CLASSIFIER", "distilbert-base-uncased-finetuned-sst-2-english")
THRESHOLD = float(os.getenv("PHISH_THRESHOLD", 0.30))
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
BILLING_DB = Path("data/billing.db")
FEEDBACK_DB = Path("data/feedback.db")
DAILY_FREE_LIMIT = 10
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


def json_abort(status: int, message: str):
    response = jsonify({"error": message})
    response.status_code = status
    abort(response)


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
    entry = f"{datetime.utcnow().isoformat()}	{email_id}	{label}	{confidence:.4f}	{token}	{reason}\n"
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


def verify_and_meter(token: Optional[str], cost: int = 1):
    if not token:
        json_abort(401, "missing_token")
    if not BILLING_DB.exists():
        json_abort(503, "billing_unavailable")
    cost = max(1, int(cost))

    with sqlite3.connect(BILLING_DB) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """SELECT users.* FROM api_tokens
               JOIN users ON users.id = api_tokens.user_id
               WHERE api_tokens.token = ?""",
            (token,),
        ).fetchone()
        if not row:
            json_abort(401, "invalid_token")
        row = dict(row)
        today = date.today().isoformat()
        if row.get("usage_reset_on") != today:
            conn.execute(
                "UPDATE users SET daily_usage = 0, usage_reset_on = ? WHERE id = ?",
                (today, row["id"]),
            )
            row["daily_usage"] = 0

        remaining = None
        if row["plan"] == "free":
            if row["daily_usage"] + cost > DAILY_FREE_LIMIT:
                json_abort(402, "limit")
            remaining = DAILY_FREE_LIMIT - (row["daily_usage"] + cost)

        conn.execute(
            "UPDATE users SET daily_usage = daily_usage + ?, usage_reset_on = ? WHERE id = ?",
            (cost, today, row["id"]),
        )
        conn.commit()

    return row, remaining


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

    token = request.headers.get("X-API-Key")
    _, remaining = verify_and_meter(token)

    text = "\n".join(part for part in (title, body) if part)
    label, confidence = classify_email(text)
    email_id = generate_email_id(title + body)
    feedback, _ = build_feedback(text, label, confidence, email_id)
    result = serialize_result(label, confidence, feedback)
    result["remaining_free_calls"] = remaining
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

    token = request.headers.get("X-API-Key")
    _, remaining = verify_and_meter(token, cost=len(prepared))

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

    return jsonify({"results": results, "remaining_free_calls": remaining}), 200


def asyncio_run_feedback(classifications: List[Dict[str, Any]]):
    if fast_feedback_async is None:
        raise RuntimeError("optimized pipeline unavailable")
    return asyncio.run(fast_feedback_async(classifications))


@app.post("/api/fetch_and_analyze")
def fetch_and_analyze():
    token = request.headers.get("X-API-Key")
    if not token:
        json_abort(401, "missing_token")

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

    cost = max(1, len(emails))
    _, remaining = verify_and_meter(token, cost=cost)

    results = []
    for email in emails:
        subject = email.get("subject") or ""
        body = email.get("body") or ""
        text = "\n".join(part for part in (subject, body) if part) or "(empty)"
        label, confidence = classify_email(text)

        reason_parts = []
        attachments = email.get("attachments") or []
        for attachment in attachments:
            filename = attachment.get("filename") or ""
            if SUSPICIOUS_PATTERN.search(filename):
                reason_parts.append("contains suspicious attachment")
                break
        if SUSPICIOUS_PATTERN.search(body):
            reason_parts.append("contains suspicious keywords")

        if reason_parts:
            confidence = min(1.0, confidence + 0.1)
        reason = "; ".join(reason_parts) if reason_parts else "model verdict"

        log_email_analysis(token, email.get("id", "unknown"), label, confidence, reason)

        results.append(
            {
                "id": email.get("id"),
                "label": label,
                "confidence": round(confidence, 4),
                "reason": reason,
            }
        )

    return jsonify({"results": results, "remaining_free_calls": remaining}), 200


@app.get("/metrics/summary")
def metrics_summary():
    return jsonify(feedback_summary())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
