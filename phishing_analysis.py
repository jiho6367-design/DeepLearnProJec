from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, List, Optional

from openai import OpenAI

BODY_PREVIEW_CHARS = int(os.getenv("PHISHING_BODY_PREVIEW_CHARS", "1200"))
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

PROMPT_TEMPLATE = """
당신은 피싱 메일을 판별하는 사이버 보안 분석가입니다. 메타데이터와 본문 일부만으로 판단하고 한국어로 답하세요.

[메일 메타데이터]
- 제목: {subject}
- 발신자: {sender}
- 본문 미리보기(개인정보 마스킹 + 앞부분 {max_chars}자):
{body_preview}

[분석 지시사항]
1) 피싱 여부를 yes/no 로 판단.
2) 0-100 범위의 위험도 점수 제공.
3) 한국어로 의심/신뢰 이유를 짧게 나열.
4) 최종 사용자가 바로 이해할 수 있는 요약 메시지 작성.
아래 JSON 포맷만 반환:
{{
  "is_phishing": <true|false>,
  "risk_score": <0-100 정수>,
  "reasons": ["..."],
  "summary": "..."
}}
"""

EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
URL_PATTERN = re.compile(r"https?://[\w./?=&%_-]+", re.IGNORECASE)


def sanitize_body(body: str, max_chars: int = BODY_PREVIEW_CHARS) -> str:
    """Redact URLs/emails and truncate the body for privacy before sending to the model."""
    redacted = URL_PATTERN.sub("[URL]", body or "")
    redacted = EMAIL_PATTERN.sub("[EMAIL]", redacted)
    redacted = redacted.replace("\r", " ").strip()
    trimmed = redacted[:max_chars]
    return trimmed


def build_prompt(subject: str, sender: str, body_preview: str) -> str:
    return PROMPT_TEMPLATE.format(
        subject=(subject or "(제목 없음)"),
        sender=(sender or "(발신자 미상)"),
        body_preview=body_preview or "(본문 없음)",
        max_chars=BODY_PREVIEW_CHARS,
    )


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"yes", "true", "1", "phishing"}
    return False


def _normalize_reasons(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if isinstance(raw, str):
        return [part.strip() for part in re.split(r"[\n;,]+", raw) if part.strip()]
    return []


def call_openai_analysis(prompt: str, client: Optional[OpenAI] = None, model: Optional[str] = None) -> Dict[str, Any]:
    openai_client = client or OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    response = openai_client.chat.completions.create(
        model=model or OPENAI_MODEL,
        temperature=0.2,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a cybersecurity assistant focused on phishing detection."},
            {"role": "user", "content": prompt},
        ],
    )
    content = response.choices[0].message.content or "{}"
    parsed = json.loads(content)
    return parsed


def analyze_email_content(
    subject: str,
    sender: str,
    body: str,
    client: Optional[OpenAI] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Run phishing analysis using OpenAI and return normalized fields."""
    prompt = build_prompt(subject, sender, sanitize_body(body))
    raw = call_openai_analysis(prompt, client=client, model=model)

    risk_score = int(raw.get("risk_score", 0)) if isinstance(raw, dict) else 0
    risk_score = max(0, min(100, risk_score))
    is_phishing = _normalize_bool(raw.get("is_phishing")) if isinstance(raw, dict) else False
    reasons = _normalize_reasons(raw.get("reasons")) if isinstance(raw, dict) else []
    summary = raw.get("summary", "") if isinstance(raw, dict) else ""

    return {
        "is_phishing": is_phishing,
        "risk_score": risk_score,
        "reasons": reasons,
        "summary": summary.strip(),
    }


@dataclass
class StoredAnalysis:
    message_id: str
    is_phishing: bool
    risk_score: int
    summary: str
    reasons: List[str]


class PhishingAnalysisStore:
    """In-memory store for phishing analysis results, keeping only non-PII fields."""

    def __init__(self):
        self._data: Dict[str, StoredAnalysis] = {}
        self._lock = Lock()

    def save(self, record: Dict[str, Any]) -> None:
        message_id = record.get("messageId")
        if not message_id:
            return
        stored = StoredAnalysis(
            message_id=message_id,
            is_phishing=bool(record.get("isPhishing")),
            risk_score=int(record.get("riskScore", 0)),
            summary=str(record.get("summary", "")),
            reasons=list(record.get("reasons", [])),
        )
        with self._lock:
            self._data[message_id] = stored

    def get(self, message_id: str) -> Optional[StoredAnalysis]:
        with self._lock:
            return self._data.get(message_id)

    def all(self) -> List[StoredAnalysis]:
        with self._lock:
            return list(self._data.values())
