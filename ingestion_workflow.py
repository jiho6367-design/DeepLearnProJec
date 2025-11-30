from __future__ import annotations

import os
from typing import Any, Dict, List

from dotenv import load_dotenv

# .env를 먼저 로드해야 OpenAI/Gmail 키가 optimized_pipeline 초기화 전에 적용됨
load_dotenv(".env")
os.environ.setdefault("PYTHONUTF8", "1")

from mail_service import GmailAuthError, get_unread_emails
from optimized_pipeline import analyze_emails

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


def fetch_and_analyze_unread(max_results: int = 5) -> List[Dict[str, Any]]:
    """Fetch unread Gmail messages, enrich with signals, and analyze with the pipeline."""

    emails = get_unread_emails(max_results=max_results)
    if not emails:
        return []

    texts = [_as_prompt_text(email) for email in emails]
    os.environ.setdefault("PHISHING_POLICY", DEFAULT_POLICY)
    model_outputs = analyze_emails(texts)

    combined: List[Dict[str, Any]] = []
    for meta, analysis in zip(emails, model_outputs):
        combined.append(
            {
                **meta,
                "label": analysis.get("label"),
                "confidence": analysis.get("confidence"),
                "feedback": analysis.get("feedback"),
                "latency_ms": analysis.get("latency_ms"),
            }
        )
    return combined


if __name__ == "__main__":
    try:
        limit = int(os.getenv("MAX_EMAILS", "5"))
    except ValueError:
        limit = 5

    try:
        reports = fetch_and_analyze_unread(max_results=limit)
    except GmailAuthError as exc:
        raise SystemExit(f"❌ Gmail OAuth2 자격 증명이 환경 변수에서 로드되지 않았습니다: {exc}")

    if not reports:
        print("새로 확인할 메일이 없습니다.")
    for report in reports:
        print("=" * 60)
        print(f"Subject: {report.get('subject')}")
        print(f"Predicted: {report.get('label')} ({report.get('confidence'):.2%})")
        print(f"Gmail labels: {', '.join(report.get('gmail_labels', [])) or 'none'}")
        print(f"Auth results: {report.get('auth_results')}")
        print("Feedback:\n" + (report.get('feedback') or "(none)"))
        print(f"LLM latency: {report.get('latency_ms', 0):.0f} ms")
