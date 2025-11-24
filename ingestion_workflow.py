from __future__ import annotations

import os
from typing import Any, Dict, List

from mail_service import GmailAuthError, get_unread_emails
from optimized_pipeline import analyze_emails

DEFAULT_POLICY = """
- Gmail 분류(SPAM, IMPORTANT)와 사용자 신고 여부를 참고한다.
- SPF/DKIM/DMARC 검증 실패, 링크/첨부파일 존재 여부를 위험 신호로 본다.
- 발신자·도메인 위장, 급박/금전 요청, 로그인 유도 링크 등 사회공학 패턴을 최우선 점검한다.
- 조직 정책에 따라 의심 단계(격리/모니터링/허용)를 명시적으로 제안한다.
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
        raise SystemExit(f"⚠️ Gmail 자격 증명이 누락되었습니다: {exc}")

    if not reports:
        print("새로운 읽지 않은 메일이 없습니다.")
    for report in reports:
        print("=" * 60)
        print(f"Subject: {report.get('subject')}")
        print(f"Predicted: {report.get('label')} ({report.get('confidence'):.2%})")
        print(f"Gmail labels: {', '.join(report.get('gmail_labels', [])) or 'none'}")
        print(f"Auth results: {report.get('auth_results')}")
        print("Feedback:\n" + (report.get('feedback') or "(none)"))
        print(f"LLM latency: {report.get('latency_ms', 0):.0f} ms")
