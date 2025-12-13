from __future__ import annotations

import re
from typing import Dict, Any, List

# Basic patterns for signals
URL_PATTERN = re.compile(r"https?://", re.IGNORECASE)
WEAK_KEYWORDS = {"입급", "urgent", "immediately", "주의", "조치", "update", "confirm"}
CRED_REQUEST = re.compile(r"(password|otp|verify|login|credential|비밀번호|인증코드|로그인)", re.IGNORECASE)
PAYMENT_REQUEST = re.compile(r"(wire|transfer|invoice|payment|bank account|계좌|송금|입금)", re.IGNORECASE)
EXEC_IMPERSONATION = re.compile(r"(ceo|cfo|cto|vp|president|회장|사장)", re.IGNORECASE)


def _severity(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.6:
        return "HIGH"
    if score >= 0.3:
        return "MEDIUM"
    return "LOW"


def _normalize_auth_value(value: Any) -> str:
    """Map bools to pass/fail and normalize strings to lowercase."""
    if value is True:
        return "pass"
    if value is False:
        return "fail"
    return str(value or "").lower()


def score_email(email: Dict[str, Any]) -> Dict[str, Any]:
    """Heuristic multi-signal scorer that avoids single-keyword triggers."""
    headers = email.get("headers", {}) or {}
    raw_body = email.get("body")
    body: str
    if isinstance(raw_body, dict):
        text_part = raw_body.get("text")
        html_part = raw_body.get("html")
        if isinstance(text_part, str):
            body = text_part
        elif isinstance(html_part, str):
            body = html_part
        else:
            body = ""
    elif isinstance(raw_body, str):
        body = raw_body
    elif raw_body is None:
        body = ""
    else:
        # Fallback for unexpected types
        body = str(raw_body)

    # Optional alternative sources
    alt_body = email.get("body_text")
    if not body and isinstance(alt_body, str):
        body = alt_body
    elif not body and alt_body is not None:
        body = str(alt_body)

    urls = email.get("urls") or []
    attachments = email.get("attachments") or []
    context = email.get("context") or {}
    auth = email.get("auth_results") or {}

    evidence_missing: List[str] = []
    if not body.strip():
        evidence_missing.append("body")
    if not headers and not auth:
        evidence_missing.append("headers_auth")
    if not urls and not attachments:
        evidence_missing.append("urls_attachments")

    # If critical evidence missing, return insufficient
    if set(evidence_missing) >= {"body", "headers_auth", "urls_attachments"}:
        return {
            "classification": "INSUFFICIENT_DATA",
            "risk_score": 0.3,
            "severity": "MEDIUM",
            "top_signals": ["Missing body content", "Missing auth/headers", "No URLs or attachments provided"],
            "evidence_missing": evidence_missing,
            "explanation": "Not enough information (body, auth, URLs/attachments absent) to make a confident decision.",
            "recommended_action": "ALLOW_WITH_WARNING",
        }

    risk = 0.0
    top_signals: List[str] = []

    # Auth signals
    spf = _normalize_auth_value(headers.get("spf_result") or auth.get("spf_pass"))
    dkim = _normalize_auth_value(headers.get("dkim_result") or auth.get("dkim_pass"))
    dmarc = _normalize_auth_value(headers.get("dmarc_result") or auth.get("dmarc_pass"))
    auth_fail = False
    if spf in ("fail", "softfail", "false") and dkim in ("fail", "none", "false"):
        risk += 0.25
        auth_fail = True
        top_signals.append("SPF and DKIM failed or absent")
    if dmarc in ("fail", "false"):
        risk += 0.2
        auth_fail = True
        top_signals.append("DMARC failed")

    # URL signals
    suspicious_url = False
    if urls:
        for u in urls:
            domain = (u.get("domain") or "").lower()
            rep = u.get("reputation_score")
            if rep is not None and rep < 0.3:
                suspicious_url = True
                risk += 0.2
                top_signals.append(f"Low-reputation URL domain {domain}")
            if domain and re.match(r"^\\d+\\.\\d+\\.\\d+\\.\\d+$", domain):
                suspicious_url = True
                risk += 0.2
                top_signals.append("URL uses IP address")
            if u.get("is_shortened"):
                suspicious_url = True
                risk += 0.1
                top_signals.append("Shortened URL present")
    elif URL_PATTERN.search(body):
        # links present but not parsed; mild boost
        risk += 0.05
        top_signals.append("Unparsed URL text in body")

    # Attachment signals
    risky_attachment = False
    for att in attachments:
        fname = att.get("filename", "").lower()
        if fname.endswith((".exe", ".js", ".vbs", ".bat", ".cmd", ".scr", ".ps1")) or att.get("is_archive"):
            risky_attachment = True
            risk += 0.25
            top_signals.append(f"Risky attachment: {fname or 'archive'}")
        if att.get("contains_macro_or_script"):
            risky_attachment = True
            risk += 0.2
            top_signals.append("Attachment contains macro/script")

    # Content/social engineering
    cred_req = bool(CRED_REQUEST.search(body))
    pay_req = bool(PAYMENT_REQUEST.search(body))
    exec_imp = bool(EXEC_IMPERSONATION.search(body + " " + (headers.get("from_display_name") or "")))

    if cred_req:
        risk += 0.25
        top_signals.append("Credential/OTP request detected")
    if pay_req:
        risk += 0.25
        top_signals.append("Payment/bank change request detected")
    if exec_imp:
        risk += 0.2
        top_signals.append("Executive/role impersonation cues")

    # Weak keywords: cap at +0.05 total
    body_l = body.lower()
    weak_hit = any(kw.lower() in body_l for kw in WEAK_KEYWORDS)
    if weak_hit:
        risk += 0.05
        top_signals.append("Weak lexical cue present")

    # Context
    if context.get("is_first_time_sender"):
        risk += 0.05
        top_signals.append("First-time sender")
    if context.get("sender_reported_as_phishing_count", 0) > 0:
        risk += 0.2
        top_signals.append("Sender previously reported as phishing")

    # Ensure multi-signal rule for high risk
    strong_signals = sum(
        1 for flag in (auth_fail, suspicious_url, risky_attachment, cred_req, pay_req, exec_imp) if flag
    )

    if strong_signals < 2:
        risk = min(risk, 0.89)


    risk = min(1.0, risk)

    # Classification
    if cred_req or pay_req or suspicious_url or risky_attachment or auth_fail or exec_imp:
        if exec_imp and pay_req:
            classification = "ADVANCED_PHISHING"
            risk = max(risk, 0.85 if strong_signals >= 2 else 0.75)
        else:
            classification = "NORMAL_PHISHING" if risk >= 0.7 or strong_signals >= 2 else "SUSPICIOUS"
    else:
        classification = "BENIGN" if risk <= 0.25 else "SUSPICIOUS"

    severity = _severity(risk)

    if classification == "BENIGN" and evidence_missing:
        classification = "INSUFFICIENT_DATA"
        risk = max(risk, 0.3)
        severity = _severity(risk)

    recommended_action = {
        "BENIGN": "ALLOW",
        "SUSPICIOUS": "ALLOW_WITH_WARNING",
        "NORMAL_PHISHING": "QUARANTINE",
        "ADVANCED_PHISHING": "BLOCK",
        "INSUFFICIENT_DATA": "ALLOW_WITH_WARNING",
    }[classification]

    explanation_parts = []
    if top_signals:
        explanation_parts.append("Signals: " + "; ".join(top_signals[:4]))
    if evidence_missing:
        explanation_parts.append("Missing evidence: " + ", ".join(evidence_missing))
    explanation = " ".join(explanation_parts) or "No notable signals."

    return {
        "classification": classification,
        "risk_score": round(risk, 3),
        "severity": severity,
        "top_signals": top_signals[:7],
        "evidence_missing": evidence_missing,
        "explanation": explanation,
        "recommended_action": recommended_action,
    }
