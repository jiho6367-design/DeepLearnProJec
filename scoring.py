from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence, Tuple
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".icu",
    ".vip",
    ".click",
    ".link",
    ".pw",
    ".live",
    ".shop",
    ".center",
    ".work",
    ".quest",
}

SHORTENER_HOSTS = {
    "bit.ly",
    "t.co",
    "goo.gl",
    "ow.ly",
    "tinyurl.com",
    "is.gd",
    "buff.ly",
    "shorte.st",
    "lnkd.in",
    "cutt.ly",
}

SUSPICIOUS_EXTENSIONS = {".zip", ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jar", ".docm", ".xlsm"}
URGENT_KEYWORDS = {
    "otp",
    "2fa",
    "mfa",
    "verify",
    "verification",
    "secure",
    "suspend",
    "suspended",
    "reset",
    "urgent",
    "immediately",
    "account locked",
    "password",
    "bank",
    "invoice",
    "payment",
}


@dataclass
class RuleSignal:
    name: str
    score: float
    reason: str


URL_REGEX = re.compile(r"(?:(?:https?://)|(?:www.))[^\s)]+", flags=re.IGNORECASE)


def _extract_urls(text: str) -> List[str]:
    return URL_REGEX.findall(text or "")


def _is_ip(host: str) -> bool:
    if not host:
        return False
    octets = host.split(".")
    if len(octets) == 4:
        return all(o.isdigit() and 0 <= int(o) <= 255 for o in octets)
    return False


def _score_urls(urls: Iterable[str]) -> List[RuleSignal]:
    signals: List[RuleSignal] = []
    for url in urls:
        normalized_url = url
        if url.lower().startswith("www."):
            normalized_url = "https://" + url
        parsed = urlparse(normalized_url)
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()

        if scheme not in {"http", "https"}:
            signals.append(RuleSignal("bad_scheme", 0.35, f"Non-HTTP scheme: {scheme}"))
        if parsed.port and parsed.port not in {80, 443}:
            signals.append(RuleSignal("non_standard_port", 0.2, f"Non-standard port {parsed.port}"))
        if host.startswith("xn--"):
            signals.append(RuleSignal("punycode", 0.4, f"Punycode host: {host}"))
        if _is_ip(host):
            signals.append(RuleSignal("ip_literal", 0.25, f"IP literal URL: {host}"))
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            signals.append(RuleSignal("suspicious_tld", 0.3, f"Suspicious TLD: {host}"))
        if host.count("-") >= 2:
            signals.append(RuleSignal("hyphenated_host", 0.15, f"Hyphenated host: {host}"))
        if host in SHORTENER_HOSTS:
            signals.append(RuleSignal("url_shortener", 0.25, f"URL shortener: {host}"))
    return signals


def _score_auth(meta: Dict[str, Any]) -> List[RuleSignal]:
    auth = meta.get("auth_results", {}) or {}
    signals: List[RuleSignal] = []
    for field in ("spf_pass", "dkim_pass", "dmarc_pass"):
        value = auth.get(field)
        if value is False:
            signals.append(RuleSignal("auth_fail", 0.25, f"{field} failed"))
    return signals


def _score_attachments(meta: Dict[str, Any]) -> List[RuleSignal]:
    attachments = meta.get("attachments") or []
    signals: List[RuleSignal] = []
    for att in attachments:
        filename = (att.get("filename") or "").lower()
        for ext in SUSPICIOUS_EXTENSIONS:
            if filename.endswith(ext):
                signals.append(RuleSignal("dangerous_attachment", 0.3, f"Attachment: {filename}"))
                break
    return signals


def _score_keywords(text: str) -> List[RuleSignal]:
    lowered = (text or "").lower()
    hits = [kw for kw in URGENT_KEYWORDS if kw in lowered]
    if not hits:
        return []
    weight = min(0.3, 0.1 + 0.05 * len(hits))
    return [RuleSignal("urgent_language", weight, f"Urgent keywords: {', '.join(hits)}")]


def compute_rule_score(text: str, meta: Dict[str, Any] | None = None) -> Tuple[float, List[RuleSignal]]:
    meta = meta or {}
    signals: List[RuleSignal] = []

    urls = _extract_urls(text)
    signals.extend(_score_urls(urls))
    signals.extend(_score_auth(meta))
    signals.extend(_score_attachments(meta))
    signals.extend(_score_keywords(text))

    if meta.get("from_header"):
        sender = str(meta.get("from_header"))
        if any(sender.lower().endswith(dom) for dom in (".ru", ".tk", ".top")):
            signals.append(RuleSignal("sender_domain", 0.1, f"Sender domain: {sender}"))

    total_weight = sum(sig.score for sig in signals)
    rule_score = max(0.0, min(1.0, total_weight))
    return rule_score, signals


def fuse_scores(model_phish_prob: float, rule_score: float, model_weight: float = 0.7) -> float:
    model_weight = max(0.0, min(1.0, model_weight))
    rule_weight = 1.0 - model_weight
    fused = model_weight * model_phish_prob + rule_weight * rule_score
    return max(0.0, min(1.0, fused))


def decide_label(fused_score: float, threshold: float = 0.5) -> str:
    return "phishing" if fused_score >= threshold else "normal"


def clamp_confidence(value: float) -> float:
    if math.isnan(value) or math.isinf(value):
        return 0.0
    return max(0.0, min(1.0, float(value)))
