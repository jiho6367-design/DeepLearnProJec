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

TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "office.com",
    "outlook.com",
    "live.com",
    "sharepoint.com",
    "github.com",
    "dropbox.com",
    "box.com",
    "adobe.com",
}

ACTION_LINK_KEYWORDS = {
    "login",
    "log in",
    "verify",
    "verification",
    "confirm",
    "access",
    "view",
    "review",
    "claim",
    "wallet",
    "secure session",
    "document",
}


@dataclass
class RuleSignal:
    name: str
    score: float
    reason: str


URL_REGEX = re.compile(r"(?:(?:https?://)|(?:www\.))[^\s)]+", flags=re.IGNORECASE)


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
        normalized_url = url.strip()

        # 흔한 끝문자 정리 (메일/HTML에서 링크 뒤에 붙는 괄호/마침표 등)
        normalized_url = normalized_url.strip(" <>\"'.,;:!?)].")

        if normalized_url.lower().startswith("www."):
            normalized_url = "https://" + normalized_url

        try:
            parsed = urlparse(normalized_url)
        except Exception:
            # Malformed URL should not break scoring; skip it.
            continue

        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()

        if not host:
            continue

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


def _is_trusted_host(host: str) -> bool:
    return any(host == dom or host.endswith("." + dom) for dom in TRUSTED_DOMAINS)


def _score_untrusted_link_with_action(text: str, urls: Iterable[str]) -> List[RuleSignal]:
    lowered = (text or "").lower()
    action_hit = next((kw for kw in ACTION_LINK_KEYWORDS if kw in lowered), None)
    if not action_hit:
        return []
    signals: List[RuleSignal] = []
    for url in urls:
        normalized_url = url.strip().strip(" <>\"'.,;:!?)].")
        if normalized_url.lower().startswith("www."):
            normalized_url = "https://" + normalized_url
        try:
            host = (urlparse(normalized_url).hostname or "").lower()
        except Exception:
            continue
        if not host or _is_trusted_host(host):
            continue
        signals.append(
            RuleSignal(
                "untrusted_link_action",
                0.35,
                f"Untrusted link host {host} with action keyword '{action_hit}'",
            )
        )
        break
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


RECEIPT_KEYWORDS = [
    "결제",
    "영수증",
    "구독",
    "청구",
    "승인",
    "금액",
    "krw",
    "원",
    "카드",
    "결제일",
    "주문번호",
    "invoice",
    "receipt",
    "payment",
    "subscription",
]

ACTION_KEYWORDS = [
    "로그인",
    "login",
    "verify",
    "인증",
    "click",
    "링크",
    "비밀번호",
    "password",
    "계정",
    "정지",
    "환불",
    "update payment",
    "confirm",
]


def _looks_like_receipt(text: str) -> bool:
    lowered = (text or "").lower()
    hits = sum(1 for kw in RECEIPT_KEYWORDS if kw in lowered)
    return hits >= 2


def _has_action_request(text: str) -> bool:
    lowered = (text or "").lower()
    return any(kw in lowered for kw in ACTION_KEYWORDS)


def compute_rule_score(text: str, meta: Dict[str, Any] | None = None) -> Tuple[float, List[RuleSignal]]:
    meta = meta or {}
    signals: List[RuleSignal] = []

    urls = _extract_urls(text)
    signals.extend(_score_urls(urls))
    signals.extend(_score_untrusted_link_with_action(text, urls))
    signals.extend(_score_auth(meta))
    signals.extend(_score_attachments(meta))
    signals.extend(_score_keywords(text))

    if meta.get("from_header"):
        sender = str(meta.get("from_header"))
        if any(sender.lower().endswith(dom) for dom in (".ru", ".tk", ".top")):
            signals.append(RuleSignal("sender_domain", 0.1, f"Sender domain: {sender}"))

    total_weight = sum(sig.score for sig in signals)
    rule_score = max(0.0, min(1.0, total_weight))

    try:
        whitelist_allowed = (
            _looks_like_receipt(text)
            and not urls
            and not _has_action_request(text)
            and not any(sig.name == "auth_fail" for sig in signals)
            and not any(sig.name == "dangerous_attachment" for sig in signals)
        )
        if whitelist_allowed:
            rule_score = max(0.0, rule_score - 0.25)
    except Exception:
        pass

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
