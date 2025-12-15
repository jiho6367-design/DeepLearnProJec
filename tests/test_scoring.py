import math

from scoring import (
    compute_rule_score,
    fuse_scores,
    decide_label,
    clamp_confidence,
)


def test_rule_score_punycode_and_shortener():
    text = "Check https://xn--phish-9o0a.com/login and http://bit.ly/abcd"
    score, signals = compute_rule_score(text, {})
    assert score > 0.4
    reasons = " ".join(sig.reason for sig in signals)
    assert "Punycode" in reasons
    assert "shortener" in reasons.lower()


def test_rule_score_ip_and_port():
    text = "Click http://192.168.1.5:8080/reset"
    score, signals = compute_rule_score(text, {})
    assert score >= 0.2
    assert any("IP literal" in sig.reason for sig in signals)
    assert any("port" in sig.reason for sig in signals)


def test_rule_score_attachment_extension():
    meta = {"attachments": [{"filename": "invoice.zip"}]}
    score, signals = compute_rule_score("", meta)
    assert score >= 0.3
    assert any("Attachment" in sig.reason for sig in signals)


def test_rule_score_auth_failures():
    meta = {"auth_results": {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False}}
    score, signals = compute_rule_score("", meta)
    assert score >= 0.5
    assert len(signals) == 3


def test_rule_score_urgent_keywords():
    text = "URGENT: Your account is suspended, reset password immediately"
    score, signals = compute_rule_score(text, {})
    assert score >= 0.15
    assert any("Urgent keywords" in sig.reason for sig in signals)


def test_fuse_scores_weighting():
    fused_high_model = fuse_scores(0.9, 0.2, model_weight=0.8)
    fused_high_rules = fuse_scores(0.2, 0.9, model_weight=0.2)
    assert fused_high_model > fused_high_rules
    assert 0.0 <= fused_high_model <= 1.0


def test_decide_label_threshold():
    assert decide_label(0.6, threshold=0.5) == "phishing"
    assert decide_label(0.49, threshold=0.5) == "normal"


def test_clamp_confidence_handles_nan():
    assert clamp_confidence(float("nan")) == 0.0
    assert clamp_confidence(-1.0) == 0.0
    assert clamp_confidence(2.0) == 1.0


def test_rule_score_limits_to_one():
    text = " ".join(["http://xn--bad.com"] * 10)
    score, _ = compute_rule_score(text, {})
    assert 0.0 <= score <= 1.0


def test_fusion_changes_decision_with_rules():
    model_prob = 0.25  # model thinks mostly benign
    rule_score = 0.9   # strong rule hit
    fused = fuse_scores(model_prob, rule_score, model_weight=0.4)
    assert fused > model_prob
    assert decide_label(fused, threshold=0.5) == "phishing"
