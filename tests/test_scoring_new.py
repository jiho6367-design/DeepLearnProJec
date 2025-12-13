import pytest

from scoring import score_email


def test_benign():
    email = {
        "headers": {"spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"},
        "body": {"text": "Welcome to our service. View your account online.", "html": None},
        "urls": [
            {"domain": "example.com", "reputation_score": 0.9, "is_shortened": False},
        ],
        "attachments": [],
        "context": {"is_first_time_sender": False},
    }
    res = score_email(email)
    assert res["classification"] == "BENIGN"
    assert res["risk_score"] <= 0.25


def test_normal_phishing():
    email = {
        "headers": {"spf_result": "fail", "dkim_result": "none", "dmarc_result": "fail"},
        "body": {"text": "Your password expires. Login here now to keep access.", "html": None},
        "urls": [
            {"domain": "bad-login.cc", "reputation_score": 0.1, "is_shortened": False},
        ],
        "attachments": [],
        "context": {"is_first_time_sender": True},
    }
    res = score_email(email)
    assert res["classification"] in ("NORMAL_PHISHING", "ADVANCED_PHISHING")
    assert res["risk_score"] >= 0.7


def test_advanced_phishing():
    email = {
        "headers": {"spf_result": "fail", "dkim_result": "fail", "dmarc_result": "fail", "from_display_name": "CEO John"},
        "body": {"text": "Wire $50,000 today to the new vendor account. CEO John", "html": None},
        "urls": [],
        "attachments": [],
        "context": {"is_first_time_sender": True, "recipient_role": "finance_approver"},
    }
    res = score_email(email)
    assert res["classification"] in ("ADVANCED_PHISHING", "NORMAL_PHISHING")
    assert res["risk_score"] >= 0.8


def test_insufficient_data():
    email = {
        "headers": {},
        "body": {"text": "", "html": None},
        "urls": [],
        "attachments": [],
        "context": {},
    }
    res = score_email(email)
    assert res["classification"] == "INSUFFICIENT_DATA"
    assert 0.2 <= res["risk_score"] <= 0.45
