import os

os.environ.setdefault("OPENAI_API_KEY", "test-key")

import api_service


def test_fetch_and_analyze_endpoint(monkeypatch):
    sample_emails = [
        {
            "id": "abc123",
            "subject": "Invoice",
            "body": "Please open attachment",
            "attachments": [{"filename": "alert.docm", "mimeType": "application/msword"}],
        }
    ]

    monkeypatch.setattr(api_service, "get_unread_emails", lambda max_results=10: sample_emails)
    monkeypatch.setattr(api_service, "classify_email", lambda text: ("phishing", 0.8))
    monkeypatch.setattr(api_service, "verify_and_meter", lambda token, cost=1: ({"plan": "free"}, 3))
    monkeypatch.setattr(api_service, "log_email_analysis", lambda *args, **kwargs: None)

    client = api_service.app.test_client()
    response = client.post(
        "/api/fetch_and_analyze",
        json={"max_results": 1},
        headers={"X-API-Key": "tok"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert "results" in data
    assert data["results"][0]["label"] == "phishing"
    assert "suspicious attachment" in data["results"][0]["reason"]
