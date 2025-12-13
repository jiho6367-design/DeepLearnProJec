import os
from typing import Dict, List

import httpx


def heuristic_analyze(body: str) -> Dict:
    lower = (body or "").lower()
    risk = 0.1
    reasons: List[str] = []
    actions: List[str] = []
    if "password" in lower or "verify" in lower:
        risk += 0.3
        reasons.append("Contains credential request keywords")
    if "link" in lower or "http" in lower:
        risk += 0.2
        reasons.append("Contains links")
        actions.append("Hover links to verify domain")
    if "urgent" in lower or "immediately" in lower:
        risk += 0.2
        reasons.append("Uses urgency language")
        actions.append("Verify sender via separate channel")
    risk = min(1.0, risk)
    verdict = "phishing" if risk >= 0.6 else "legit"
    summary = "Heuristic assessment based on keywords."
    return {
        "verdict": verdict,
        "score": risk,
        "summary": summary,
        "reasons": reasons,
        "recommended_actions": actions or ["Use caution with links and attachments"],
        "llm_available": False,
    }


async def analyze_body_deep(body: str) -> Dict:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not configured")
    prompt = (
        "You are a security analyst. Classify the following email text as phishing or legit. "
        "Return JSON with keys: verdict (phishing|legit), score (0-1), summary, reasons (array), recommended_actions (array). "
        "Email text:\n"
        f"{body[:4000]}"
    )
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"},
        "temperature": 0,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
    content = data["choices"][0]["message"]["content"]
    import json

    parsed = json.loads(content)
    return parsed
