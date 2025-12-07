from __future__ import annotations

import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Sequence, Dict, Any
import re
from urllib.parse import urlparse

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from openai import AsyncOpenAI

FAST_MODEL = os.getenv("FAST_MODEL", "philschmid/MiniLM-L6-H384-uncased-sst2")
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

tokenizer = AutoTokenizer.from_pretrained(FAST_MODEL, use_fast=True)
model = AutoModelForSequenceClassification.from_pretrained(
    FAST_MODEL,
    dtype=torch.float16 if DEVICE.type == "cuda" else torch.float32,
).to(DEVICE).eval()

async_client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


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

SUSPICIOUS_KEYWORDS = [
    "otp",
    "보안",
    "이상거래",
    "비정상",
    "재등록",
    "계좌",
    "출금",
    "인증",
    "로그인",
    "verify",
    "secure",
    "update",
    "suspend",
    "reset",
    "urgent",
    "auth",
]


def _has_suspicious_url(text: str) -> bool:
    urls = re.findall(r"https?://[^\s)]+", text, flags=re.IGNORECASE)
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            return True
        if host.count("-") >= 2:
            return True
    return False


def _suspicion_boost(text: str) -> float:
    """Lightweight heuristic to boost phishing confidence for banking/OTP lures."""
    lowered = text.lower()
    score = 0.0
    if _has_suspicious_url(text):
        score += 0.35
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lowered:
            score += 0.08
    return min(score, 0.6)


@torch.inference_mode()
def classify_batch(texts: Sequence[str]) -> Sequence[Dict[str, Any]]:
    inputs = tokenizer(
        list(texts),
        padding=True,
        truncation=True,
        max_length=256,
        return_tensors="pt",
    ).to(DEVICE)
    logits = model(**inputs).logits
    probs = F.softmax(logits, dim=-1)
    outputs = []
    for i, prob in enumerate(probs):
        idx = int(prob.argmax())
        raw = model.config.id2label[idx].upper()
        label = "phishing" if raw.startswith("NEG") else "normal"
        confidence = float(prob[idx])

        boost = _suspicion_boost(texts[i])
        if boost and label == "normal":
            label = "phishing"
            confidence = max(confidence, min(0.99, confidence + boost))
        elif boost:
            confidence = min(0.99, confidence + boost * 0.5)

        outputs.append(
            {
                "text": texts[i],
                "label": label,
                "confidence": confidence,
            }
        )
    return outputs


def analyze_in_threads(texts: Sequence[str], batch_size: int = 64) -> Sequence[Dict[str, Any]]:
    batches = [texts[i : i + batch_size] for i in range(0, len(texts), batch_size)]
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        results = pool.map(classify_batch, batches)
    flattened = [item for batch in results for item in batch]
    return flattened


async def feedback_async(
    items: Sequence[Dict[str, Any]], detection_policy: str = ""
) -> Sequence[Dict[str, Any]]:
    async def _one(item: Dict[str, Any]):
        prompt = f"""Detection policy:
{detection_policy or 'Use best-practice phishing detection criteria (payload, sender, urgency, links).'}

Email:
{item['text']}

Verdict: {item['label']} ({item['confidence']:.2%})

Explain briefly why/why not it is risky, cite the policy items you used, and give three safe actions.
모든 설명과 피드백 문장은 한국어로 작성하세요."""
        started = time.perf_counter()
        resp = await async_client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            temperature=0.2,
            max_tokens=320,
            messages=[
                {
                    "role": "system",
                    "content": "You are a concise cybersecurity analyst. 모든 설명과 피드백은 한국어로 작성하세요.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        latency_ms = (time.perf_counter() - started) * 1000
        return {
            "content": resp.choices[0].message.content.strip(),
            "latency_ms": latency_ms,
        }

    responses = await asyncio.gather(*(_one(item) for item in items), return_exceptions=False)
    return responses


def analyze_emails(texts: Sequence[str]) -> Sequence[Dict[str, Any]]:
    batches = analyze_in_threads(texts)
    detection_policy = os.getenv(
        "PHISHING_POLICY",
        (
            "Follow Gmail spam indicators, SPF/DKIM/DMARC failures, suspicious links, "
            "unexpected attachments, sender mismatch, and urgent/social-engineering language."
        ),
    )
    feedback = asyncio.run(feedback_async(batches, detection_policy=detection_policy))
    for record, fb in zip(batches, feedback):
        record["feedback"] = fb["content"]
        record["latency_ms"] = fb["latency_ms"]
    return batches
