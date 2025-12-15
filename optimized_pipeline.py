from __future__ import annotations

import asyncio
import os
import time
from typing import Sequence, Dict, Any, List

import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from openai import AsyncOpenAI

from scoring import compute_rule_score, fuse_scores, decide_label, clamp_confidence

# Lightweight fusion of a fast HuggingFace classifier + rule-based signals.
FAST_MODEL = os.getenv("FAST_MODEL", "philschmid/MiniLM-L6-H384-uncased-sst2")
PHISH_THRESHOLD = float(os.getenv("PHISH_THRESHOLD", "0.25"))
# Relative weight of the model vs. rules for fusion; can be tuned offline.
MODEL_WEIGHT = float(os.getenv("MODEL_WEIGHT", "0.7"))
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

tokenizer = AutoTokenizer.from_pretrained(FAST_MODEL, use_fast=True)
model = AutoModelForSequenceClassification.from_pretrained(
    FAST_MODEL,
    dtype=torch.float16 if DEVICE.type == "cuda" else torch.float32,
).to(DEVICE).eval()

async_client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))


def _infer_label_mapping() -> Dict[int, str]:
    return {idx: str(lbl).upper() for idx, lbl in model.config.id2label.items()}


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

    id2label = _infer_label_mapping()
    phish_idx = next((i for i, lbl in id2label.items() if "NEG" in lbl or "PHISH" in lbl), None)

    outputs = []
    for i, prob in enumerate(probs):
        idx = int(prob.argmax())
        raw = id2label.get(idx, "")
        base_label = "phishing" if raw.startswith("NEG") or "PHISH" in raw else "normal"
        base_conf = clamp_confidence(float(prob[idx]))
        phish_prob = (
            clamp_confidence(float(prob[phish_idx]))
            if phish_idx is not None
            else (base_conf if base_label == "phishing" else 1.0 - base_conf)
        )
        outputs.append(
            {
                "text": texts[i],
                "base_label": base_label,
                "base_confidence": base_conf,
                "phish_probability": phish_prob,
            }
        )
    return outputs


async def feedback_async(
    items: Sequence[Dict[str, Any]], detection_policy: str = ""
) -> Sequence[Dict[str, Any]]:
    if not os.environ.get("OPENAI_API_KEY"):
        return [{"content": None, "latency_ms": None} for _ in items]

    async def _one(item: Dict[str, Any]):
        prompt = f"""Detection policy:
{detection_policy or 'Use best-practice phishing detection criteria (payload, sender, urgency, links).'}

Email:
{item['text']}

Verdict: {item['label']} ({item['confidence']:.2%})

Explain briefly why/why not it is risky, cite the policy items you used, and give three safe actions.
모든 설명과 메세지는 한국어로 작성하세요"""
        started = time.perf_counter()
        resp = await async_client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            temperature=0.2,
            max_tokens=320,
            messages=[
                {
                    "role": "system",
                    "content": "You are a concise cybersecurity analyst. 모든 설명과 메세지는 한국어로 작성하세요",
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


def analyze_emails(texts: Sequence[str], metas: Sequence[Dict[str, Any]] | None = None) -> Sequence[Dict[str, Any]]:
    metas = metas or [{} for _ in texts]
    base_results = classify_batch(texts)
    detection_policy = os.getenv(
        "PHISHING_POLICY",
        (
            "Follow Gmail spam indicators, SPF/DKIM/DMARC failures, suspicious links, "
            "unexpected attachments, sender mismatch, and urgent/social-engineering language."
        ),
    )

    fused_records: List[Dict[str, Any]] = []
    for base, meta in zip(base_results, metas):
        rule_score, signals = compute_rule_score(base["text"], meta)
        fused = fuse_scores(base["phish_probability"], rule_score, model_weight=MODEL_WEIGHT)
        label = decide_label(fused, threshold=PHISH_THRESHOLD)
        fused_records.append(
            {
                "text": base["text"],
                "label": label,
                "confidence": clamp_confidence(fused),
                "rule_score": clamp_confidence(rule_score),
                "rule_signals": [sig.reason for sig in signals],
                "base_label": base["base_label"],
                "base_confidence": base["base_confidence"],
                "base_phish_probability": base["phish_probability"],
            }
        )

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        feedback = asyncio.run(feedback_async(fused_records, detection_policy=detection_policy))
    else:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, feedback_async(fused_records, detection_policy=detection_policy))
            feedback = future.result()

    for record, fb in zip(fused_records, feedback):
        record["feedback"] = fb["content"]
        record["latency_ms"] = fb["latency_ms"]
    return fused_records
