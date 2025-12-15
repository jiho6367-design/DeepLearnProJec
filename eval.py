from __future__ import annotations

import argparse
import csv
import os
from typing import Any, Dict, List, Tuple

from optimized_pipeline import classify_batch, PHISH_THRESHOLD, MODEL_WEIGHT
from scoring import compute_rule_score, fuse_scores, decide_label, clamp_confidence


def _load_rows(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [row for row in reader]


def _to_bool(label: str) -> int:
    normalized = (label or "").strip().lower()
    return 1 if normalized in {"phishing", "spam", "1", "true", "yes", "bad"} else 0


def _combine_text(row: Dict[str, Any]) -> str:
    if row.get("text"):
        return row["text"]
    subject = row.get("subject", "")
    body = row.get("body", "")
    return "\n".join(part for part in (subject, body) if part)


def _predict(texts: List[str]) -> List[Dict[str, Any]]:
    base = classify_batch(texts)
    fused: List[Dict[str, Any]] = []
    for item in base:
        rule_score, _ = compute_rule_score(item["text"], {})
        fused_score = fuse_scores(item["phish_probability"], rule_score, model_weight=MODEL_WEIGHT)
        fused.append(
            {
                "text": item["text"],
                "phish_probability": clamp_confidence(fused_score),
            }
        )
    return fused


def _metrics(y_true: List[int], scores: List[float], threshold: float) -> Dict[str, float]:
    tp = fp = fn = tn = 0
    for truth, score in zip(y_true, scores):
        pred = 1 if score >= threshold else 0
        if truth == 1 and pred == 1:
            tp += 1
        elif truth == 0 and pred == 1:
            fp += 1
        elif truth == 1 and pred == 0:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def threshold_sweep(y_true: List[int], scores: List[float], thresholds: List[float]) -> List[Tuple[float, Dict[str, float]]]:
    return [(t, _metrics(y_true, scores, t)) for t in thresholds]


def main():
    parser = argparse.ArgumentParser(description="Offline evaluation for phishing detector.")
    parser.add_argument("csv_path", help="CSV file with columns: text or subject/body, label")
    parser.add_argument("--threshold", type=float, default=PHISH_THRESHOLD, help="Decision threshold for phishing.")
    parser.add_argument("--sweep", action="store_true", help="Print threshold sweep from 0.1 to 0.9.")
    args = parser.parse_args()

    rows = _load_rows(args.csv_path)
    if not rows:
        raise SystemExit("No rows found in CSV.")

    texts = [_combine_text(row) for row in rows]
    labels = [_to_bool(row.get("label", "")) for row in rows]

    predictions = _predict(texts)
    scores = [p["phish_probability"] for p in predictions]

    metrics = _metrics(labels, scores, args.threshold)
    print(f"Records: {len(rows)}")
    print(f"Threshold: {args.threshold:.2f}")
    print(
        f"Precision: {metrics['precision']:.3f}  Recall: {metrics['recall']:.3f}  F1: {metrics['f1']:.3f}  "
        f"TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} TN={metrics['tn']}"
    )

    if args.sweep:
        thresholds = [round(x, 2) for x in [0.1 + i * 0.05 for i in range(17)]]
        print("\nThreshold sweep (precision / recall / f1):")
        for t, m in threshold_sweep(labels, scores, thresholds):
            print(f"{t:.2f}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUTF8", "1")
    main()
