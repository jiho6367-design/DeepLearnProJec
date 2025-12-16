from __future__ import annotations

import argparse
import csv
import os
import re
from typing import Any, Dict, List, Tuple

from optimized_pipeline import classify_batch, PHISH_THRESHOLD, MODEL_WEIGHT
from scoring import compute_rule_score, fuse_scores, clamp_confidence


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


def _extract_meta(row: Dict[str, Any]) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    auth = {}
    for key in ("spf_pass", "dkim_pass", "dmarc_pass"):
        if key in row and row[key] != "":
            auth[key] = str(row[key]).strip().lower() in {"1", "true", "yes", "pass"}
    if auth:
        meta["auth_results"] = auth
    if "attachments" in row and row["attachments"]:
        att_list = []
        for token in re.split(r"[;,]", str(row["attachments"])):
            token = token.strip()
            if not token:
                continue
            att_list.append({"filename": token})
        meta["attachments"] = att_list
    return meta


def _predict_components(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    texts = [_combine_text(row) for row in rows]
    metas = [_extract_meta(row) for row in rows]
    base = classify_batch(texts)
    fused: List[Dict[str, Any]] = []
    for item, meta in zip(base, metas):
        rule_score, signals = compute_rule_score(item["text"], meta)
        fused.append(
            {
                "text": item["text"],
                "base_prob": clamp_confidence(item["phish_probability"]),
                "rule_score": clamp_confidence(rule_score),
                "rule_signals": [sig.reason for sig in signals],
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
    parser.add_argument("--out", type=str, default=None, help="Write per-row results to CSV.")
    args = parser.parse_args()

    rows = _load_rows(args.csv_path)
    if not rows:
        raise SystemExit("No rows found in CSV.")

    labels = [_to_bool(row.get("label", "")) for row in rows]

    components = _predict_components(rows)
    scores = [fuse_scores(row["base_prob"], row["rule_score"], model_weight=MODEL_WEIGHT) for row in components]

    metrics = _metrics(labels, scores, args.threshold)
    print(f"Records: {len(rows)}")
    print(f"Threshold: {args.threshold:.2f}")
    print(
        f"Precision: {metrics['precision']:.3f}  Recall: {metrics['recall']:.3f}  F1: {metrics['f1']:.3f}  "
        f"TP={metrics['tp']} FP={metrics['fp']} FN={metrics['fn']} TN={metrics['tn']}"
    )

    if args.out:
        out_fields = ["base_prob", "rule_score", "fused", "label", "gt_label", "rule_signals"]
        with open(args.out, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=out_fields)
            writer.writeheader()
            for comp, score, gt in zip(components, scores, labels):
                pred_label = "phishing" if score >= args.threshold else "normal"
                writer.writerow(
                    {
                        "base_prob": f"{comp['base_prob']:.4f}",
                        "rule_score": f"{comp['rule_score']:.4f}",
                        "fused": f"{score:.4f}",
                        "label": pred_label,
                        "gt_label": "phishing" if gt else "normal",
                        "rule_signals": "; ".join(comp.get("rule_signals", []))[:200],
                    }
                )

    if args.sweep:
        thresholds = [round(x, 2) for x in [0.1 + i * 0.05 for i in range(17)]]
        model_weights = [0.60, 0.65, 0.70, 0.75, 0.80]
        print("\nWeight/Threshold sweep (precision / recall / f1):")
        for mw in model_weights:
            row_components = components
            sweep_scores = [fuse_scores(c["base_prob"], c["rule_score"], model_weight=mw) for c in row_components]
            for t in thresholds:
                m = _metrics(labels, sweep_scores, t)
                print(f"mw={mw:.2f} t={t:.2f}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUTF8", "1")
    main()
