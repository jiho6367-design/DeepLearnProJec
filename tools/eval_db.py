from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from scoring import clamp_confidence, fuse_scores


def list_tables(conn: sqlite3.Connection) -> List[str]:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return [row[0] for row in cur.fetchall()]


def table_columns(conn: sqlite3.Connection, table: str) -> List[Tuple[str, str]]:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return [(row[1], row[2]) for row in cur.fetchall()]


def detect_pred_table(conn: sqlite3.Connection, tables: List[str]) -> Optional[str]:
    best = None
    best_score = -1
    for t in tables:
        cols = {c.lower() for c, _ in table_columns(conn, t)}
        score = 0
        if "label" in cols:
            score += 2
        if "confidence" in cols:
            score += 2
        if "feedback" in cols:
            score += 1
        if "phish_probability" in cols or "base_prob" in cols:
            score += 1
        if score > best_score:
            best_score = score
            best = t
    return best


def detect_gt_column(columns: List[str]) -> Optional[str]:
    candidates = ["gt_label", "true_label", "user_label", "human_label"]
    lower = {c.lower(): c for c in columns}
    for name in candidates:
        if name in lower:
            return lower[name]
    return None


def load_predictions_with_gt(conn: sqlite3.Connection, pred_table: str, only_labeled: bool = False) -> Tuple[List[Dict[str, Any]], Optional[str], int, int]:
    pred_cols = [c for c, _ in table_columns(conn, pred_table)]
    colmap = {c.lower(): c for c in pred_cols}

    base_fields = []
    for want in ["label", "confidence", "feedback", "phish_probability", "base_prob", "rule_score", "fused", "timestamp", "date", "id", "gmail_id"]:
        if want in colmap:
            base_fields.append(colmap[want])
    if not base_fields:
        raise RuntimeError(f"No usable columns found in {pred_table}")

    # Join to human_labels if present
    tables = list_tables(conn)
    has_human = "human_labels" in tables
    gt_col = None
    labeled_total = 0

    if has_human:
        gt_col = "gt_label"
        sel_fields = [f"ea.{f}" for f in base_fields] + ["hl.gt_label AS gt_label"]
        sql = f"SELECT {', '.join(sel_fields)} FROM {pred_table} ea LEFT JOIN human_labels hl ON ea.id = hl.id"
        if only_labeled:
            sql += " WHERE hl.gt_label IS NOT NULL"
        rows = conn.execute(sql).fetchall()
        labeled_total = conn.execute("SELECT COUNT(*) FROM human_labels WHERE gt_label IS NOT NULL").fetchone()[0]
    else:
        sel_fields = base_fields
        sql = f"SELECT {', '.join(sel_fields)} FROM {pred_table}"
        rows = conn.execute(sql).fetchall()

    records: List[Dict[str, Any]] = []
    for row in rows:
        rec: Dict[str, Any] = {}
        for key, value in zip([f.split(".")[-1] for f in sel_fields], row):
            rec[key] = value
        records.append(rec)

    total_rows = conn.execute(f"SELECT COUNT(*) FROM {pred_table}").fetchone()[0]
    return records, gt_col, labeled_total, total_rows


def to_bool_label(value: Any) -> Optional[int]:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in {"phishing", "spam", "1", "true", "yes", "bad"}:
        return 1
    if s in {"normal", "ham", "0", "false", "no", "good"}:
        return 0
    return None


def metrics(gt: List[int], scores: List[float], threshold: float) -> Dict[str, float]:
    tp = fp = fn = tn = 0
    for g, s in zip(gt, scores):
        pred = 1 if s >= threshold else 0
        if g == 1 and pred == 1:
            tp += 1
        elif g == 0 and pred == 1:
            fp += 1
        elif g == 1 and pred == 0:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def pick_score(rec: Dict[str, Any], weight: float) -> float:
    base_prob = rec.get("phish_probability") or rec.get("base_prob") or rec.get("base_phish_probability")
    rule_score = rec.get("rule_score")
    fused = rec.get("fused")
    if base_prob is not None and rule_score is not None:
        try:
            return clamp_confidence(fuse_scores(float(base_prob), float(rule_score), model_weight=weight))
        except Exception:
            pass
    if fused is not None:
        return clamp_confidence(float(fused))
    if rec.get("confidence") is not None:
        return clamp_confidence(float(rec["confidence"]))
    return 0.0


def main():
    parser = argparse.ArgumentParser(description="Evaluate phishing predictions directly from SQLite DB.")
    parser.add_argument("--db", required=True, help="Path to SQLite DB (e.g., data/phishguard.db)")
    parser.add_argument("--threshold", type=float, default=0.25, help="Decision threshold for phishing")
    parser.add_argument("--sweep", action="store_true", help="Run threshold/model_weight sweeps")
    parser.add_argument("--thresholds", nargs="*", type=float, default=None, help="Custom thresholds for sweep")
    parser.add_argument("--weights", nargs="*", type=float, default=[0.6, 0.65, 0.7, 0.75, 0.8], help="Model weights for sweep when base_prob+rule_score available")
    parser.add_argument("--only_labeled", action="store_true", help="Evaluate only rows with human_labels.gt_label present")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        raise SystemExit(f"DB not found: {db_path}")

    conn = sqlite3.connect(db_path)
    tables = list_tables(conn)
    print(f"Found tables: {tables}")
    for t in tables:
        cols = table_columns(conn, t)
        print(f" - {t}: {[c for c, _ in cols]}")

    pred_table = detect_pred_table(conn, tables)
    if not pred_table:
        raise SystemExit("Could not find a table with label/confidence.")
    print(f"\nUsing predictions from table: {pred_table}")

    records, gt_col, labeled_total, total_rows = load_predictions_with_gt(conn, pred_table, only_labeled=args.only_labeled)
    print(f"Loaded {len(records)} rows (total in table {pred_table}: {total_rows})")
    if gt_col:
        print(f"Human labels detected via human_labels.gt_label. Labeled rows: {labeled_total}. Evaluating on: {len(records)} rows.")
    else:
        print("No ground-truth column detected (human_labels missing). Accuracy metrics will be skipped.")

    if len(records) == 0:
        print("\nNo labeled rows to evaluate.")
        print("Fill gt_label in label_candidates.csv with 'phishing' or 'normal', then re-import.")
        return

    # Prepare scores and labels
    gt_labels: List[int] = []
    scores: List[float] = []

    for rec in records:
        if not gt_col:
            continue
        gt_val = to_bool_label(rec.get(gt_col))
        if gt_val is None:
            continue
    score = pick_score(rec, weight=args.weights[0] if args.weights else 0.7)
    gt_labels.append(gt_val)
    scores.append(score)

    has_gt = len(gt_labels) > 0 and len(gt_labels) == len(scores)

    # Single-threshold report
    if has_gt:
        m = metrics(gt_labels, scores, args.threshold)
        print(f"\nThreshold {args.threshold:.2f} -> P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")
    else:
        print("\nGround-truth labels not available; skipping precision/recall/F1.")

    if args.sweep:
        thresholds = args.thresholds or [round(0.10 + i * 0.05, 2) for i in range(17)]
        can_weight = any(rec.get("rule_score") is not None for rec in records) and any(
            rec.get("phish_probability") or rec.get("base_prob") or rec.get("base_phish_probability") for rec in records
        )
        if has_gt:
            print("\nThreshold sweep (fixed weight {:.2f}):".format(args.weights[0]))
            sweep_scores = scores
            for t in thresholds:
                m = metrics(gt_labels, sweep_scores, t)
                print(f" t={t:.2f}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")
        else:
            print("\nGround-truth labels not available; skipping threshold sweep metrics.")

        if can_weight and has_gt:
            print("\nModel weight sweep (threshold {:.2f}):".format(args.threshold))
            for w in args.weights:
                w_scores = [pick_score(rec, weight=w) for rec in records]
                m = metrics(gt_labels, w_scores, args.threshold)
                print(f" w={w:.2f}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")
        else:
            print("\nModel weight sweep not possible (missing base_prob/rule_score or ground-truth).")


if __name__ == "__main__":
    main()
