from __future__ import annotations

import argparse
import csv
import datetime as dt
import sqlite3
from pathlib import Path
from typing import List


def ensure_table(conn: sqlite3.Connection, table: str = "human_labels") -> None:
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id TEXT PRIMARY KEY,
            gt_label TEXT NOT NULL CHECK(gt_label IN ('phishing','normal')),
            noted_at TEXT
        )
        """
    )
    conn.commit()


def export_candidates(
    conn: sqlite3.Connection, out_csv: Path, limit: int = 50, src_table: str = "email_analysis"
) -> List[str]:
    cols = [row[1] for row in conn.execute(f"PRAGMA table_info({src_table})")]
    if "id" not in cols:
        raise SystemExit(f"{src_table} must have an id column to export for labeling.")

    rows = conn.execute(
        f"SELECT id, subject, body, label, confidence, feedback FROM {src_table} LIMIT ?", (limit,)
    ).fetchall()
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "subject", "body", "label", "confidence", "feedback", "gt_label"])
        for r in rows:
            rid, subj, body, lab, conf, fb = r
            body = (body or "")[:500]
            writer.writerow([rid, subj, body, lab, conf, fb, ""])
    return [r[0] for r in rows]


def import_labels(conn: sqlite3.Connection, in_csv: Path, table: str = "human_labels") -> int:
    ensure_table(conn, table)
    inserted = 0

    with in_csv.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        # (A) 헤더 정규화
        raw_headers = reader.fieldnames or []
        headers = [h.strip() for h in raw_headers if h is not None]

        print(f"[import_labels] detected headers={headers}")

        for i, row in enumerate(reader):
            # (B) row 키 정규화
            norm_row = { (k.strip() if k else k): v for k, v in (row or {}).items() if k }

            if i < 3:
                print(f"[import_labels] sample row {i} keys={list(norm_row.keys())}")

            # (C) gt_label은 오직 이 컬럼만 읽기
            gt = (norm_row.get("gt_label") or "").strip().lower()
            if gt not in {"phishing", "normal"}:
                continue

            id_ = (norm_row.get("id") or "").strip()
            if not id_:
                continue

            conn.execute(
                f"INSERT OR REPLACE INTO {table} (id, gt_label, noted_at) VALUES (?, ?, ?)",
                (id_, gt, dt.datetime.utcnow().isoformat()),
            )
            inserted += 1

    conn.commit()
    return inserted



def main():
    parser = argparse.ArgumentParser(description="Export or import human labels for evaluation.")
    parser.add_argument("--db", required=True, help="Path to SQLite DB")
    parser.add_argument("--export", action="store_true", help="Export candidates to CSV")
    parser.add_argument("--import_csv", type=str, help="Import labeled CSV back into DB")
    parser.add_argument("--out", type=str, default="label_candidates.csv", help="Export CSV path")
    parser.add_argument("--limit", type=int, default=50, help="Number of rows to export")
    args = parser.parse_args()

    conn = sqlite3.connect(Path(args.db))

    if args.export:
        exported_ids = export_candidates(conn, Path(args.out), limit=args.limit)
        print(
            f"Exported {len(exported_ids)} rows to {args.out}. "
            "Fill gt_label column (phishing|normal) and re-import with --import_csv."
        )

    if args.import_csv:
        inserted = import_labels(conn, Path(args.import_csv))
        print(f"Imported {inserted} labeled rows into human_labels.")


if __name__ == "__main__":
    main()
