from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# SQLite persistence for analysis history
HISTORY_DB = Path("data/phishguard.db")
HISTORY_DB.parent.mkdir(parents=True, exist_ok=True)


def init_db(db_path: Path = HISTORY_DB) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_analysis (
                id TEXT PRIMARY KEY,
                subject TEXT,
                label TEXT,
                confidence REAL,
                feedback TEXT,
                latency_ms REAL,
                timestamp TEXT,
                date TEXT,
                gmail_id TEXT,
                gmail_labels TEXT,
                auth_results TEXT,
                body TEXT
            )
            """
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_email_analysis_gmail_id ON email_analysis (gmail_id)"
        )
        conn.commit()


def get_existing_gmail_ids(gmail_ids: list[str], db_path: Path = HISTORY_DB) -> set[str]:
    if not gmail_ids:
        return set()
    placeholders = ",".join(["?"] * len(gmail_ids))
    query = f"SELECT gmail_id FROM email_analysis WHERE gmail_id IN ({placeholders})"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(query, gmail_ids).fetchall()
    return {row[0] for row in rows if row and row[0]}


def load_history_by_gmail_ids(gmail_ids: list[str], db_path: Path = HISTORY_DB) -> List[Dict[str, Any]]:
    if not gmail_ids:
        return []
    placeholders = ",".join(["?"] * len(gmail_ids))
    query = f"""
        SELECT id, subject, label, confidence, feedback, latency_ms, timestamp, date,
               gmail_id, gmail_labels, auth_results, body
          FROM email_analysis
         WHERE gmail_id IN ({placeholders})
    """
    results: List[Dict[str, Any]] = []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute(query, gmail_ids):
            gmail_labels = row["gmail_labels"]
            auth_results = row["auth_results"]
            results.append(
                {
                    "id": row["id"],
                    "subject": row["subject"],
                    "label": row["label"],
                    "confidence": row["confidence"],
                    "feedback": row["feedback"],
                    "latency_ms": row["latency_ms"],
                    "timestamp": row["timestamp"],
                    "date": row["date"],
                    "gmail_id": row["gmail_id"],
                    "gmail_labels": json.loads(gmail_labels) if gmail_labels else [],
                    "auth_results": json.loads(auth_results) if auth_results else {},
                    "body": row["body"],
                    "from_cache": True,
                }
            )
    return results


def save_analysis_result(result: Dict[str, Any], db_path: Path = HISTORY_DB) -> None:
    """Persist a single analysis result; errors are expected to be caught by caller."""
    gmail_labels = result.get("gmail_labels")
    auth_results = result.get("auth_results")
    row = {
        "id": result.get("id"),
        "subject": result.get("subject"),
        "label": result.get("label"),
        "confidence": result.get("confidence"),
        "feedback": result.get("feedback") or result.get("gpt_feedback"),
        "latency_ms": result.get("latency_ms"),
        "timestamp": result.get("timestamp"),
        "date": result.get("date"),
        "gmail_id": result.get("gmail_id") or result.get("id"),
        "gmail_labels": json.dumps(gmail_labels) if gmail_labels is not None else None,
        "auth_results": json.dumps(auth_results) if auth_results is not None else None,
        "body": result.get("body"),
    }
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO email_analysis
            (id, subject, label, confidence, feedback, latency_ms, timestamp, date, gmail_id, gmail_labels, auth_results, body)
            VALUES (:id, :subject, :label, :confidence, :feedback, :latency_ms, :timestamp, :date, :gmail_id, :gmail_labels, :auth_results, :body)
            ON CONFLICT(gmail_id) DO UPDATE SET
                subject=excluded.subject,
                label=excluded.label,
                confidence=excluded.confidence,
                feedback=excluded.feedback,
                latency_ms=excluded.latency_ms,
                timestamp=excluded.timestamp,
                date=excluded.date,
                gmail_labels=excluded.gmail_labels,
                auth_results=excluded.auth_results,
                body=excluded.body
            """,
            row,
        )
        conn.commit()


def load_history(limit: int = 200, days: Optional[int] = None, db_path: Path = HISTORY_DB) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 1), 1000))
    params: Dict[str, Any] = {"limit": limit}
    where_clause = ""
    if days is not None:
        try:
            days_int = int(days)
            cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days_int)).isoformat()
            where_clause = "WHERE date >= :cutoff"
            params["cutoff"] = cutoff
        except (TypeError, ValueError):
            where_clause = ""

    query = f"""
        SELECT id, subject, label, confidence, feedback, latency_ms, timestamp, date,
               gmail_id, gmail_labels, auth_results, body
          FROM email_analysis
          {where_clause}
         ORDER BY timestamp DESC
         LIMIT :limit
    """
    results: List[Dict[str, Any]] = []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute(query, params):
            gmail_labels = row["gmail_labels"]
            auth_results = row["auth_results"]
            results.append(
                {
                    "id": row["id"],
                    "subject": row["subject"],
                    "label": row["label"],
                    "confidence": row["confidence"],
                    "feedback": row["feedback"],
                    "latency_ms": row["latency_ms"],
                    "timestamp": row["timestamp"],
                    "date": row["date"],
                    "gmail_id": row["gmail_id"],
                    "gmail_labels": json.loads(gmail_labels) if gmail_labels else [],
                    "auth_results": json.loads(auth_results) if auth_results else {},
                    "body": row["body"],
                }
            )
    return results
