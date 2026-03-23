from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any


class SQLiteFeedbackStore:
    def __init__(self, db_path: str = "data/arg_feedback.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_column(self, conn: sqlite3.Connection, column_name: str, column_type: str) -> None:
        cols = conn.execute("PRAGMA table_info(analyst_feedback)").fetchall()
        existing = {row[1] for row in cols}
        if column_name not in existing:
            conn.execute(f"ALTER TABLE analyst_feedback ADD COLUMN {column_name} {column_type}")

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    result_session_id TEXT,
                    actor_id TEXT,
                    verdict TEXT NOT NULL,
                    notes TEXT,
                    source TEXT DEFAULT 'console'
                )
            """)
            self._ensure_column(conn, "rule_name", "TEXT")
            self._ensure_column(conn, "finding_id", "TEXT")
            conn.commit()

    def add(self, *, result_session_id: str | None, actor_id: str | None, verdict: str, notes: str,
            source: str = "console", rule_name: str | None = None, finding_id: str | None = None) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO analyst_feedback (result_session_id, actor_id, rule_name, finding_id, verdict, notes, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (result_session_id, actor_id, rule_name, finding_id, verdict, notes, source))
            conn.commit()
            feedback_id = cur.lastrowid
        return {"id": feedback_id, "result_session_id": result_session_id, "actor_id": actor_id,
                "rule_name": rule_name, "finding_id": finding_id, "verdict": verdict, "notes": notes, "source": source}

    def list(self, limit: int = 100, verdict: str | None = None,
             created_from: str | None = None, created_to: str | None = None,
             actor_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT id, created_at, result_session_id, actor_id, rule_name, finding_id, verdict, notes, source FROM analyst_feedback WHERE 1=1"
        params: list[Any] = []
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        if actor_id:
            query += " AND actor_id = ?"
            params.append(actor_id)
        if created_from:
            query += " AND created_at >= ?"
            params.append(created_from)
        if created_to:
            query += " AND created_at <= ?"
            params.append(created_to)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT verdict, COUNT(*) AS cnt FROM analyst_feedback GROUP BY verdict").fetchall()
        s = {"true_positive": 0, "false_positive": 0, "benign_but_weird": 0, "total": 0}
        for row in rows:
            s[row["verdict"]] = int(row["cnt"])
            s["total"] += int(row["cnt"])
        return s

    def rule_summary(self, limit: int = 50, created_from: str | None = None, created_to: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT COALESCE(rule_name, '__unknown__') AS rule_name,
                   SUM(CASE WHEN verdict='true_positive' THEN 1 ELSE 0 END) AS tp,
                   SUM(CASE WHEN verdict='false_positive' THEN 1 ELSE 0 END) AS fp,
                   SUM(CASE WHEN verdict='benign_but_weird' THEN 1 ELSE 0 END) AS bw,
                   COUNT(*) AS total
            FROM analyst_feedback WHERE 1=1
        """
        params: list[Any] = []
        if created_from:
            query += " AND created_at >= ?"
            params.append(created_from)
        if created_to:
            query += " AND created_at <= ?"
            params.append(created_to)
        query += " GROUP BY COALESCE(rule_name, '__unknown__') ORDER BY fp DESC, total DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            tp, fp, bw, total = int(row["tp"] or 0), int(row["fp"] or 0), int(row["bw"] or 0), int(row["total"] or 0)
            items.append({"rule_name": row["rule_name"], "tp": tp, "fp": fp, "bw": bw, "total": total,
                          "fp_ratio": round(fp / max(1, total), 3), "tp_ratio": round(tp / max(1, total), 3)})
        return items

    def recent_rule_feedback_cases(self, rule_name: str, verdict: str | None = None, limit: int = 20,
                                    created_from: str | None = None, created_to: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT id, created_at, result_session_id, actor_id, rule_name, finding_id, verdict, notes, source FROM analyst_feedback WHERE rule_name = ?"
        params: list[Any] = [rule_name]
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        if created_from:
            query += " AND created_at >= ?"
            params.append(created_from)
        if created_to:
            query += " AND created_at <= ?"
            params.append(created_to)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
