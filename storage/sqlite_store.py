from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any


class SQLiteResultStore:
    def __init__(self, db_path: str = "data/arg_results.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS replay_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    actor_id TEXT,
                    session_id TEXT,
                    chain_summary TEXT,
                    risk_score INTEGER,
                    decision TEXT,
                    execution_status TEXT,
                    full_result_json TEXT NOT NULL
                )
            """)
            conn.commit()

    def add(self, item: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("""
                INSERT INTO replay_results (actor_id, session_id, chain_summary, risk_score, decision, execution_status, full_result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                item.get("actor_id"),
                item.get("session_id"),
                json.dumps(item.get("chain_summary", []), ensure_ascii=False),
                item.get("risk_score"),
                item.get("decision"),
                item.get("execution_status"),
                json.dumps(item.get("full_result", {}), ensure_ascii=False),
            ))
            conn.commit()

    def list(
        self,
        limit: int = 100,
        actor_id: str | None = None,
        decision: str | None = None,
        min_risk: int | None = None,
        created_from: str | None = None,
        created_to: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            SELECT created_at, actor_id, session_id, chain_summary,
                   risk_score, decision, execution_status, full_result_json
            FROM replay_results WHERE 1=1
        """
        params: list[Any] = []
        if actor_id:
            query += " AND actor_id = ?"
            params.append(actor_id)
        if decision:
            query += " AND decision = ?"
            params.append(decision)
        if min_risk is not None:
            query += " AND risk_score >= ?"
            params.append(min_risk)
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

        return [
            {
                "created_at": row["created_at"],
                "actor_id": row["actor_id"],
                "session_id": row["session_id"],
                "chain_summary": json.loads(row["chain_summary"] or "[]"),
                "risk_score": row["risk_score"],
                "decision": row["decision"],
                "execution_status": row["execution_status"],
                "full_result": json.loads(row["full_result_json"] or "{}"),
            }
            for row in rows
        ]

    def decision_summary(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("""
                SELECT decision, COUNT(*) AS cnt, AVG(risk_score) AS avg_risk
                FROM replay_results GROUP BY decision ORDER BY cnt DESC
            """).fetchall()
        return [{"decision": row["decision"], "count": int(row["cnt"]), "avg_risk": round(float(row["avg_risk"] or 0), 2)} for row in rows]

    def recent_cases_by_rule(self, rule_name: str, limit: int = 20, created_from: str | None = None, created_to: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT created_at, actor_id, session_id, chain_summary, risk_score, decision, execution_status, full_result_json FROM replay_results WHERE 1=1"
        params: list[Any] = []
        if created_from:
            query += " AND created_at >= ?"
            params.append(created_from)
        if created_to:
            query += " AND created_at <= ?"
            params.append(created_to)
        query += " ORDER BY id DESC LIMIT 500"

        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        items: list[dict[str, Any]] = []
        for row in rows:
            full_result = json.loads(row["full_result_json"] or "{}")
            findings = full_result.get("findings", [])
            if not any(f.get("rule_name") == rule_name for f in findings):
                continue
            items.append({
                "created_at": row["created_at"], "actor_id": row["actor_id"],
                "session_id": row["session_id"],
                "chain_summary": json.loads(row["chain_summary"] or "[]"),
                "risk_score": row["risk_score"], "decision": row["decision"],
                "execution_status": row["execution_status"], "full_result": full_result,
            })
            if len(items) >= limit:
                break
        return items

    def clear(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM replay_results")
            conn.commit()
