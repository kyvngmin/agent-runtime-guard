from __future__ import annotations

from pathlib import Path

from storage.sqlite_store import SQLiteResultStore


def test_sqlite_result_store_roundtrip(tmp_path: Path) -> None:
    store = SQLiteResultStore(str(tmp_path / "arg_results.db"))
    store.add({"actor_id": "alice", "session_id": "sess-1", "chain_summary": ["prompt_submit", "tool_egress"],
               "risk_score": 88, "decision": "deny_tool_execution", "execution_status": "executed",
               "full_result": {"risk": {"risk_score": 88}}})
    items = store.list(limit=10)
    assert len(items) == 1
    assert items[0]["actor_id"] == "alice"
    assert items[0]["risk_score"] == 88
    store.clear()
    assert store.list(limit=10) == []


def test_sqlite_result_store_filters(tmp_path: Path) -> None:
    store = SQLiteResultStore(str(tmp_path / "arg_results.db"))
    store.add({"actor_id": "alice", "session_id": "s1", "chain_summary": ["x"], "risk_score": 88,
               "decision": "deny_tool_execution", "execution_status": "executed", "full_result": {}})
    store.add({"actor_id": "bob", "session_id": "s2", "chain_summary": ["x"], "risk_score": 25,
               "decision": "allow", "execution_status": "allowed", "full_result": {}})
    deny_items = store.list(limit=10, decision="deny_tool_execution")
    assert len(deny_items) == 1 and deny_items[0]["actor_id"] == "alice"
    high_risk = store.list(limit=10, min_risk=70)
    assert len(high_risk) == 1


def test_recent_cases_by_rule(tmp_path: Path) -> None:
    store = SQLiteResultStore(str(tmp_path / "arg_results.db"))
    store.add({"actor_id": "alice", "session_id": "s1", "chain_summary": ["x"], "risk_score": 88,
               "decision": "deny", "execution_status": "executed",
               "full_result": {"findings": [{"rule_name": "prompt_injection_attempt", "finding_id": "f1"}]}})
    store.add({"actor_id": "bob", "session_id": "s2", "chain_summary": ["x"], "risk_score": 25,
               "decision": "allow", "execution_status": "allowed",
               "full_result": {"findings": [{"rule_name": "other_rule", "finding_id": "f2"}]}})
    items = store.recent_cases_by_rule("prompt_injection_attempt", limit=10)
    assert len(items) == 1 and items[0]["actor_id"] == "alice"
