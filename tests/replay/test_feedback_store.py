from __future__ import annotations

from pathlib import Path

from storage.sqlite_feedback_store import SQLiteFeedbackStore


def test_feedback_store_roundtrip(tmp_path: Path) -> None:
    store = SQLiteFeedbackStore(str(tmp_path / "arg_feedback.db"))
    saved = store.add(result_session_id="sess-100", actor_id="alice",
                      verdict="true_positive", notes="Confirmed", source="test")
    assert saved["verdict"] == "true_positive"
    items = store.list(limit=10)
    assert len(items) == 1 and items[0]["actor_id"] == "alice"


def test_feedback_summary_counts(tmp_path: Path) -> None:
    store = SQLiteFeedbackStore(str(tmp_path / "arg_feedback.db"))
    store.add(result_session_id="s1", actor_id="alice", verdict="true_positive", notes="ok", source="test")
    store.add(result_session_id="s2", actor_id="bob", verdict="false_positive", notes="too aggressive", source="test")
    summary = store.summary()
    assert summary["true_positive"] == 1
    assert summary["false_positive"] == 1
    assert summary["total"] == 2


def test_rule_summary(tmp_path: Path) -> None:
    store = SQLiteFeedbackStore(str(tmp_path / "arg_feedback.db"))
    store.add(result_session_id="s1", actor_id="a", verdict="true_positive", notes="", source="t", rule_name="prompt_injection_attempt")
    store.add(result_session_id="s2", actor_id="b", verdict="false_positive", notes="", source="t", rule_name="prompt_injection_attempt")
    store.add(result_session_id="s3", actor_id="c", verdict="true_positive", notes="", source="t", rule_name="tool_abuse_sequence")
    items = store.rule_summary(limit=10)
    assert len(items) == 2
    pi_rule = next(i for i in items if i["rule_name"] == "prompt_injection_attempt")
    assert pi_rule["tp"] == 1 and pi_rule["fp"] == 1


def test_recent_rule_feedback_cases(tmp_path: Path) -> None:
    store = SQLiteFeedbackStore(str(tmp_path / "arg_feedback.db"))
    store.add(result_session_id="s1", actor_id="a", verdict="true_positive", notes="", source="t", rule_name="r1")
    store.add(result_session_id="s2", actor_id="b", verdict="false_positive", notes="", source="t", rule_name="r1")
    store.add(result_session_id="s3", actor_id="c", verdict="true_positive", notes="", source="t", rule_name="r2")
    tp_items = store.recent_rule_feedback_cases("r1", verdict="true_positive", limit=10)
    assert len(tp_items) == 1 and tp_items[0]["verdict"] == "true_positive"
    fp_items = store.recent_rule_feedback_cases("r1", verdict="false_positive", limit=10)
    assert len(fp_items) == 1
