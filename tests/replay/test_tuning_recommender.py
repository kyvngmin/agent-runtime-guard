from __future__ import annotations

from feedback.tuning_recommender import RuleTuningRecommender


def test_recommender_flags_noisy_rule() -> None:
    recs = RuleTuningRecommender().recommend([
        {"rule_name": "prompt_injection_attempt", "tp": 1, "fp": 4, "bw": 0, "total": 5, "fp_ratio": 0.8, "tp_ratio": 0.2},
    ])
    assert len(recs) == 1
    assert recs[0]["status"] == "too_noisy"
    assert recs[0]["pattern_action"] == "narrow_pattern"


def test_recommender_flags_stable_rule() -> None:
    recs = RuleTuningRecommender().recommend([
        {"rule_name": "tool_abuse_sequence", "tp": 5, "fp": 1, "bw": 0, "total": 6, "fp_ratio": 0.167, "tp_ratio": 0.833},
    ])
    assert len(recs) == 1
    assert recs[0]["status"] == "stable"
    assert recs[0]["pattern_action"] == "consider_expand_pattern"


def test_recommender_insufficient_data() -> None:
    recs = RuleTuningRecommender().recommend([
        {"rule_name": "new_rule", "tp": 1, "fp": 0, "bw": 0, "total": 1, "fp_ratio": 0.0, "tp_ratio": 1.0},
    ])
    assert recs[0]["status"] == "insufficient_data"
