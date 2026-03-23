from __future__ import annotations

from typing import Any


class RuleTuningRecommender:
    def recommend(self, rule_summary_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        recommendations: list[dict[str, Any]] = []
        for item in rule_summary_items:
            rule_name = item.get("rule_name")
            tp = int(item.get("tp", 0) or 0)
            fp = int(item.get("fp", 0) or 0)
            total = int(item.get("total", 0) or 0)
            fp_ratio = float(item.get("fp_ratio", 0) or 0)
            tp_ratio = float(item.get("tp_ratio", 0) or 0)

            if total < 3:
                recommendations.append({"rule_name": rule_name, "status": "insufficient_data",
                    "severity_adjustment": 0, "confidence_adjustment": 0.0,
                    "pattern_action": "collect_more_feedback", "reason": "Not enough feedback samples yet."})
                continue
            if fp_ratio >= 0.50:
                recommendations.append({"rule_name": rule_name, "status": "too_noisy",
                    "severity_adjustment": +5, "confidence_adjustment": +0.05,
                    "pattern_action": "narrow_pattern", "reason": "False positive ratio is high. Consider stricter gating."})
                continue
            if fp_ratio >= 0.35 and tp_ratio < 0.50:
                recommendations.append({"rule_name": rule_name, "status": "mixed_quality",
                    "severity_adjustment": +3, "confidence_adjustment": +0.03,
                    "pattern_action": "review_examples", "reason": "Mixed performance. Compare recent TP/FP examples."})
                continue
            if tp_ratio >= 0.70 and fp_ratio <= 0.20 and total >= 5:
                recommendations.append({"rule_name": rule_name, "status": "stable",
                    "severity_adjustment": 0, "confidence_adjustment": -0.02,
                    "pattern_action": "consider_expand_pattern", "reason": "Rule appears stable. Consider expanding."})
                continue
            recommendations.append({"rule_name": rule_name, "status": "monitor",
                "severity_adjustment": 0, "confidence_adjustment": 0.0,
                "pattern_action": "monitor", "reason": "No strong recommendation yet."})
        return recommendations
