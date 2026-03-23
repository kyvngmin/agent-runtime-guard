from __future__ import annotations

from typing import Iterable

from schemas.event import DetectionFinding, RiskResult, SecurityEvent


class RiskEngine:
    def score(self, chain: list[SecurityEvent], findings: Iterable[DetectionFinding]) -> RiskResult:
        finding_list = list(findings)
        if not chain:
            return RiskResult(
                risk_score=0, confidence=0.0, reasons=["empty_chain"],
                recommended_action="monitor", findings=[],
            )

        asset_criticality = max((e.asset_criticality or 1 for e in chain), default=1)
        action_severity = min(max((f.severity for f in finding_list), default=10), 100)
        sequence_confidence = max((f.confidence for f in finding_list), default=0.20)
        novelty = 70 if any("new_device" in e.tags for e in chain) else 30

        if len(chain) >= 4:
            speed = 75
        elif len(chain) >= 2:
            speed = 50
        else:
            speed = 20

        raw_score = (
            asset_criticality * 20 * 0.25
            + action_severity * 0.25
            + (sequence_confidence * 100) * 0.20
            + novelty * 0.15
            + speed * 0.15
        )
        risk_score = max(0, min(100, round(raw_score)))

        if risk_score >= 90:
            action = "isolate"
        elif risk_score >= 75:
            action = "block"
        elif risk_score >= 60:
            action = "step_up"
        else:
            action = "monitor"

        reasons = [f.title for f in finding_list] or ["weak_signal"]
        confidence = min(1.0, max(sequence_confidence, 0.25))

        return RiskResult(
            risk_score=risk_score, confidence=confidence, reasons=reasons,
            recommended_action=action, findings=finding_list,
        )
