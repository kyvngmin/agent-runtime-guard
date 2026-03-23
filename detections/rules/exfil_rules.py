from __future__ import annotations

from typing import List
from uuid import uuid4

from schemas.event import DetectionFinding, SecurityEvent


class ExfilRules:
    RULE_NAME = "sensitive_read_followed_by_egress"
    SENSITIVE_TAGS = {"sensitive_asset", "secret_material", "internal_only"}
    EGRESS_EVENTS = {"external_post", "external_share", "download", "copy_to_clipboard", "tool_egress"}

    def run(self, chain: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: list[DetectionFinding] = []
        sensitive_event = next(
            (e for e in chain
             if (e.asset_criticality and e.asset_criticality >= 4)
             or any(tag in self.SENSITIVE_TAGS for tag in e.tags)),
            None,
        )
        egress_event = next((e for e in chain if e.event_type in self.EGRESS_EVENTS), None)

        if sensitive_event and egress_event:
            findings.append(DetectionFinding(
                finding_id=str(uuid4()),
                finding_type="exfiltration",
                rule_name=self.RULE_NAME,
                severity=85,
                confidence=0.90,
                title="Sensitive read followed by egress attempt",
                summary="Sensitive asset access was followed by an external egress attempt in the same session.",
                tags=["exfiltration", "sequence", "sensitive_asset"],
                related_event_ids=[sensitive_event.event_id, egress_event.event_id],
                evidence={
                    "sensitive_event_type": sensitive_event.event_type,
                    "egress_event_type": egress_event.event_type,
                    "asset_id": sensitive_event.asset_id,
                    "tool_name": egress_event.tool_name,
                },
            ))
        return findings
