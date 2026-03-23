from __future__ import annotations

from typing import List
from uuid import uuid4

from schemas.event import DetectionFinding, SecurityEvent


class ToolAbuseSequenceRules:
    RULE_NAME = "tool_abuse_sequence"
    SENSITIVE_EVENT_TYPES = {"retrieval_read", "secret_read", "credential_read"}
    EGRESS_EVENT_TYPES = {"tool_egress", "external_post", "external_share", "download"}
    HIGH_RISK_TOOLS = {"http_post", "shell_exec", "mystery_sync"}

    def run(self, chain: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: list[DetectionFinding] = []
        if not chain:
            return findings

        sensitive_read = next(
            (e for e in chain
             if e.event_type in self.SENSITIVE_EVENT_TYPES
             and ((e.asset_criticality or 0) >= 4 or "sensitive_asset" in e.tags)),
            None,
        )
        tool_event = next((e for e in chain if e.tool_name), None)
        egress_event = next(
            (e for e in chain
             if e.event_type in self.EGRESS_EVENT_TYPES or e.tool_name in self.HIGH_RISK_TOOLS),
            None,
        )

        if not (sensitive_read and tool_event and egress_event):
            return findings

        severity = 82
        confidence = 0.87
        if tool_event.tool_name in self.HIGH_RISK_TOOLS:
            severity = 90
            confidence = 0.92

        findings.append(DetectionFinding(
            finding_id=str(uuid4()),
            finding_type="sequence",
            rule_name=self.RULE_NAME,
            severity=severity,
            confidence=confidence,
            title="Sensitive retrieval followed by risky tool/egress sequence",
            summary="A session accessed sensitive material and then attempted a risky tool call or external egress.",
            tags=["sequence", "tool_abuse", "egress", "sensitive_asset"],
            related_event_ids=[sensitive_read.event_id, tool_event.event_id, egress_event.event_id],
            evidence={
                "sensitive_event_type": sensitive_read.event_type,
                "tool_name": tool_event.tool_name,
                "egress_event_type": egress_event.event_type,
                "asset_id": sensitive_read.asset_id,
            },
        ))
        return findings
