from __future__ import annotations

from typing import List
from uuid import uuid4

from schemas.event import DetectionFinding, SecurityEvent


SUSPICIOUS_PATTERNS = [
    "ignore previous instructions",
    "reveal your system prompt",
    "print hidden instructions",
    "bypass guardrails",
    "exfiltrate",
]


class PromptInjectionDetector:
    RULE_NAME = "prompt_injection_attempt"

    def run(self, chain: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for event in chain:
            if event.source.value != "llm_gateway":
                continue
            prompt_text = str(event.raw.get("prompt_text", "")).lower()
            matches = [p for p in SUSPICIOUS_PATTERNS if p in prompt_text]
            if matches:
                findings.append(DetectionFinding(
                    finding_id=str(uuid4()),
                    finding_type="llm_security",
                    rule_name=self.RULE_NAME,
                    severity=72,
                    confidence=0.82,
                    title="Prompt injection pattern detected",
                    summary=f"Potential prompt injection attempt against model {event.model_name}.",
                    tags=["llm", "prompt_injection"] + matches,
                    related_event_ids=[event.event_id],
                    evidence={"matched_patterns": matches, "tool_name": event.tool_name, "asset_id": event.asset_id},
                ))
        return findings
