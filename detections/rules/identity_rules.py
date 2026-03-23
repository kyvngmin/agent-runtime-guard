from __future__ import annotations

from typing import List
from uuid import uuid4

from schemas.event import DetectionFinding, SecurityEvent


class IdentityRules:
    NEW_DEVICE_LOGIN = "new_device_login"
    PRIV_ESC_AFTER_LOGIN = "privilege_escalation_after_login"

    def run(self, chain: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: list[DetectionFinding] = []
        if not chain:
            return findings
        findings.extend(self._detect_new_device_login(chain))
        findings.extend(self._detect_privilege_escalation_after_login(chain))
        return findings

    def _detect_new_device_login(self, chain: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: list[DetectionFinding] = []
        first = chain[0]
        if first.event_type == "login" and "new_device" in first.tags and first.outcome.value == "success":
            findings.append(DetectionFinding(
                finding_id=str(uuid4()),
                finding_type="identity",
                rule_name=self.NEW_DEVICE_LOGIN,
                severity=55,
                confidence=0.70,
                title="New device login detected",
                summary=f"User {first.actor_id} logged in from a previously unseen device.",
                tags=["identity", "new_device", "login"],
                related_event_ids=[first.event_id],
                evidence={"device_id": first.device_id, "src_ip": first.src_ip, "geo": first.geo},
            ))
        return findings

    def _detect_privilege_escalation_after_login(self, chain: List[SecurityEvent]) -> List[DetectionFinding]:
        findings: list[DetectionFinding] = []
        login_event = next((e for e in chain if e.event_type == "login" and e.outcome.value == "success"), None)
        privilege_event = next(
            (e for e in chain if e.event_type in {"role_change", "token_scope_upgrade", "admin_grant"}), None
        )
        if login_event and privilege_event:
            findings.append(DetectionFinding(
                finding_id=str(uuid4()),
                finding_type="identity",
                rule_name=self.PRIV_ESC_AFTER_LOGIN,
                severity=80,
                confidence=0.88,
                title="Privilege escalation shortly after login",
                summary=f"User {login_event.actor_id} performed {privilege_event.event_type} shortly after login.",
                tags=["identity", "privilege_escalation", "sequence"],
                related_event_ids=[login_event.event_id, privilege_event.event_id],
                evidence={"login_ts": login_event.ts.isoformat(), "privilege_event_ts": privilege_event.ts.isoformat()},
            ))
        return findings
