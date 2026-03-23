from __future__ import annotations

from typing import Dict

from schemas.event import PolicyDecision


class ResponseOrchestrator:
    def execute(self, decision: PolicyDecision) -> Dict[str, object]:
        if decision.action == "allow":
            return {"status": "allowed", "action": decision.action, "reason": decision.reason, "parameters": decision.parameters}

        if not decision.should_execute:
            return {"status": "skipped", "action": decision.action, "reason": decision.reason, "parameters": decision.parameters}

        effect_map = {
            "deny_tool_execution": "tool_blocked",
            "require_human_approval": "approval_required",
            "terminate_session_and_block_external_share": "session_terminated_and_share_blocked",
            "isolate_host_and_disable_account": "host_isolated_and_account_disabled",
            "step_up_mfa": "mfa_challenge_triggered",
        }
        effect = effect_map.get(decision.action, "generic_execution")

        return {"status": "executed", "action": decision.action, "effect": effect, "reason": decision.reason, "parameters": decision.parameters}
