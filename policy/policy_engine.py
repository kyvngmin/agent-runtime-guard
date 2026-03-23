from __future__ import annotations

from policy.tool_policy import ToolPolicyEngine
from schemas.event import PolicyDecision, RiskResult, SecurityEvent


class PolicyEngine:
    def __init__(self) -> None:
        self.tool_policy = ToolPolicyEngine()

    def decide(self, risk_result: RiskResult, chain: list[SecurityEvent]) -> PolicyDecision:
        actor_id = chain[0].actor_id if chain else None
        asset_id = chain[0].asset_id if chain else None
        tool_event = next((e for e in chain if e.tool_name), None)

        tool_decision = None
        if tool_event is not None:
            tool_decision = self.tool_policy.evaluate(tool_event, risk_result.risk_score)

        if tool_decision:
            if tool_decision["decision"] == "deny":
                return PolicyDecision(
                    action="deny_tool_execution", should_execute=True,
                    reason=tool_decision["reason"], cooldown_seconds=1800,
                    parameters={"actor_id": actor_id, "asset_id": asset_id, "tool_name": tool_event.tool_name},
                )
            if tool_decision["decision"] == "approval":
                return PolicyDecision(
                    action="require_human_approval", should_execute=True,
                    reason=tool_decision["reason"], cooldown_seconds=900,
                    parameters={"actor_id": actor_id, "asset_id": asset_id, "tool_name": tool_event.tool_name},
                )

        if risk_result.risk_score >= 90:
            return PolicyDecision(
                action="isolate_host_and_disable_account", should_execute=True,
                reason="Critical risk score reached", cooldown_seconds=3600,
                parameters={"actor_id": actor_id, "asset_id": asset_id},
            )
        if risk_result.risk_score >= 75:
            return PolicyDecision(
                action="terminate_session_and_block_external_share", should_execute=True,
                reason="High-confidence malicious sequence detected", cooldown_seconds=1800,
                parameters={"actor_id": actor_id, "asset_id": asset_id},
            )
        if risk_result.risk_score >= 60:
            return PolicyDecision(
                action="step_up_mfa", should_execute=True,
                reason="Elevated risk requires user verification", cooldown_seconds=900,
                parameters={"actor_id": actor_id},
            )

        return PolicyDecision(
            action="allow", should_execute=False,
            reason="Risk below automated response threshold", cooldown_seconds=0,
            parameters={"actor_id": actor_id},
        )
