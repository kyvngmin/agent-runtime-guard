from __future__ import annotations

from dataclasses import dataclass

from schemas.event import SecurityEvent


@dataclass(frozen=True)
class ToolPolicyRule:
    tool_name: str
    mode: str  # allow | deny | approval
    reason: str


DEFAULT_TOOL_RULES = {
    "web_fetch": ToolPolicyRule("web_fetch", "allow", "Read-only external fetch allowed"),
    "slack_post": ToolPolicyRule("slack_post", "approval", "External collaboration action requires approval"),
    "gmail_send": ToolPolicyRule("gmail_send", "approval", "Outbound email requires approval"),
    "http_post": ToolPolicyRule("http_post", "deny", "Direct arbitrary outbound POST is blocked"),
    "shell_exec": ToolPolicyRule("shell_exec", "deny", "Shell execution is blocked by default"),
}


class ToolPolicyEngine:
    def evaluate(self, event: SecurityEvent, session_risk: int) -> dict:
        tool_name = event.tool_name or ""
        rule = DEFAULT_TOOL_RULES.get(tool_name)

        if rule is None:
            if session_risk >= 70:
                return {"decision": "deny", "reason": "Unknown tool blocked in elevated-risk session"}
            return {"decision": "approval", "reason": "Unknown tool requires approval"}

        if session_risk >= 80 and rule.mode == "allow":
            return {"decision": "approval", "reason": "Previously allowed tool escalated to approval due to session risk"}

        return {"decision": rule.mode, "reason": rule.reason}
