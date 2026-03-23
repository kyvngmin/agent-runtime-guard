from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import requests

API_BASE = os.getenv("ARG_API_BASE", "http://localhost:8000")

SCENARIOS = [
    ("health", "GET", "/health"),
    ("normal_session_allow", "POST", "/replay/normal-session"),
    ("prompt_to_egress_block", "POST", "/replay/prompt-to-egress"),
    ("rag_indirect_injection", "POST", "/replay/rag-indirect-injection"),
    ("tool_abuse_sequence", "POST", "/replay/tool-abuse-sequence"),
]


@dataclass
class SmokeResult:
    name: str
    ok: bool
    status_code: int = 0
    decision: str | None = None
    risk_score: int = 0
    findings: int = 0
    message: str = ""


def call(method: str, path: str) -> requests.Response:
    url = f"{API_BASE}{path}"
    if method == "GET":
        return requests.get(url, timeout=15)
    return requests.post(url, timeout=15)


def evaluate_result(name: str, response: requests.Response) -> SmokeResult:
    try:
        payload = response.json()
    except Exception:
        return SmokeResult(name=name, ok=False, status_code=response.status_code, message="Non-JSON response")

    if name == "health":
        ok = response.status_code == 200 and payload.get("status") == "ok"
        return SmokeResult(name=name, ok=ok, status_code=response.status_code, message="health ok" if ok else f"unexpected: {payload}")

    results = payload.get("results", [])
    if not results:
        return SmokeResult(name=name, ok=False, status_code=response.status_code, message="No results")

    first = results[0]
    risk = first.get("risk", {})
    decision = first.get("decision", {})
    findings = first.get("findings", [])
    decision_name = decision.get("action")
    risk_score = int(risk.get("risk_score", 0) or 0)

    expected = {
        "normal_session_allow": lambda: decision_name == "allow",
        "prompt_to_egress_block": lambda: decision_name in {"deny_tool_execution", "require_human_approval", "terminate_session_and_block_external_share", "isolate_host_and_disable_account"},
        "rag_indirect_injection": lambda: risk_score >= 60 and len(findings) >= 1,
        "tool_abuse_sequence": lambda: risk_score >= 70 and len(findings) >= 1,
    }
    ok = expected.get(name, lambda: response.status_code == 200)()

    return SmokeResult(name=name, ok=ok, status_code=response.status_code,
                       decision=decision_name, risk_score=risk_score, findings=len(findings),
                       message="pass" if ok else json.dumps(first, ensure_ascii=False)[:300])


def main() -> int:
    results: list[SmokeResult] = []
    for name, method, path in SCENARIOS:
        try:
            response = call(method, path)
            result = evaluate_result(name, response)
        except Exception as exc:
            result = SmokeResult(name=name, ok=False, status_code=0, message=f"request failed: {exc}")
        results.append(result)

    print("\n=== Smoke Runner Results ===")
    failures = 0
    for item in results:
        tag = "PASS" if item.ok else "FAIL"
        print(f"[{tag}] {item.name} | status={item.status_code} | decision={item.decision} | risk={item.risk_score} | findings={item.findings} | {item.message}")
        if not item.ok:
            failures += 1
    print(f"\nTotal: {len(results)} | Failures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
