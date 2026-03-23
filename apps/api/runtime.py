from __future__ import annotations

from detections.llm_security.prompt_injection import PromptInjectionDetector
from detections.llm_security.rag_indirect_injection import RagIndirectInjectionDetector
from detections.rules.exfil_rules import ExfilRules
from detections.rules.tool_abuse_sequence import ToolAbuseSequenceRules
from fabric.correlator import Correlator
from fabric.normalizer import EventNormalizer
from policy.policy_engine import PolicyEngine
from response.orchestrator import ResponseOrchestrator
from risk.risk_engine import RiskEngine
from schemas.event import SecurityEvent
from storage.sqlite_store import SQLiteResultStore

normalizer = EventNormalizer()
correlator = Correlator(window_minutes=15)
prompt_detector = PromptInjectionDetector()
rag_detector = RagIndirectInjectionDetector()
exfil_rules = ExfilRules()
sequence_rules = ToolAbuseSequenceRules()
risk_engine = RiskEngine()
policy_engine = PolicyEngine()
response = ResponseOrchestrator()
result_store = SQLiteResultStore(db_path="data/arg_results.db")


def decide_events(events: list[SecurityEvent]) -> dict:
    normalized = normalizer.normalize_batch(events)
    chains = correlator.correlate(normalized)

    results = []
    for chain in chains:
        findings = []
        findings.extend(prompt_detector.run(chain))
        findings.extend(rag_detector.run(chain))
        findings.extend(exfil_rules.run(chain))
        findings.extend(sequence_rules.run(chain))

        risk = risk_engine.score(chain, findings)
        decision = policy_engine.decide(risk, chain)
        execution = response.execute(decision)

        result_payload = {
            "chain": [e.model_dump(mode="json") for e in chain],
            "findings": [f.model_dump(mode="json") for f in findings],
            "risk": risk.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "execution": execution,
        }
        results.append(result_payload)

        result_store.add({
            "chain_summary": [e.event_type for e in chain],
            "actor_id": chain[0].actor_id if chain else None,
            "session_id": chain[0].session_id if chain else None,
            "risk_score": risk.risk_score,
            "decision": decision.action,
            "execution_status": execution.get("status"),
            "full_result": result_payload,
        })

    return {"results": results}
