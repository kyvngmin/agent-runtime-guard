from __future__ import annotations

from fastapi.testclient import TestClient

from apps.api.main import app

client = TestClient(app)


def test_health_endpoint() -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_prompt_to_egress_replay_contract() -> None:
    r = client.post("/replay/prompt-to-egress")
    assert r.status_code == 200
    payload = r.json()
    assert "results" in payload
    first = payload["results"][0]
    assert "risk" in first and "decision" in first and "execution" in first


def test_normal_session_replay_contract() -> None:
    r = client.post("/replay/normal-session")
    assert r.status_code == 200
    first = r.json()["results"][0]
    assert first["decision"]["action"] == "allow"


def test_rag_indirect_injection_replay_contract() -> None:
    r = client.post("/replay/rag-indirect-injection")
    assert r.status_code == 200
    first = r.json()["results"][0]
    assert len(first["findings"]) >= 1


def test_tool_abuse_sequence_replay_contract() -> None:
    r = client.post("/replay/tool-abuse-sequence")
    assert r.status_code == 200
    first = r.json()["results"][0]
    assert len(first["findings"]) >= 1
    assert first["risk"]["risk_score"] >= 70
