from __future__ import annotations

import os
from datetime import date, datetime, time
from typing import Any
from urllib.parse import urlencode

import requests
import streamlit as st

API_BASE = os.getenv("ARG_API_BASE", "http://localhost:8000")

st.set_page_config(page_title="Agent Runtime Guard", layout="wide")
st.title("Agent Runtime Guard Console")
st.caption("Prompt → Retrieval → Tool/Egress chain detection & blocking — v0.1")

REPLAY_OPTIONS = {
    "Prompt to Egress Block": "/replay/prompt-to-egress",
    "Normal Session Allow": "/replay/normal-session",
    "Unknown Tool High Risk": "/replay/unknown-tool-high-risk",
    "RAG Indirect Injection": "/replay/rag-indirect-injection",
    "Tool Abuse Sequence": "/replay/tool-abuse-sequence",
}

DECISION_COLORS = {
    "allow": "#16a34a",
    "step_up_mfa": "#eab308",
    "require_human_approval": "#f97316",
    "deny_tool_execution": "#dc2626",
    "terminate_session_and_block_external_share": "#b91c1c",
    "isolate_host_and_disable_account": "#7f1d1d",
}

SEVERITY_COLORS = {"low": "#16a34a", "medium": "#eab308", "high": "#f97316", "critical": "#dc2626"}


# --- Helpers ---

def severity_bucket(value: int) -> str:
    if value >= 85: return "critical"
    if value >= 70: return "high"
    if value >= 40: return "medium"
    return "low"


def badge(label: str, color: str) -> str:
    return f"<span style='display:inline-block;padding:0.25rem 0.55rem;border-radius:999px;background:{color};color:white;font-size:0.85rem;font-weight:600'>{label}</span>"


def get_max_severity(findings: list[dict[str, Any]]) -> int:
    if not findings: return 0
    return max(int(f.get("severity", 0)) for f in findings)


def call_post(path: str) -> dict[str, Any]:
    r = requests.post(f"{API_BASE}{path}", timeout=10)
    r.raise_for_status()
    return r.json()


def call_get(path: str) -> dict[str, Any]:
    r = requests.get(f"{API_BASE}{path}", timeout=10)
    r.raise_for_status()
    return r.json()


def call_post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    r = requests.post(f"{API_BASE}{path}", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


def to_sqlite_dt_start(value: date | None) -> str:
    if value is None: return ""
    return datetime.combine(value, time.min).strftime("%Y-%m-%d %H:%M:%S")


def to_sqlite_dt_end(value: date | None) -> str:
    if value is None: return ""
    return datetime.combine(value, time.max).strftime("%Y-%m-%d %H:%M:%S")


# --- Chain card renderer ---

def render_chain_card(result: dict[str, Any], index: int) -> None:
    chain = result.get("chain", [])
    findings = result.get("findings", [])
    risk = result.get("risk", {})
    decision = result.get("decision", {})

    decision_name = decision.get("action", "-")
    decision_color = DECISION_COLORS.get(decision_name, "#334155")
    max_sev = get_max_severity(findings)
    max_sev_color = SEVERITY_COLORS[severity_bucket(max_sev)]

    st.markdown(f"### Chain {index + 1} &nbsp; {badge(decision_name, decision_color)}", unsafe_allow_html=True)
    st.caption(f"Events: {' → '.join(e.get('event_type', '?') for e in chain)}")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Risk Score", risk.get("risk_score", 0))
    col2.metric("Confidence", f"{risk.get('confidence', 0.0):.2f}")
    col3.metric("Findings", len(findings))
    col4.markdown(badge(f"MAX SEV {max_sev}", max_sev_color), unsafe_allow_html=True)

    left, right = st.columns(2)
    with left:
        st.write("**Findings**")
        if findings:
            for f in findings:
                st.markdown(f"**{f['title']}**")
                st.caption(f"rule={f['rule_name']} | severity={f.get('severity')} | confidence={f.get('confidence')}")
                st.write(f.get("summary", ""))
        else:
            st.info("No findings")
    with right:
        st.write("**Reasons**")
        for reason in risk.get("reasons", []):
            st.markdown(f"- {reason}")

    with st.expander("Full JSON"):
        st.json(result)


# --- History table ---

def render_history_table(items: list[dict[str, Any]], limit: int) -> None:
    if not items:
        st.info("No replay history yet")
        return
    rows = [
        {
            "actor_id": it.get("actor_id"), "session_id": it.get("session_id"),
            "chain_summary": " → ".join(it.get("chain_summary", [])),
            "risk_score": it.get("risk_score"), "decision": it.get("decision"),
            "execution_status": it.get("execution_status"),
        }
        for it in items[:limit]
    ]
    st.dataframe(rows, use_container_width=True)


# === SIDEBAR ===

with st.sidebar:
    st.write("## Replay Controls")
    selected = st.selectbox("Choose scenario", list(REPLAY_OPTIONS.keys()))

    if st.button("Run Replay", use_container_width=True):
        try:
            payload = call_post(REPLAY_OPTIONS[selected])
            st.session_state["last_result"] = payload
            st.success("Replay completed")
        except Exception as exc:
            st.error(f"Replay failed: {exc}")

    st.divider()
    st.write("## History Filters")
    history_actor = st.text_input("Actor filter", value="")
    history_decision = st.selectbox("Decision filter", ["", "allow", "require_human_approval", "deny_tool_execution", "step_up_mfa"], index=0)
    history_min_risk = st.slider("Minimum risk", 0, 100, 0, step=5)
    history_limit = st.slider("Max rows", 5, 50, 20, step=5)
    history_from = st.date_input("From date", value=None)
    history_to = st.date_input("To date", value=None)

    if st.button("Refresh History", use_container_width=True):
        try:
            q = urlencode({"limit": history_limit, "actor_id": history_actor, "decision": history_decision,
                           "min_risk": history_min_risk, "created_from": to_sqlite_dt_start(history_from),
                           "created_to": to_sqlite_dt_end(history_to)})
            history = call_get(f"/replay/results?{q}")
            st.session_state["history"] = history.get("items", [])
            st.success("History refreshed")
        except Exception as exc:
            st.error(f"History load failed: {exc}")

    if st.button("Clear History", use_container_width=True):
        try:
            call_post("/replay/results/clear")
            st.session_state["history"] = []
            st.success("History cleared")
        except Exception as exc:
            st.error(f"History clear failed: {exc}")

    st.divider()
    st.caption(f"API: {API_BASE}")


# === MAIN AREA ===

# Latest Replay
st.write("## Latest Replay")
latest = st.session_state.get("last_result", {})
latest_results = latest.get("results", [])
if latest_results:
    for idx, result in enumerate(latest_results):
        render_chain_card(result, idx)
else:
    st.info("Run a replay scenario to see output")

# History
st.write("## Replay History")
history_items = st.session_state.get("history", [])
render_history_table(history_items, limit=history_limit)

# History detail + feedback
if history_items:
    selected_index = st.number_input("History item index", min_value=0,
        max_value=max(0, min(len(history_items), history_limit) - 1), value=0, step=1)
    sel = history_items[selected_index]
    with st.expander("Selected History Detail"):
        st.json(sel.get("full_result", {}))

    st.write("### Analyst Feedback")
    fb_col1, fb_col2 = st.columns(2)
    with fb_col1:
        feedback_verdict = st.selectbox("Verdict", ["true_positive", "false_positive", "benign_but_weird"], index=0)
    with fb_col2:
        # Finding-level feedback
        full_res = sel.get("full_result", {})
        finding_list = full_res.get("findings", [])
        rule_names_in_findings = [f.get("rule_name", "unknown") for f in finding_list]
        selected_rule_for_fb = st.selectbox("Rule (optional)", [""] + rule_names_in_findings, index=0)

    feedback_notes = st.text_area("Notes", value="", height=80)
    if st.button("Submit Feedback", use_container_width=True):
        try:
            payload = {
                "result_session_id": sel.get("session_id"), "actor_id": sel.get("actor_id"),
                "verdict": feedback_verdict, "notes": feedback_notes, "source": "console",
                "rule_name": selected_rule_for_fb or None,
            }
            result = call_post_json("/feedback", payload)
            st.success(f"Feedback saved: {result['verdict']}")
        except Exception as exc:
            st.error(f"Feedback submit failed: {exc}")

# Feedback Summary
st.write("## Feedback Summary")
try:
    fb_summary = call_get("/feedback/summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("TP", fb_summary.get("true_positive", 0))
    c2.metric("FP", fb_summary.get("false_positive", 0))
    c3.metric("Benign Weird", fb_summary.get("benign_but_weird", 0))
    c4.metric("Total", fb_summary.get("total", 0))
except Exception:
    st.caption("Feedback summary not available yet")

# Rule Summary
st.write("## Rule Feedback Summary")
try:
    from_str = to_sqlite_dt_start(history_from)
    to_str = to_sqlite_dt_end(history_to)
    q = urlencode({"limit": 50, "created_from": from_str, "created_to": to_str})
    rule_payload = call_get(f"/feedback/rule-summary?{q}")
    rule_items = rule_payload.get("items", [])
    if rule_items:
        st.dataframe(rule_items, use_container_width=True)
    else:
        st.info("No rule-level feedback yet")
except Exception:
    st.caption("Rule summary not available yet")

# Recommendations
st.write("## Rule Tuning Recommendations")
try:
    q = urlencode({"limit": 50, "created_from": to_sqlite_dt_start(history_from), "created_to": to_sqlite_dt_end(history_to)})
    rec_payload = call_get(f"/feedback/recommendations?{q}")
    rec_items = rec_payload.get("items", [])
    if rec_items:
        st.dataframe(rec_items, use_container_width=True)
        for item in rec_items[:10]:
            status = item.get("status")
            msg = f"{item.get('rule_name')}: {item.get('reason')}"
            if status == "too_noisy": st.warning(msg)
            elif status == "stable": st.success(msg)
            elif status == "mixed_quality": st.info(msg)
            elif status == "insufficient_data": st.caption(msg)
    else:
        st.info("No recommendations yet")
except Exception:
    st.caption("Recommendations not available yet")
