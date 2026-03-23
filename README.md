# Agent Runtime Guard v0.1

An open-source runtime security gateway for teams that want to use OpenClaw, Claude Code, and AI agents in enterprise environments — but need a control layer before security will approve them.

Agent Runtime Guard detects and blocks malicious prompt / retrieval / tool / egress chains **before execution**.

**Not a prompt filter.**
It is a session-level policy and sequence-based blocking engine with feedback-aware tuning.

## Quickstart (30 seconds)

```bash
# 1. Install
pip install -e ".[dev]"

# 2. API Server
uvicorn apps.api.main:app --reload

# 3. Console (new terminal)
streamlit run apps/console/streamlit_app.py
```

Then run the **Prompt to Egress Block** replay scenario from the console to see a deny decision end-to-end.

## Claude API Proxy — enterprise control layer for OpenClaw / Claude Code

Deploy Agent Runtime Guard as a proxy in front of the Claude API. It inspects every `tool_use` request in real-time before it reaches the model.

**The problem:** Your team wants to use Claude Code or OpenClaw, but security won't approve unmonitored tool execution.

**The fix:** Point your client at the proxy. Everything passes through the guard first.

```bash
# 1. Guard API server (port 8000)
uvicorn apps.api.main:app --port 8000 &

# 2. Proxy server (port 8080)
uvicorn apps.proxy.main:app --port 8080
```

Then just change one environment variable:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ANTHROPIC_API_KEY=sk-ant-...
```

### Request Flow

1. Receive `POST /v1/messages` request
2. Extract `tool_use` blocks from messages
3. If `tool_use` found → send SecurityEvent to Guard `/decide` API
4. Based on result:
   - **allow** → proxy to Anthropic API (streaming supported)
   - **deny** → return `403` `{"error": "blocked_by_guard", "reason": "..."}`
   - **step_up_mfa** → return `202` `{"action": "require_approval", "reason": "..."}`
5. Requests without `tool_use` are proxied directly (no guard check)

> **Note:** Current proxy behavior is centered on inspecting request-side `tool_use` flows. Response-generated tool interception is an active next-step area.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | (required) | Anthropic API key |
| `GUARD_API_URL` | `http://localhost:8000` | Guard API address |
| `ANTHROPIC_API_URL` | `https://api.anthropic.com` | Anthropic API address |

### Custom Headers

| Header | Description |
|--------|-------------|
| `X-Actor-Id` | Requester identity (defaults to `anonymous`) |
| `X-Session-Id` | Session identity (auto-generated if absent) |

## Core Scenarios

| Scenario | Expected Result |
|----------|----------------|
| Normal Session Allow | `allow` — normal queries pass through |
| Prompt to Egress Block | `deny` — injection + sensitive query + external exfil blocked |
| RAG Indirect Injection | `deny` — hidden commands in documents detected |
| Tool Abuse Sequence | `deny` — sensitive query → dangerous tool → egress chain blocked |

## Architecture

```
Event Ingestion → Normalization → Correlation → Detection (Rules + Sequence + LLM Security)
    → Risk Scoring → Policy Decision → Auto-Response
                                          ↓
                              Feedback → Tuning Recommendation → Recursive Improvement
```

## What Makes It Different

- **Session-level flow analysis** — not just single-prompt filtering
- **Cross-vote risk scoring** — multiple detection signals converge to a single decision
- **Auto-response** — block, require approval, or terminate based on policy
- **Recursive improvement loop** — feedback → tuning → better detection over time
- **Open-source scope** — proxy server, schemas, rulesets, risk engine, policy engine, local dashboard, test suite

## Current Status

This project is currently **alpha / pre-MVP**.

**Current strengths:**
- Session-level sequence blocking
- Replay-driven testing (4 core scenarios)
- Claude API proxy with streaming support
- Feedback + tuning recommendation loop
- 19 passing pytest tests

**Current limitations:**
- Response-generated tool interception is still an active next-step area
- Current connectors are mostly mock / local-first
- Single-node only (no distributed deployment yet)

## Project Structure

```
schemas/          Event, detection, risk, policy schemas
assets/           Crown Jewel registry
ingestion/        Sensor connectors (mock)
fabric/           Normalization + session correlation
detections/       Detection engine (rules + LLM security)
risk/             Risk scoring engine
policy/           Policy engine + tool policies
response/         Auto-response orchestrator
feedback/         Analyst feedback + tuning recommendations
storage/          SQLite storage
apps/api/         FastAPI server
apps/console/     Streamlit console
apps/proxy/       Claude API proxy
scripts/          Smoke test runner
tests/            pytest tests
```

## Tests

```bash
pytest tests/ -q
```

## Smoke Test

With the API server running:

```bash
python scripts/smoke_runner.py
```

## v0.2 Backlog

- Connect at least one real-world connector
- Response-generated tool interception
- Auto-apply policy threshold candidates
- Separate findings table (performance optimization)
- Export / reporting
- Deployment automation

## License

MIT
