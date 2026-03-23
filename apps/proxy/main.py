"""Claude API Proxy with Agent Runtime Guard.

Sits between LLM clients (e.g. OpenClaw) and the Anthropic API.
Intercepts tool_use blocks, evaluates them via the guard /decide API,
and blocks/approves before forwarding to Anthropic.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger("agent-runtime-guard.proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

GUARD_API_URL = os.getenv("GUARD_API_URL", "http://localhost:8000")
ANTHROPIC_API_URL = os.getenv("ANTHROPIC_API_URL", "https://api.anthropic.com")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

app = FastAPI(title="Agent Runtime Guard Proxy", version="0.1.0")


@app.get("/health")
def health():
    return {"status": "ok", "service": "agent-runtime-guard-proxy"}


def _extract_tool_use_blocks(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract all tool_use content blocks from messages."""
    blocks: list[dict[str, Any]] = []
    for msg in messages:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                blocks.append(block)
    return blocks


def _build_security_event(
    tool_block: dict[str, Any],
    messages: list[dict[str, Any]],
    actor_id: str,
    session_id: str,
) -> dict[str, Any]:
    """Convert a tool_use block into a SecurityEvent dict for the guard API."""
    return {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": "llm_gateway",
        "event_type": "tool_use_request",
        "actor_id": actor_id,
        "actor_type": "agent",
        "session_id": session_id,
        "tool_name": tool_block.get("name", "unknown"),
        "action": "tool_call",
        "outcome": "unknown",
        "tags": ["tool_use"],
        "raw": {
            "prompt_text": json.dumps(messages, ensure_ascii=False, default=str),
            "tool_input": tool_block.get("input", {}),
        },
    }


async def _check_guard(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Call the guard /decide API and return the response."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{GUARD_API_URL}/decide",
            json={"events": events},
        )
        resp.raise_for_status()
        return resp.json()


def _evaluate_guard_results(guard_response: dict[str, Any]) -> tuple[str, str]:
    """Return (action, reason) from guard results.

    action is one of: "allow", "deny", "step_up_mfa"
    """
    for result in guard_response.get("results", []):
        decision = result.get("decision", {})
        action = decision.get("action", "allow")
        reason = decision.get("reason", "")

        if action in (
            "deny_tool_execution",
            "terminate_session_and_block_external_share",
            "isolate_host_and_disable_account",
        ):
            return "deny", reason
        if action in ("step_up_mfa", "require_human_approval"):
            return "step_up_mfa", reason

    return "allow", ""


def _forward_headers(request: Request) -> dict[str, str]:
    """Build headers for the upstream Anthropic API request."""
    headers: dict[str, str] = {
        "x-api-key": ANTHROPIC_API_KEY,
        "content-type": "application/json",
    }
    # Forward anthropic-specific headers
    for key in ("anthropic-version", "anthropic-beta"):
        val = request.headers.get(key)
        if val:
            headers[key] = val
    return headers


@app.post("/v1/messages")
async def proxy_messages(request: Request):
    body = await request.json()
    messages: list[dict[str, Any]] = body.get("messages", [])
    is_stream = body.get("stream", False)

    actor_id = request.headers.get("x-actor-id", "anonymous")
    session_id = request.headers.get("x-session-id", str(uuid.uuid4()))

    # Extract tool_use blocks
    tool_blocks = _extract_tool_use_blocks(messages)

    # If tool_use exists, check with guard
    if tool_blocks:
        events = [
            _build_security_event(tb, messages, actor_id, session_id)
            for tb in tool_blocks
        ]

        try:
            guard_response = await _check_guard(events)
        except httpx.HTTPError as exc:
            logger.error("Guard API call failed: %s", exc)
            # Fail-open is dangerous; fail-closed for security
            return JSONResponse(
                status_code=502,
                content={"error": "guard_unavailable", "reason": str(exc)},
            )

        action, reason = _evaluate_guard_results(guard_response)

        if action == "deny":
            logger.warning(
                "BLOCKED tool_use request | actor=%s session=%s tools=%s reason=%s",
                actor_id,
                session_id,
                [tb.get("name") for tb in tool_blocks],
                reason,
            )
            return JSONResponse(
                status_code=403,
                content={"error": "blocked_by_guard", "reason": reason},
            )

        if action == "step_up_mfa":
            logger.info(
                "APPROVAL REQUIRED for tool_use | actor=%s session=%s tools=%s reason=%s",
                actor_id,
                session_id,
                [tb.get("name") for tb in tool_blocks],
                reason,
            )
            return JSONResponse(
                status_code=202,
                content={"action": "require_approval", "reason": reason},
            )

    # Forward to Anthropic API
    upstream_url = f"{ANTHROPIC_API_URL}/v1/messages"
    headers = _forward_headers(request)

    if is_stream:
        return await _stream_response(upstream_url, headers, body)
    else:
        return await _non_stream_response(upstream_url, headers, body)


async def _non_stream_response(
    url: str, headers: dict[str, str], body: dict[str, Any]
) -> JSONResponse:
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, headers=headers, json=body)
    return JSONResponse(status_code=resp.status_code, content=resp.json())


async def _stream_response(
    url: str, headers: dict[str, str], body: dict[str, Any]
) -> StreamingResponse:
    client = httpx.AsyncClient(timeout=120.0)

    async def event_generator():
        try:
            async with client.stream("POST", url, headers=headers, json=body) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk
        finally:
            await client.aclose()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"cache-control": "no-cache", "connection": "keep-alive"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
