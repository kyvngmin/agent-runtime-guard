from __future__ import annotations

from typing import Iterable

from ingestion.base import BaseConnector
from schemas.event import ActorType, EventSource, OutcomeType, SecurityEvent


class MockLLMGatewayConnector(BaseConnector):
    name = "mock_llm_gateway"

    def __init__(self, events: list[dict] | None = None) -> None:
        self._events = events or []

    def fetch(self) -> Iterable[dict]:
        return self._events

    def normalize(self, raw: dict) -> SecurityEvent:
        return SecurityEvent(
            event_id=raw["event_id"],
            ts=raw["ts"],
            source=EventSource.llm_gateway,
            vendor=raw.get("vendor", "mock_gateway"),
            event_type=raw["event_type"],
            actor_id=raw.get("actor_id"),
            actor_type=ActorType(raw.get("actor_type", "human")),
            session_id=raw.get("session_id"),
            device_id=raw.get("device_id"),
            asset_id=raw.get("asset_id"),
            asset_type=raw.get("asset_type"),
            action=raw.get("action"),
            outcome=OutcomeType(raw.get("outcome", "unknown")),
            tool_name=raw.get("tool_name"),
            model_name=raw.get("model_name"),
            prompt_hash=raw.get("prompt_hash"),
            response_hash=raw.get("response_hash"),
            bytes_in=raw.get("bytes_in"),
            bytes_out=raw.get("bytes_out"),
            object_count=raw.get("object_count"),
            tags=raw.get("tags", []),
            raw=raw,
        )
