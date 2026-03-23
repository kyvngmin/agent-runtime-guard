from __future__ import annotations

from typing import Iterable

from ingestion.base import BaseConnector
from schemas.event import ActorType, EventSource, OutcomeType, SecurityEvent


class MockIdentityConnector(BaseConnector):
    name = "mock_identity"

    def __init__(self, events: list[dict] | None = None) -> None:
        self._events = events or []

    def fetch(self) -> Iterable[dict]:
        return self._events

    def normalize(self, raw: dict) -> SecurityEvent:
        return SecurityEvent(
            event_id=raw["event_id"],
            ts=raw["ts"],
            source=EventSource.identity,
            vendor=raw.get("vendor", "mock_idp"),
            event_type=raw["event_type"],
            actor_id=raw.get("actor_id"),
            actor_type=ActorType(raw.get("actor_type", "human")),
            session_id=raw.get("session_id"),
            device_id=raw.get("device_id"),
            outcome=OutcomeType(raw.get("outcome", "unknown")),
            src_ip=raw.get("src_ip"),
            geo=raw.get("geo"),
            tags=raw.get("tags", []),
            raw=raw,
        )
