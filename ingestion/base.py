from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from schemas.event import SecurityEvent


class BaseConnector(ABC):
    name: str = "base"

    @abstractmethod
    def fetch(self) -> Iterable[dict]:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: dict) -> SecurityEvent:
        raise NotImplementedError

    def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for raw in self.fetch():
            try:
                events.append(self.normalize(raw))
            except Exception:
                continue
        return events
