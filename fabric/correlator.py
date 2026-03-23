from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable, List

from schemas.event import SecurityEvent


class Correlator:
    def __init__(self, window_minutes: int = 15) -> None:
        self.window = timedelta(minutes=window_minutes)

    def _group_key(self, event: SecurityEvent) -> str:
        return "|".join([
            event.actor_id or "-",
            event.session_id or "-",
            event.device_id or "-",
        ])

    def correlate(self, events: Iterable[SecurityEvent]) -> List[List[SecurityEvent]]:
        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in sorted(events, key=lambda e: e.ts):
            grouped[self._group_key(event)].append(event)

        chains: list[list[SecurityEvent]] = []
        for event_list in grouped.values():
            current_chain: list[SecurityEvent] = []
            for event in event_list:
                if not current_chain:
                    current_chain = [event]
                    continue
                if event.ts - current_chain[-1].ts <= self.window:
                    current_chain.append(event)
                else:
                    chains.append(current_chain)
                    current_chain = [event]
            if current_chain:
                chains.append(current_chain)
        return chains
