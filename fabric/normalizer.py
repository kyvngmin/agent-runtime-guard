from __future__ import annotations

from typing import Iterable, List

from assets.crown_jewels import get_asset_criticality
from schemas.event import SecurityEvent


class EventNormalizer:
    def apply_enrichment(self, event: SecurityEvent) -> SecurityEvent:
        if event.asset_criticality is None:
            criticality = get_asset_criticality(event.asset_id)
            if criticality is not None:
                event.asset_criticality = criticality
        if not event.tags:
            event.tags = []
        return event

    def normalize_batch(self, events: Iterable[SecurityEvent]) -> List[SecurityEvent]:
        return [self.apply_enrichment(event) for event in events]
