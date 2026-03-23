from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from apps.api.runtime import decide_events
from schemas.event import SecurityEvent

router = APIRouter(tags=["decide"])


class EventIngestRequest(BaseModel):
    events: list[SecurityEvent]


@router.post("/decide")
def decide(request: EventIngestRequest) -> dict:
    return decide_events(request.events)
