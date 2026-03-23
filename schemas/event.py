from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class EventSource(str, Enum):
    identity = "identity"
    endpoint = "endpoint"
    cloud = "cloud"
    saas = "saas"
    llm_gateway = "llm_gateway"
    web = "web"
    mail = "mail"


class ActorType(str, Enum):
    human = "human"
    service_account = "service_account"
    agent = "agent"
    admin = "admin"


class OutcomeType(str, Enum):
    success = "success"
    fail = "fail"
    blocked = "blocked"
    unknown = "unknown"


class SecurityEvent(BaseModel):
    event_id: str
    ts: datetime

    source: EventSource
    vendor: Optional[str] = None
    event_type: str

    actor_id: Optional[str] = None
    actor_type: Optional[ActorType] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None

    asset_id: Optional[str] = None
    asset_type: Optional[str] = None
    asset_criticality: Optional[int] = Field(default=None, ge=1, le=5)

    action: Optional[str] = None
    outcome: OutcomeType = OutcomeType.unknown

    src_ip: Optional[str] = None
    geo: Optional[str] = None
    network_zone: Optional[str] = None

    tool_name: Optional[str] = None
    model_name: Optional[str] = None
    prompt_hash: Optional[str] = None
    response_hash: Optional[str] = None

    bytes_in: Optional[int] = Field(default=None, ge=0)
    bytes_out: Optional[int] = Field(default=None, ge=0)
    object_count: Optional[int] = Field(default=None, ge=0)

    tags: List[str] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts", mode="before")
    @classmethod
    def ensure_datetime(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        raise ValueError("ts must be datetime or ISO8601 string")


class DetectionFinding(BaseModel):
    finding_id: str
    finding_type: str
    rule_name: str
    severity: int = Field(ge=1, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    summary: str
    tags: List[str] = Field(default_factory=list)
    related_event_ids: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)


class RiskResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    recommended_action: str
    findings: List[DetectionFinding] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    action: str
    should_execute: bool
    reason: str
    cooldown_seconds: int = Field(default=0, ge=0)
    parameters: Dict[str, Any] = Field(default_factory=dict)
