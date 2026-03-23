from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from storage.sqlite_feedback_store import SQLiteFeedbackStore


@dataclass
class AnalystVerdict:
    alert_id: str | None
    verdict: str
    notes: str
    reviewed_at: datetime


class AnalystReviewService:
    def __init__(self, store: SQLiteFeedbackStore | None = None) -> None:
        self.store = store or SQLiteFeedbackStore()

    def submit(self, *, alert_id: str | None, actor_id: str | None, verdict: str, notes: str,
               source: str = "console", rule_name: str | None = None, finding_id: str | None = None) -> AnalystVerdict:
        if verdict not in {"true_positive", "false_positive", "benign_but_weird"}:
            raise ValueError("invalid verdict")
        saved = self.store.add(
            result_session_id=alert_id, actor_id=actor_id, verdict=verdict,
            notes=notes, source=source, rule_name=rule_name, finding_id=finding_id,
        )
        return AnalystVerdict(
            alert_id=saved["result_session_id"], verdict=saved["verdict"],
            notes=saved["notes"], reviewed_at=datetime.now(timezone.utc),
        )
