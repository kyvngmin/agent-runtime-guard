from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from feedback.analyst_review import AnalystReviewService
from feedback.tuning_recommender import RuleTuningRecommender

router = APIRouter(prefix="/feedback", tags=["feedback"])
feedback_service = AnalystReviewService()
recommender = RuleTuningRecommender()


class FeedbackSubmitRequest(BaseModel):
    result_session_id: str | None = None
    actor_id: str | None = None
    verdict: str
    notes: str = ""
    source: str = "console"
    rule_name: str | None = None
    finding_id: str | None = None


@router.post("")
def submit_feedback(req: FeedbackSubmitRequest) -> dict:
    result = feedback_service.submit(
        alert_id=req.result_session_id, actor_id=req.actor_id,
        verdict=req.verdict, notes=req.notes, source=req.source,
        rule_name=req.rule_name, finding_id=req.finding_id,
    )
    return {"verdict": result.verdict, "alert_id": result.alert_id, "reviewed_at": result.reviewed_at.isoformat()}


@router.get("")
def list_feedback(limit: int = 100, verdict: str | None = None,
                  created_from: str | None = None, created_to: str | None = None) -> dict:
    return {"items": feedback_service.store.list(limit=limit, verdict=verdict, created_from=created_from, created_to=created_to)}


@router.get("/summary")
def feedback_summary() -> dict:
    return feedback_service.store.summary()


@router.get("/rule-summary")
def feedback_rule_summary(limit: int = 50, created_from: str | None = None, created_to: str | None = None) -> dict:
    return {"items": feedback_service.store.rule_summary(limit=limit, created_from=created_from, created_to=created_to)}


@router.get("/rule-cases")
def feedback_rule_cases(rule_name: str, verdict: str | None = None, limit: int = 20,
                        created_from: str | None = None, created_to: str | None = None) -> dict:
    return {"items": feedback_service.store.recent_rule_feedback_cases(
        rule_name=rule_name, verdict=verdict, limit=limit, created_from=created_from, created_to=created_to)}


@router.get("/by-actor")
def feedback_by_actor(actor_id: str, limit: int = 50, verdict: str | None = None) -> dict:
    return {"items": feedback_service.store.list(limit=limit, verdict=verdict, actor_id=actor_id)}


@router.get("/recommendations")
def feedback_recommendations(limit: int = 50, created_from: str | None = None, created_to: str | None = None) -> dict:
    items = feedback_service.store.rule_summary(limit=limit, created_from=created_from, created_to=created_to)
    return {"items": recommender.recommend(items)}
