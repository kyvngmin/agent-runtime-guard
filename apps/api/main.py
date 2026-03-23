from __future__ import annotations

from fastapi import FastAPI

from apps.api.routes.decide import router as decide_router
from apps.api.routes.feedback import router as feedback_router
from apps.api.routes.replay import router as replay_router

app = FastAPI(title="Agent Runtime Guard", version="0.1.0")
app.include_router(decide_router)
app.include_router(replay_router)
app.include_router(feedback_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "agent-runtime-guard"}
