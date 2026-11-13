from typing import Any

from fastapi import APIRouter, Depends, Query
from starlette.concurrency import run_in_threadpool

from ai.analyzer import analyze_pending, get_detector
from ai.detector import model_path
from api.security import require_roles
from database.database import list_ai_windows

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.get("/status")
def ai_status(_: dict[str, Any] = Depends(require_roles("admin", "analyst", "viewer"))) -> dict[str, Any]:
    detector = get_detector()
    if detector is None:
        return {"enabled": False, "reason": "model_not_trained", "model_path": str(model_path())}
    bundle = detector.bundle
    return {
        "enabled": True,
        "algorithm": bundle["algorithm"],
        "version": bundle["version"],
        "trained_at": bundle["trained_at"],
        "training_windows": bundle["training_windows"],
        "window_seconds": bundle["window_seconds"],
        "target_fpr": bundle["target_fpr"],
        "features": bundle["feature_names"],
        "constant_features": bundle["constant_features"],
        "feature_p99": bundle["feature_p99"],
        "forest_threshold": bundle["threshold"],
        "novelty_threshold": bundle["novelty_threshold"],
        "hosts": bundle.get("hosts", []),
    }


@router.get("/windows")
def ai_windows(
    host_id: str | None = Query(default=None),
    anomalies_only: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=1000),
    _: dict[str, Any] = Depends(require_roles("admin", "analyst", "viewer")),
) -> list[dict[str, Any]]:
    return list_ai_windows(host_id, anomalies_only, limit)


@router.post("/analyze")
async def ai_analyze(_: dict[str, Any] = Depends(require_roles("admin", "analyst"))) -> dict[str, Any]:
    return await run_in_threadpool(analyze_pending)
