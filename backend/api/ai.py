from typing import Any

from fastapi import APIRouter, Depends, Query
from starlette.concurrency import run_in_threadpool

from ai.analyzer import analyze_pending, get_detector, get_scenario_classifier
from ai.assets import assets_path, get_assets
from ai.detector import model_path
from ai.scenarios import SCENARIOS, scenario_model_path
from api.security import require_roles
from database.database import list_ai_windows

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.get("/status")
def ai_status(_: dict[str, Any] = Depends(require_roles("admin", "analyst", "viewer"))) -> dict[str, Any]:
    detector = get_detector()
    classifier = get_scenario_classifier()
    assets = get_assets()
    common = {
        "scenario_catalog": {key: value["label"] for key, value in SCENARIOS.items()},
        "scenario_model": {
            "enabled": True,
            "algorithm": classifier.bundle["algorithm"],
            "version": classifier.version,
            "trained_at": classifier.bundle["trained_at"],
            "classes": classifier.bundle["classes"],
            "class_counts": classifier.bundle.get("class_counts", {}),
            "runs_per_scenario": classifier.bundle.get("runs_per_scenario", {}),
            "min_confidence": classifier.min_confidence,
            "holdout": {k: v for k, v in (classifier.bundle.get("holdout") or {}).items() if k != "per_scenario"},
        } if classifier else {"enabled": False, "model_path": str(scenario_model_path())},
        "assets": {"path": str(assets_path()), "hosts": [h["host_id"] for h in assets.hosts],
                   "internal_networks": [str(n) for n in assets.internal],
                   "untrusted_networks": [str(n) for n in assets.untrusted]},
    }
    if detector is None:
        return {"enabled": False, "reason": "model_not_trained", "model_path": str(model_path()), **common}
    bundle = detector.bundle
    return {
        **common,
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
