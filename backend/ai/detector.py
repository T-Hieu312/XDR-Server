"""Hybrid anomaly model: Isolation Forest + baseline novelty, with explanations.

Two complementary detectors are calibrated on the same benign baseline:

* Isolation Forest finds unusual *combinations* of feature values. It cannot
  react to a feature that never varied during training (e.g. LSASS access is
  always 0 on a clean host), because its trees never split on that feature.
* Novelty measures how far each feature exceeds its baseline 99th percentile,
  ``sum(log2((value + 1) / (p99 + 1)))`` over exceeding features, so behaviour
  never seen in the baseline is still scored.

Each part is thresholded at the ``target_fpr`` quantile of its baseline scores;
a window is anomalous if either part crosses its threshold.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ai.features import FEATURE_NAMES, WINDOW_SECONDS

DEFAULT_MODEL_PATH = "data/ai_model.joblib"
MIN_TRAINING_WINDOWS = 50
# A single feature merely doubling past its baseline p99 (novelty = 1.0) is not enough.
MIN_NOVELTY_THRESHOLD = 1.0


def novelty_scores(raw: np.ndarray, p99: np.ndarray) -> np.ndarray:
    ratios = (np.clip(raw, 0, None) + 1.0) / (p99 + 1.0)
    return np.log2(np.maximum(ratios, 1.0)).sum(axis=1)


def model_path() -> Path:
    return Path(os.environ.get("XDR_AI_MODEL_PATH", DEFAULT_MODEL_PATH))


def _matrix(rows: list[dict[str, float]], feature_names: list[str]) -> np.ndarray:
    # log1p keeps bursty counts (0, 3, 300) on a comparable scale for random splits.
    values = np.array([[float(row.get(name, 0.0)) for name in feature_names] for row in rows])
    return np.log1p(np.clip(values, 0, None))


def train_model(
    rows: list[dict[str, float]],
    target_fpr: float = 0.01,
    n_estimators: int = 200,
    random_state: int = 42,
    min_windows: int = MIN_TRAINING_WINDOWS,
) -> dict[str, Any]:
    """Train on benign windows only and calibrate the alert threshold.

    The threshold is the ``target_fpr`` quantile of the training scores, so on
    the baseline itself roughly ``target_fpr`` of windows would be flagged.
    """
    if len(rows) < min_windows:
        raise ValueError(f"Need at least {min_windows} benign windows, got {len(rows)}")
    if not 0 < target_fpr < 0.5:
        raise ValueError("target_fpr must be between 0 and 0.5")

    X = _matrix(rows, FEATURE_NAMES)
    model = IsolationForest(n_estimators=n_estimators, contamination="auto",
                            random_state=random_state, n_jobs=-1)
    model.fit(X)
    scores = model.score_samples(X)
    raw = np.array([[float(row.get(name, 0.0)) for name in FEATURE_NAMES] for row in rows])
    p99 = np.quantile(raw, 0.99, axis=0)
    novelty = novelty_scores(raw, p99)

    trained_at = datetime.now(timezone.utc)
    return {
        "model": model,
        "algorithm": "IsolationForest",
        "version": "if-" + trained_at.strftime("%Y%m%d%H%M%S"),
        "trained_at": trained_at.isoformat(),
        "feature_names": list(FEATURE_NAMES),
        "transform": "log1p",
        "window_seconds": WINDOW_SECONDS,
        "training_windows": len(rows),
        "target_fpr": target_fpr,
        "threshold": float(np.quantile(scores, target_fpr)),
        "median_score": float(np.median(scores)),
        "novelty_threshold": max(float(np.quantile(novelty, 1 - target_fpr)), MIN_NOVELTY_THRESHOLD),
        "feature_p99": {name: float(p99[i]) for i, name in enumerate(FEATURE_NAMES)},
        "constant_features": [name for i, name in enumerate(FEATURE_NAMES) if np.ptp(raw[:, i]) == 0],
    }


def save_model(bundle: dict[str, Any], path: Path | None = None) -> Path:
    path = path or model_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    return path


class AnomalyDetector:
    def __init__(self, bundle: dict[str, Any]):
        if bundle.get("feature_names") != FEATURE_NAMES:
            raise ValueError("Model was trained with a different feature set; retrain it")
        self.bundle = bundle
        self.model = bundle["model"]
        self.version = bundle["version"]
        self.threshold = bundle["threshold"]
        self.median_score = bundle["median_score"]
        self.novelty_threshold = bundle["novelty_threshold"]
        self.p99 = np.array([bundle["feature_p99"][name] for name in FEATURE_NAMES])

    @classmethod
    def load(cls, path: Path | None = None) -> "AnomalyDetector | None":
        path = path or model_path()
        if not path.exists():
            return None
        return cls(joblib.load(path))

    def score_many(self, rows: list[dict[str, float]]) -> list[dict[str, Any]]:
        if not rows:
            return []
        scores = self.model.score_samples(_matrix(rows, FEATURE_NAMES))
        raw = np.array([[float(row.get(name, 0.0)) for name in FEATURE_NAMES] for row in rows])
        novelty = novelty_scores(raw, self.p99)
        return [self._result(row, float(score), float(nov)) for row, score, nov in zip(rows, scores, novelty)]

    def score(self, row: dict[str, float]) -> dict[str, Any]:
        return self.score_many([row])[0]

    def _result(self, row: dict[str, float], forest_score: float, novelty: float) -> dict[str, Any]:
        # Both parts map to 0..1 with 0.5 exactly at their calibrated threshold.
        span = max(self.median_score - self.threshold, 1e-6)
        forest_part = float(np.clip(0.5 * (self.median_score - forest_score) / span, 0.0, 1.0))
        novelty_part = float(np.clip(0.5 * novelty / self.novelty_threshold, 0.0, 1.0))
        forest_anomaly = forest_score < self.threshold
        novelty_anomaly = novelty > self.novelty_threshold
        return {
            "is_anomaly": bool(forest_anomaly or novelty_anomaly),
            "ai_score": round(max(forest_part, novelty_part), 4),
            # Single ranking value for ROC/PR metrics: higher = more anomalous.
            "anomaly_rank": max(forest_part, novelty_part),
            "forest": {"score": forest_score, "threshold": self.threshold,
                       "anomaly": bool(forest_anomaly), "ai_score": round(forest_part, 4)},
            "novelty": {"score": round(novelty, 4), "threshold": self.novelty_threshold,
                        "anomaly": bool(novelty_anomaly), "ai_score": round(novelty_part, 4)},
            "raw_score": forest_score,
            "model_version": self.version,
            "top_features": self.explain(row),
        }

    def explain(self, row: dict[str, float], limit: int = 3) -> list[dict[str, float]]:
        """Features that exceed the 99th percentile of the benign baseline."""
        p99 = self.bundle["feature_p99"]
        deviations = []
        for name in FEATURE_NAMES:
            value = float(row.get(name, 0.0))
            baseline = p99.get(name, 0.0)
            if value > baseline:
                deviations.append({"feature": name, "value": value, "baseline_p99": baseline,
                                   "ratio": round((value + 1) / (baseline + 1), 2)})
        deviations.sort(key=lambda item: item["ratio"], reverse=True)
        return deviations[:limit]
