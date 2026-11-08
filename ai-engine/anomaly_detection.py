from typing import Any

from feature_engineering import event_features


def anomaly_score(event: dict[str, Any]) -> float:
    """Baseline placeholder score; replace with an evaluated, versioned model."""
    features = event_features(event)
    return round(features["severity_weight"] * 0.9 + (1 - features["has_host"]) * 0.1, 3)