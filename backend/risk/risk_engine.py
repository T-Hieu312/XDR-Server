SEVERITY_SCORES = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}


def calculate_risk(severity: str, confidence: float = 1.0, anomaly: float = 0.0) -> int:
    """Combine rule confidence and an optional anomaly probability into a 0..100 score."""
    base = SEVERITY_SCORES.get(str(severity).lower(), 5)
    confidence_score = max(0.0, min(1.0, float(confidence)))
    anomaly_score = max(0.0, min(1.0, float(anomaly)))
    return max(0, min(100, round(base * confidence_score * (1 - 0.35 * anomaly_score) + 35 * anomaly_score)))