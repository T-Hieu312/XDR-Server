from __future__ import annotations

import csv
import math
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ai.features import FEATURE_NAMES, WINDOW_SECONDS, parse_timestamp

DEFAULT_SCENARIO_MODEL_PATH = "data/ai_scenarios.joblib"
BENIGN = "benign"
UNKNOWN = "unknown"

# Scenarios of the lab topology. Labels in the runs CSV may use other ids; those
# are shown as-is with no MITRE mapping.
SCENARIOS: dict[str, dict[str, Any]] = {
    BENIGN: {"label": "Bình thường", "mitre": []},
    "bruteforce": {"label": "Brute force đăng nhập", "mitre": ["T1110"]},
    "rdp_compromise": {"label": "Đăng nhập RDP + hậu khai thác", "mitre": ["T1021.001", "T1078", "T1059"]},
    "sql_injection": {"label": "SQL injection / tấn công web", "mitre": ["T1190"]},
    "port_scan": {"label": "Quét mạng / dò dịch vụ", "mitre": ["T1046"]},
    "execution": {"label": "Thực thi lệnh / tải mã độc", "mitre": ["T1059", "T1105"]},
    "persistence": {"label": "Cài cơ chế bám trụ", "mitre": ["T1547.001", "T1053.005"]},
    "credential_access": {"label": "Đánh cắp thông tin xác thực", "mitre": ["T1003.001"]},
    "command_and_control": {"label": "Kết nối C2 / ra ngoài bất thường", "mitre": ["T1071", "T1568.002"]},
    UNKNOWN: {"label": "Bất thường chưa rõ loại", "mitre": []},
}

# Which scenario a feature above its baseline p99 is evidence for (heuristic fallback).
FEATURE_SCENARIO = {
    "auth_failure_count": "bruteforce",
    "auth_failure_src_count": "bruteforce",
    "ids_bruteforce_count": "bruteforce",
    "rdp_logon_count": "rdp_compromise",
    "auth_success_after_failures": "rdp_compromise",
    "ids_web_attack_count": "sql_injection",
    "web_attack_count": "sql_injection",
    "ids_scan_count": "port_scan",
    "unique_dst_port": "port_scan",
    "unique_dst_ip": "port_scan",
    "suspicious_cmdline_count": "execution",
    "shell_process_count": "execution",
    "lolbin_process_count": "execution",
    "office_spawn_count": "execution",
    "user_writable_exec_count": "execution",
    "executable_file_create_count": "execution",
    "max_cmdline_length": "execution",
    "persistence_registry_count": "persistence",
    "lsass_access_count": "credential_access",
    "external_connection_count": "command_and_control",
    "max_domain_entropy": "command_and_control",
}
IDENTITY = {"bruteforce", "rdp_compromise"}
POST_EXPLOITATION = {"execution", "persistence", "credential_access", "command_and_control"}


def scenario_info(scenario_id: str) -> dict[str, Any]:
    info = SCENARIOS.get(scenario_id, {"label": scenario_id, "mitre": []})
    return {"id": scenario_id, "label": info["label"], "mitre": list(info["mitre"])}


def heuristic_scenario(deviations: list[dict[str, Any]]) -> dict[str, Any]:
    """Name the scenario from the features that exceed the baseline (no labelled data needed).

    Evidence per scenario is the sum of log2 ratios of its deviating features. A
    remote logon / brute force followed by post-exploitation on the same host in
    the same window is reported as the RDP compromise chain.
    """
    evidence: dict[str, float] = {}
    for item in deviations:
        scenario = FEATURE_SCENARIO.get(item["feature"])
        if scenario:
            evidence[scenario] = evidence.get(scenario, 0.0) + math.log2(max(float(item["ratio"]), 1.0))
    if not evidence:
        return {**scenario_info(UNKNOWN), "confidence": 0.0, "source": "heuristic", "chain": []}

    chain = sorted(evidence, key=evidence.get, reverse=True)
    best = chain[0]
    if evidence.keys() & IDENTITY and evidence.keys() & POST_EXPLOITATION:
        best = "rdp_compromise"
    info = scenario_info(best)
    info["mitre"] = sorted({m for s in chain for m in SCENARIOS.get(s, {}).get("mitre", [])})
    total = sum(evidence.values())
    return {**info, "confidence": round(evidence.get(best, total) / total if total else 0.0, 4),
            "source": "heuristic", "chain": chain}


# ---------------------------------------------------------------- classifier

def scenario_model_path() -> Path:
    return Path(os.environ.get("XDR_AI_SCENARIO_MODEL_PATH", DEFAULT_SCENARIO_MODEL_PATH))


def _matrix(rows: list[dict[str, float]], names: list[str]) -> np.ndarray:
    return np.log1p(np.clip(np.array([[float(r.get(n, 0.0)) for n in names] for r in rows]), 0, None))


def train_scenario_model(rows: list[dict[str, float]], labels: list[str], min_confidence: float = 0.6,
                         random_state: int = 42) -> dict[str, Any]:
    classes = sorted(set(labels))
    if len(classes) < 2:
        raise ValueError("Need at least two classes (benign + one attack scenario)")
    model = RandomForestClassifier(n_estimators=300, class_weight="balanced", min_samples_leaf=1,
                                   random_state=random_state, n_jobs=-1)
    model.fit(_matrix(rows, FEATURE_NAMES), labels)
    trained_at = datetime.now(timezone.utc)
    importance = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda x: x[1], reverse=True)
    return {
        "model": model,
        "algorithm": "RandomForestClassifier",
        "version": "rf-" + trained_at.strftime("%Y%m%d%H%M%S"),
        "trained_at": trained_at.isoformat(),
        "feature_names": list(FEATURE_NAMES),
        "classes": [str(c) for c in model.classes_],
        "class_counts": {c: labels.count(c) for c in classes},
        "min_confidence": min_confidence,
        "feature_importance": {name: round(float(v), 4) for name, v in importance[:10]},
    }


class ScenarioClassifier:
    def __init__(self, bundle: dict[str, Any]):
        self.bundle = bundle
        self.model = bundle["model"]
        self.version = bundle["version"]
        self.feature_names = bundle["feature_names"]
        self.min_confidence = float(bundle.get("min_confidence", 0.6))

    @classmethod
    def load(cls, path: Path | None = None) -> "ScenarioClassifier | None":
        path = path or scenario_model_path()
        return cls(joblib.load(path)) if path.exists() else None

    def predict_many(self, rows: list[dict[str, float]]) -> list[dict[str, Any]]:
        if not rows:
            return []
        probabilities = self.model.predict_proba(_matrix(rows, self.feature_names))
        classes = [str(c) for c in self.model.classes_]
        results = []
        for row_probs in probabilities:
            order = np.argsort(row_probs)[::-1]
            best = classes[order[0]]
            results.append({
                **scenario_info(best),
                "confidence": round(float(row_probs[order[0]]), 4),
                "source": "classifier",
                "model_version": self.version,
                "probabilities": {classes[i]: round(float(row_probs[i]), 4) for i in order[:3]},
                "is_attack": best != BENIGN and float(row_probs[order[0]]) >= self.min_confidence,
            })
        return results


# ---------------------------------------------------------------- labelled runs

def load_runs(path: str | Path) -> list[dict[str, Any]]:
    """Read the attack-runs CSV: scenario,start,end[,host][,run_id] with UTC ISO times."""
    runs = []
    with open(path, newline="", encoding="utf-8-sig") as handle:
        for index, row in enumerate(csv.DictReader(handle), start=1):
            row = {str(k).strip().lower(): (v or "").strip() for k, v in row.items() if k}
            if not row.get("scenario") or row["scenario"].startswith("#"):
                continue
            start, end = parse_timestamp(row.get("start")), parse_timestamp(row.get("end"))
            if start is None or end is None or end <= start:
                raise ValueError(f"Row {index}: invalid start/end ({row.get('start')!r}, {row.get('end')!r})")
            runs.append({"run_id": row.get("run_id") or f"run{index}", "scenario": row["scenario"],
                         "start": start, "end": end, "host": row.get("host") or None})
    return runs


def window_overlaps(window_start: datetime, start: datetime, end: datetime,
                    window_seconds: int = WINDOW_SECONDS) -> bool:
    return window_start < end and window_start + timedelta(seconds=window_seconds) > start


def overlap_seconds(window_start: datetime, start: datetime, end: datetime,
                    window_seconds: int = WINDOW_SECONDS) -> float:
    window_end = window_start + timedelta(seconds=window_seconds)
    return max(0.0, (min(window_end, end) - max(window_start, start)).total_seconds())


def label_windows(windows: dict[tuple[str, datetime], list[dict[str, Any]]], runs: list[dict[str, Any]],
                  window_seconds: int = WINDOW_SECONDS,
                  min_overlap_seconds: float = 60) -> dict[tuple[str, datetime], dict[str, Any]]:
    """Attack label (scenario + run) for windows of the target host that cover a run.

    A window that only touches the last seconds of a run holds almost no attack
    activity; labelling it as an attack would teach the model noise. Short runs
    still label the window that contains them.
    """
    labelled: dict[tuple[str, datetime], dict[str, Any]] = {}
    for run in runs:
        needed = min(min_overlap_seconds, (run["end"] - run["start"]).total_seconds())
        for key in windows:
            host, start = key
            if (run["host"] is None or run["host"].lower() == host.lower()) \
                    and overlap_seconds(start, run["start"], run["end"], window_seconds) >= needed:
                labelled[key] = run
    return labelled


def near_any_run(window_start: datetime, runs: list[dict[str, Any]], margin: timedelta) -> bool:
    return any(window_overlaps(window_start, run["start"] - margin, run["end"] + margin) for run in runs)
