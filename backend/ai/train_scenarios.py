from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import joblib
from sklearn.metrics import classification_report, confusion_matrix

from ai.datasets import iter_db_events
from ai.features import WINDOW_SECONDS, group_windows, parse_timestamp, window_features
from ai.scenarios import (BENIGN, load_runs, label_windows, near_any_run, scenario_model_path,
                          train_scenario_model)
from database.database import get_database_path


def _load_events(db_paths: list[Path], ranges: list[tuple[Any, Any]]) -> list[dict[str, Any]]:
    events: dict[str, dict[str, Any]] = {}
    pad = timedelta(seconds=WINDOW_SECONDS)
    for db_path in db_paths:
        for start, end in ranges:
            since = (start - pad).isoformat()[:19]
            until = (end + pad).isoformat()[:19]
            for event in iter_db_events(db_path, since, until):
                events[str(event["event_id"])] = event
    return list(events.values())


def split_holdout(samples: list[dict[str, Any]], test_ratio: float) -> tuple[list, list]:
    """Hold out whole attack runs (never single windows of a run) and the latest benign windows."""
    train, test = [], []
    step = max(2, round(1 / test_ratio)) if test_ratio > 0 else 0
    by_scenario: dict[str, list[str]] = {}
    for sample in samples:
        if sample["label"] != BENIGN:
            runs = by_scenario.setdefault(sample["label"], [])
            if sample["group"] not in runs:
                runs.append(sample["group"])
    test_runs = set()
    for runs in by_scenario.values():
        runs.sort()
        if step and len(runs) >= 2:
            chosen = [run for i, run in enumerate(runs) if (i + 1) % step == 0] or [runs[-1]]
            test_runs.update(chosen)
    benign = sorted((s for s in samples if s["label"] == BENIGN), key=lambda s: s["window_start"])
    cut = len(benign) - int(round(len(benign) * test_ratio))
    benign_test = {id(s) for s in benign[cut:]}
    for sample in samples:
        is_test = sample["group"] in test_runs if sample["label"] != BENIGN else id(sample) in benign_test
        (test if is_test else train).append(sample)
    return train, test


def holdout_report(train: list[dict[str, Any]], test: list[dict[str, Any]],
                   min_confidence: float) -> dict[str, Any]:
    if not test or len({s["label"] for s in train}) < 2:
        return {"note": "not enough runs for a hold-out evaluation"}
    bundle = train_scenario_model([s["features"] for s in train], [s["label"] for s in train], min_confidence)
    model = bundle["model"]
    from ai.scenarios import _matrix  # same transform as at inference

    probabilities = model.predict_proba(_matrix([s["features"] for s in test], bundle["feature_names"]))
    classes = [str(c) for c in model.classes_]
    predicted = []
    for probs in probabilities:
        best = classes[int(probs.argmax())]
        predicted.append(best if best == BENIGN or probs.max() >= min_confidence else BENIGN)
    truth = [s["label"] for s in test]
    labels = sorted(set(truth) | set(predicted))
    attack_truth = [t != BENIGN for t in truth]
    attack_pred = [p != BENIGN for p in predicted]
    tp = sum(t and p for t, p in zip(attack_truth, attack_pred))
    fp = sum(p and not t for t, p in zip(attack_truth, attack_pred))
    fn = sum(t and not p for t, p in zip(attack_truth, attack_pred))
    tn = sum(not t and not p for t, p in zip(attack_truth, attack_pred))
    return {
        "test_windows": len(test),
        "test_runs": sorted({s["group"] for s in test if s["label"] != BENIGN}),
        "per_scenario": classification_report(truth, predicted, labels=labels, output_dict=True, zero_division=0),
        "confusion_matrix": {"labels": labels, "matrix": confusion_matrix(truth, predicted, labels=labels).tolist()},
        "attack_vs_benign": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                             "recall": round(tp / (tp + fn), 4) if tp + fn else None,
                             "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the scenario classifier from labelled lab attack runs")
    parser.add_argument("--db", type=Path, nargs="*", default=None, help="XDR databases (default: XDR_DATABASE_PATH)")
    parser.add_argument("--runs", type=Path, required=True, help="CSV: scenario,start,end[,host][,run_id] (UTC)")
    parser.add_argument("--benign-range", nargs=2, action="append", default=[], metavar=("START", "END"),
                        required=True, help="UTC range of normal activity; repeat for several")
    parser.add_argument("--margin-minutes", type=int, default=10,
                        help="Benign windows this close to an attack run are not used (default 10)")
    parser.add_argument("--test-ratio", type=float, default=0.3, help="Share of runs held out for evaluation")
    parser.add_argument("--min-confidence", type=float, default=0.6)
    parser.add_argument("--out", type=Path, default=None, help="Model path (default: XDR_AI_SCENARIO_MODEL_PATH)")
    parser.add_argument("--report", type=Path, help="Write the JSON report here")
    args = parser.parse_args()

    runs = load_runs(args.runs)
    if not runs:
        raise SystemExit(f"No attack runs in {args.runs}")
    benign_ranges = []
    for start, end in args.benign_range:
        parsed = (parse_timestamp(start), parse_timestamp(end))
        if None in parsed:
            raise SystemExit(f"Invalid --benign-range {start} {end}")
        benign_ranges.append(parsed)

    db_paths = args.db or [get_database_path()]
    for db_path in db_paths:
        if not Path(db_path).exists():
            raise SystemExit(f"Database not found: {db_path}")
    events = _load_events(db_paths, [(r["start"], r["end"]) for r in runs] + benign_ranges)
    windows = group_windows(events)
    attack_labels = label_windows(windows, runs)
    margin = timedelta(minutes=args.margin_minutes)

    samples = []
    for key, window_events in windows.items():
        host, start = key
        if key in attack_labels:
            run = attack_labels[key]
            samples.append({"label": run["scenario"], "group": run["run_id"], "host": host,
                            "window_start": start, "features": window_features(window_events)})
        elif any(b0 <= start < b1 for b0, b1 in benign_ranges) and not near_any_run(start, runs, margin):
            samples.append({"label": BENIGN, "group": "benign", "host": host,
                            "window_start": start, "features": window_features(window_events)})

    counts: dict[str, int] = {}
    for sample in samples:
        counts[sample["label"]] = counts.get(sample["label"], 0) + 1
    runs_per_scenario: dict[str, int] = {}
    for run in runs:
        runs_per_scenario[run["scenario"]] = runs_per_scenario.get(run["scenario"], 0) + 1
    missing = [r["run_id"] for r in runs if not any(lab is r for lab in attack_labels.values())]

    train, test = split_holdout(samples, args.test_ratio)
    evaluation = holdout_report(train, test, args.min_confidence)
    try:
        bundle = train_scenario_model([s["features"] for s in samples], [s["label"] for s in samples],
                                      args.min_confidence)
    except ValueError as error:
        raise SystemExit(f"Training aborted: {error}. Windows per label: {counts}") from error
    bundle["runs_per_scenario"] = runs_per_scenario
    bundle["holdout"] = evaluation
    path = args.out or scenario_model_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)

    summary = {
        "model_path": str(path), "version": bundle["version"], "windows_per_label": counts,
        "runs_per_scenario": runs_per_scenario, "runs_without_windows": missing,
        "holdout": {k: v for k, v in evaluation.items() if k != "per_scenario"},
        "holdout_per_scenario": {label: {m: round(v, 4) for m, v in stats.items()}
                                 for label, stats in evaluation.get("per_scenario", {}).items()
                                 if isinstance(stats, dict)},
        "top_features": bundle["feature_importance"],
    }
    print("=== SCENARIO MODEL TRAINED ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if missing:
        print(f"WARNING: no windows found for runs {missing}: check the times (UTC) and host names.")
    few = [s for s, n in runs_per_scenario.items() if n < 5]
    if few:
        print(f"WARNING: fewer than 5 runs for {few}; results will not be reliable.")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(summary, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
