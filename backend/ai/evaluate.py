"""Evaluate the AI model on labelled benign and attack data.

Every host/5-minute window built from ``--benign`` sources is labelled 0 and
every window from ``--attack`` sources is labelled 1. Use benign data that was
NOT used for training (e.g. train on days 1-5, evaluate on days 6-7).

    python -m ai.evaluate --benign-db data/xdr.sqlite3 --since 2026-11-06 --until 2026-11-08 \
        --attack ../datasets/otrf/*.zip --report data/ai_evaluation.json

    # attacks run in the lab and collected by the EDR agent (UTC times you wrote down)
    python -m ai.evaluate --benign-db data/xdr.sqlite3 --since 2026-11-16 --until 2026-11-17 \
        --attack-range 2026-11-17T03:00 2026-11-17T03:10 --attack-hosts WIN10-01
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sklearn.metrics import average_precision_score, roc_auc_score

from ai.datasets import iter_db_events, load_file
from ai.detector import AnomalyDetector, model_path
from ai.features import group_windows, window_features


def score_windows(detector: AnomalyDetector, events: list[dict[str, Any]], label: int,
                  source: str, hosts: list[str] | None = None) -> list[dict[str, Any]]:
    windows = group_windows(events)
    keys = [key for key in windows if not hosts or key[0] in hosts]
    rows = [window_features(windows[key]) for key in keys]
    return [
        {"label": label, "source": source, "host_id": host, "window_start": start.isoformat(),
         "event_count": len(windows[(host, start)]), **result}
        for (host, start), result in zip(keys, detector.score_many(rows))
    ]


def metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(1 for r in results if r["label"] == 1 and r["is_anomaly"])
    fn = sum(1 for r in results if r["label"] == 1 and not r["is_anomaly"])
    fp = sum(1 for r in results if r["label"] == 0 and r["is_anomaly"])
    tn = sum(1 for r in results if r["label"] == 0 and not r["is_anomaly"])
    attacks = [r for r in results if r["label"] == 1]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    report: dict[str, Any] = {
        "windows": len(results), "attack_windows": tp + fn, "benign_windows": fp + tn,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        # Which part of the hybrid model caught the attack windows (ablation view).
        "attack_detected_by": {
            "isolation_forest": sum(1 for r in attacks if r["forest"]["anomaly"]),
            "novelty": sum(1 for r in attacks if r["novelty"]["anomaly"]),
            "both": sum(1 for r in attacks if r["forest"]["anomaly"] and r["novelty"]["anomaly"]),
        },
    }
    labels = [r["label"] for r in results]
    if len(set(labels)) == 2:
        scores = [r["anomaly_rank"] for r in results]
        report["roc_auc"] = round(roc_auc_score(labels, scores), 4)
        report["pr_auc"] = round(average_precision_score(labels, scores), 4)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the XDR AI model")
    parser.add_argument("--model", type=Path, default=None)
    parser.add_argument("--benign", nargs="*", default=[], help="Benign JSON/JSONL/ZIP files")
    parser.add_argument("--benign-db", type=Path, help="XDR SQLite database with benign events")
    parser.add_argument("--since", help="ISO start for --benign-db")
    parser.add_argument("--until", help="ISO end for --benign-db")
    parser.add_argument("--attack", nargs="*", default=[], help="Attack JSON/JSONL/ZIP files (e.g. OTRF)")
    parser.add_argument("--attack-db", type=Path,
                        help="Database holding attack runs (default: --benign-db)")
    parser.add_argument("--attack-range", nargs=2, action="append", default=[], metavar=("START", "END"),
                        help="UTC time range of an attack run in the database; repeat for several runs")
    parser.add_argument("--attack-hosts", nargs="*", help="Only label windows of these hosts as attack")
    parser.add_argument("--report", type=Path, help="Write the full JSON report here")
    args = parser.parse_args()

    detector = AnomalyDetector.load(args.model or model_path())
    if detector is None:
        raise SystemExit("Model not found; run python -m ai.train first")

    results: list[dict[str, Any]] = []
    for path in args.benign:
        results += score_windows(detector, load_file(path), 0, Path(path).name)
    if args.benign_db:
        results += score_windows(detector, list(iter_db_events(args.benign_db, args.since, args.until)),
                                 0, "database")
    for path in args.attack:
        results += score_windows(detector, load_file(path), 1, Path(path).name, args.attack_hosts)
    attack_db = args.attack_db or args.benign_db
    if args.attack_range and not attack_db:
        raise SystemExit("--attack-range needs --attack-db or --benign-db")
    for start, end in args.attack_range:
        results += score_windows(detector, list(iter_db_events(attack_db, start, end)), 1,
                                 f"database {start}..{end}", args.attack_hosts)
    if not results:
        raise SystemExit("No windows to evaluate; pass --benign/--benign-db and/or --attack")

    report = {"model_version": detector.version, **metrics(results)}
    print(json.dumps(report, indent=2))

    print("\nAttack windows:")
    for r in (r for r in results if r["label"] == 1):
        top = ", ".join(f"{t['feature']}={t['value']:g}" for t in r["top_features"]) or "-"
        print(f"  {'DETECTED' if r['is_anomaly'] else 'missed  '} ai={r['ai_score']:.2f} "
              f"{r['host_id']} {r['window_start']} events={r['event_count']} [{top}]")

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({"summary": report, "windows": results}, indent=2), encoding="utf-8")
        print(f"\nReport written to {args.report}")


if __name__ == "__main__":
    main()
