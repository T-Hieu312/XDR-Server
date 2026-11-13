from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from ai.datasets import iter_db_events, load_files
from ai.detector import MIN_TRAINING_WINDOWS, model_path, save_model, train_model
from ai.features import group_windows, window_features
from database.database import get_database_path


def alerted_event_ids(db_path: Path) -> set[str]:
    connection = sqlite3.connect(db_path)
    try:
        return {row[0] for row in connection.execute("SELECT DISTINCT event_id FROM alerts")}
    except sqlite3.OperationalError:
        return set()
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the XDR Isolation Forest on benign windows")
    parser.add_argument("--db", type=Path, help="XDR SQLite database (default: XDR_DATABASE_PATH)")
    parser.add_argument("--since", help="ISO start of the clean baseline period (inclusive)")
    parser.add_argument("--until", help="ISO end of the clean baseline period (exclusive)")
    parser.add_argument("--hosts", nargs="*", help="Only use these host_ids")
    parser.add_argument("--files", nargs="*", default=[], help="Extra benign JSON/JSONL/ZIP files")
    parser.add_argument("--keep-alerted", action="store_true",
                        help="Keep windows containing rule alerts (dropped by default)")
    parser.add_argument("--target-fpr", type=float, default=0.01,
                        help="Share of baseline windows allowed above the threshold (default 0.01)")
    parser.add_argument("--min-windows", type=int, default=MIN_TRAINING_WINDOWS)
    parser.add_argument("--out", type=Path, default=None, help="Model path (default: XDR_AI_MODEL_PATH)")
    args = parser.parse_args()

    events = load_files(args.files)
    db_path = args.db or (get_database_path() if not args.files else None)
    if db_path is not None:
        if not Path(db_path).exists():
            raise SystemExit(f"Database not found: {db_path}")
        events.extend(iter_db_events(db_path, args.since, args.until, args.hosts))
    if not events:
        raise SystemExit("No events found for training")

    windows = group_windows(events)
    dropped = 0
    if db_path is not None and not args.keep_alerted:
        alerted = alerted_event_ids(Path(db_path))
        clean = {}
        for key, window_events in windows.items():
            if any(str(event.get("event_id")) in alerted for event in window_events):
                dropped += 1
            else:
                clean[key] = window_events
        windows = clean

    rows = [window_features(window_events) for window_events in windows.values()]
    try:
        bundle = train_model(rows, target_fpr=args.target_fpr, min_windows=args.min_windows)
    except ValueError as error:
        raise SystemExit(f"Training aborted: {error}. Each window is 5 minutes of activity on one "
                         "host; keep the EDR agent running longer (Sysmon must be installed).") from error
    bundle["hosts"] = sorted({host for host, _ in windows})
    path = save_model(bundle, args.out or model_path())

    print("=== AI MODEL TRAINED ===")
    print(json.dumps({
        "model_path": str(path),
        "version": bundle["version"],
        "events": len(events),
        "training_windows": bundle["training_windows"],
        "dropped_alerted_windows": dropped,
        "hosts": bundle["hosts"],
        "target_fpr": bundle["target_fpr"],
        "forest_threshold": round(bundle["threshold"], 4),
        "novelty_threshold": round(bundle["novelty_threshold"], 4),
        "constant_features": bundle["constant_features"],
    }, indent=2))
    if len(bundle["constant_features"]) > len(bundle["feature_names"]) // 2:
        print("WARNING: more than half of the features never vary in the baseline. "
              "Check that Sysmon is installed and collect a longer, more varied baseline.")


if __name__ == "__main__":
    main()
