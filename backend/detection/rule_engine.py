import json
from pathlib import Path
from typing import Any

RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "detection_rules.json"


def load_default_rules() -> list[dict[str, Any]]:
    return load_rules(RULES_PATH)


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as rules_file:
        rules = json.load(rules_file)
    if not isinstance(rules, list):
        raise ValueError("Detection rules must be a JSON list")
    return rules


def match_event(event: dict[str, Any], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches = []
    for rule in rules:
        if event.get("event_type") != rule.get("event_type"):
            continue
        conditions = rule.get("conditions", {})
        raw = event.get("raw", {})
        if all(raw.get(key) == value for key, value in conditions.items()):
            matches.append(rule)
    return matches
