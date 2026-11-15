import json
import re
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
        if all(_matches_condition(_get_path(raw, key), expected) for key, expected in conditions.items()):
            matches.append(rule)
    return matches


def _get_path(value: Any, path: str) -> Any:
    """Resolve a dot-separated path inside the normalized event's raw payload."""
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _matches_condition(actual: Any, expected: Any) -> bool:
    # Scalar conditions retain exact-match behavior for existing rules.
    if not isinstance(expected, dict):
        return actual == expected
    original_actual = actual
    if not isinstance(actual, str):
        actual = "" if actual is None else str(actual)
    folded = actual.casefold()
    for operator, operand in expected.items():
        if operator == "exists":
            exists = original_actual is not None and original_actual != ""
            if exists is not bool(operand):
                return False
        if operator == "contains" and str(operand).casefold() not in folded:
            return False
        if operator == "contains_any" and not any(str(item).casefold() in folded for item in operand):
            return False
        if operator == "endswith" and not folded.endswith(str(operand).casefold()):
            return False
        if operator == "regex" and re.search(str(operand), actual, re.IGNORECASE) is None:
            return False
        if operator == "lte":
            try:
                if float(original_actual) > float(operand):
                    return False
            except (TypeError, ValueError):
                return False
        if operator not in {"contains", "contains_any", "endswith", "regex", "exists", "lte"}:
            raise ValueError(f"Unsupported detection rule operator: {operator}")
    return True
