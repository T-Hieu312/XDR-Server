import json
import re
from pathlib import Path
from typing import Any

RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "detection_rules.json"
OPERATORS = {
    "equals",
    "contains",
    "contains_any",
    "endswith",
    "endswith_any",
    "exists",
    "lte",
    "regex",
    "startswith_any",
}


def load_default_rules() -> list[dict[str, Any]]:
    return load_rules(RULES_PATH)


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as rules_file:
        rules = json.load(rules_file)
    if not isinstance(rules, list):
        raise ValueError("Detection rules must be a JSON list")
    return rules


def _field(raw: dict[str, Any], path: str) -> Any:
    """Resolve ``data.CommandLine`` style paths inside the raw event."""
    value: Any = raw
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _condition_matches(value: Any, expected: Any) -> bool:
    if not isinstance(expected, dict):
        return value == expected  # backwards compatible exact match
    unknown = set(expected) - OPERATORS
    if unknown:
        raise ValueError(f"Unknown rule operators: {sorted(unknown)}")
    for operator, operand in expected.items():
        if operator == "exists":
            exists = value is not None and value != ""
            if exists is not bool(operand):
                return False
            continue
        if value is None:
            return False
        text = str(value)
        folded = text.casefold()
        values = [str(item) for item in _as_list(operand)]
        if operator == "equals" and folded not in {item.casefold() for item in values}:
            return False
        if operator in {"contains", "contains_any"}:
            needles = [str(item) for item in _as_list(operand)] if operator == "contains_any" else values
            if not any(needle.casefold() in folded for needle in needles):
                return False
        if operator in {"endswith", "endswith_any"}:
            if not any(folded.endswith(item.casefold()) for item in values):
                return False
        if operator == "startswith_any" and not any(
            folded.startswith(item.casefold()) for item in values
        ):
            return False
        if operator == "regex" and re.search(str(operand), text, re.IGNORECASE) is None:
            return False
        if operator == "lte":
            try:
                if float(value) > float(operand):
                    return False
            except (TypeError, ValueError):
                return False
    return True


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def match_event(event: dict[str, Any], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return rules whose event_type matches and whose conditions all hold.

    Conditions map a raw field path to either a literal (exact match) or an
    operator object, e.g. ``{"data.CommandLine": {"contains_any": ["-enc"]}}``.
    """
    matches = []
    raw = event.get("raw") or {}
    for rule in rules:
        if event.get("event_type") != rule.get("event_type"):
            continue
        conditions = rule.get("conditions", {})
        if all(_condition_matches(_field(raw, key), expected) for key, expected in conditions.items()):
            matches.append(rule)
    return matches
