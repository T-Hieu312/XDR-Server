import json
from pathlib import Path
from typing import Any

RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "detection_rules.json"
OPERATORS = {"equals", "contains_any", "endswith_any", "startswith_any"}


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
    if value is None:
        return False
    text = str(value).lower()
    checks = {
        "equals": lambda needles: text in {str(n).lower() for n in _as_list(needles)},
        "contains_any": lambda needles: any(str(n).lower() in text for n in _as_list(needles)),
        "endswith_any": lambda needles: text.endswith(tuple(str(n).lower() for n in _as_list(needles))),
        "startswith_any": lambda needles: text.startswith(tuple(str(n).lower() for n in _as_list(needles))),
    }
    return all(checks[operator](needles) for operator, needles in expected.items())


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
