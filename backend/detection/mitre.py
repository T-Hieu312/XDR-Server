from typing import Any


def techniques_for_rule(rule: dict[str, Any]) -> list[str]:
    techniques = rule.get("mitre_attack", [])
    return [str(technique) for technique in techniques]