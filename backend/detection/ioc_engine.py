import ipaddress
import json
import re
from pathlib import Path
from typing import Any

IOC_PATH = Path(__file__).resolve().parents[2] / "rules" / "ioc.json"
HASH_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])")
DOMAIN_RE = re.compile(r"(?i)(?<![a-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?")
IP_TOKEN_RE = re.compile(r"(?<![0-9a-f:.])[0-9a-f:.]{3,}(?![0-9a-f:.])", re.IGNORECASE)


def load_iocs(path: str | Path = IOC_PATH) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as ioc_file:
        iocs = json.load(ioc_file)
    if not isinstance(iocs, dict):
        raise ValueError("IOC data must be a JSON object")
    for category in ("ips", "domains", "file_hashes"):
        values = iocs.get(category, [])
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError(f"IOC field {category} must be a list of strings")
    return iocs


def find_ip_match(ip: str, iocs: dict[str, Any]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for indicator in iocs.get("ips", []):
        try:
            if address in ipaddress.ip_network(indicator, strict=False):
                return True
        except ValueError:
            continue
    return False


def _string_values(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _string_values(child)
    elif isinstance(value, str):
        yield value


def match_iocs(event: dict[str, Any], iocs: dict[str, Any]) -> list[dict[str, Any]]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    text_values = list(_string_values(raw))
    text = "\n".join(text_values)
    matches: dict[tuple[str, str], dict[str, Any]] = {}

    ip_indicators = set()
    for token in IP_TOKEN_RE.findall(text):
        try:
            normalized_ip = str(ipaddress.ip_address(token))
        except ValueError:
            continue
        if find_ip_match(normalized_ip, iocs):
            ip_indicators.add(normalized_ip)
    for indicator in sorted(ip_indicators):
        matches[("ip", indicator)] = _ioc_rule("ip", indicator)

    known_domains = {value.casefold().rstrip(".") for value in iocs.get("domains", [])}
    matched_domains = set()
    for token in DOMAIN_RE.findall(text):
        domain = token.casefold().rstrip(".")
        for known in known_domains:
            if domain == known or domain.endswith("." + known):
                matched_domains.add(known)
    for indicator in sorted(matched_domains):
        matches[("domain", indicator)] = _ioc_rule("domain", indicator)

    known_hashes = {value.casefold() for value in iocs.get("file_hashes", [])}
    matched_hashes = {value.casefold() for value in HASH_RE.findall(text) if value.casefold() in known_hashes}
    for indicator in sorted(matched_hashes):
        matches[("hash", indicator)] = _ioc_rule("hash", indicator)
    return list(matches.values())


def _ioc_rule(kind: str, indicator: str) -> dict[str, Any]:
    return {
        "id": f"ioc-{kind}-{indicator}",
        "name": f"Known malicious {kind} indicator matched: {indicator}",
        "severity": "high",
        "confidence": 0.95,
        "mitre_attack": [],
    }
