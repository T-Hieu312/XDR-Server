import json
from pathlib import Path
from typing import Any

IOC_PATH = Path(__file__).resolve().parents[2] / "rules" / "ioc.json"


def load_iocs(path: str | Path = IOC_PATH) -> dict[str, set[str]]:
    with Path(path).open(encoding="utf-8") as ioc_file:
        iocs = json.load(ioc_file)
    if not isinstance(iocs, dict):
        raise ValueError("IOC data must be a JSON object")
    return {
        kind: {str(value).strip().lower() for value in iocs.get(kind, []) if str(value).strip()}
        for kind in ("ips", "domains", "file_hashes")
    }


def find_ip_match(ip: str, iocs: dict[str, Any]) -> bool:
    return str(ip).strip().lower() in {str(value).lower() for value in iocs.get("ips", [])}


def _domain_matches(domain: str, known: set[str]) -> str | None:
    labels = domain.lower().strip(".").split(".")
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        if candidate in known:
            return candidate
    return None


def _hashes(value: Any) -> list[str]:
    # Sysmon format: "SHA256=ABC...,MD5=DEF...,IMPHASH=..."
    return [part.split("=", 1)[-1].strip().lower() for part in str(value or "").split(",") if part.strip()]


def match_iocs(event: dict[str, Any], iocs: dict[str, set[str]]) -> list[dict[str, Any]]:
    """Return rule-like matches so IOC hits flow through the normal alert path."""
    raw = event.get("raw") or {}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    found: list[tuple[str, str]] = []

    for ip in (data.get("DestinationIp"), raw.get("dest_ip"), raw.get("src_ip")):
        if ip and str(ip).lower() in iocs["ips"]:
            found.append(("ip", str(ip)))
    domain = data.get("QueryName") or data.get("DestinationHostname")
    if domain and (matched := _domain_matches(str(domain), iocs["domains"])):
        found.append(("domain", matched))
    for file_hash in _hashes(data.get("Hashes")):
        if file_hash in iocs["file_hashes"]:
            found.append(("hash", file_hash))

    return [
        {
            "id": f"ioc-{kind}",
            "name": f"IOC match ({kind}): {value}",
            "severity": "high",
            "confidence": 0.95,
            "mitre_attack": [],
        }
        for kind, value in dict.fromkeys(found)
    ]
