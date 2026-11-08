import json
from pathlib import Path
from typing import Any


def load_iocs(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as ioc_file:
        iocs = json.load(ioc_file)
    if not isinstance(iocs, dict):
        raise ValueError("IOC data must be a JSON object")
    return iocs


def find_ip_match(ip: str, iocs: dict[str, Any]) -> bool:
    return ip in iocs.get("ips", [])