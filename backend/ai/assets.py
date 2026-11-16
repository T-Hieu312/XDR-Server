from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any

DEFAULT_ASSETS_PATH = Path(__file__).resolve().parents[2] / "rules" / "assets.json"
DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def assets_path() -> Path:
    return Path(os.environ.get("XDR_AI_ASSETS_PATH", str(DEFAULT_ASSETS_PATH)))


def _networks(values: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [ipaddress.ip_network(value, strict=False) for value in values]


def _ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


class AssetMap:
    """Maps every event to the internal machine it is about.

    EDR events already name their host. Wazuh alerts name a Wazuh agent, which
    may differ from the Windows hostname. Suricata alerts only carry IPs, so the
    internal, trusted side of the flow (normally the victim) becomes the host and
    the other side is kept as the peer (normally the attacker).
    """

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.internal = _networks(config.get("internal_networks") or DEFAULT_INTERNAL)
        # Networks that are never a monitored asset (e.g. the attacker VLAN of the lab).
        self.untrusted = _networks(config.get("untrusted_networks") or [])
        self.by_alias: dict[str, str] = {}
        self.by_ip: dict[str, str] = {}
        self.hosts: list[dict[str, Any]] = []
        for host in config.get("hosts") or []:
            host_id = str(host["host_id"])
            self.hosts.append(host)
            for alias in [host_id, *(host.get("aliases") or [])]:
                self.by_alias[str(alias).lower()] = host_id
            for ip in host.get("ips") or []:
                self.by_ip[str(ip)] = host_id

    @classmethod
    def load(cls, path: Path | None = None) -> "AssetMap":
        path = path or assets_path()
        if not path.exists():
            return cls()
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def canonical(self, name: Any) -> str:
        text = str(name or "").strip()
        return self.by_alias.get(text.lower(), text) or "unknown"

    def is_monitored_ip(self, value: Any) -> bool:
        ip = _ip(value)
        if ip is None:
            return False
        if str(ip) in self.by_ip:
            return True
        return any(ip in net for net in self.internal) and not any(ip in net for net in self.untrusted)

    def resolve(self, event: dict[str, Any]) -> tuple[str, str | None] | None:
        """Return (host, peer_ip) for an event, or None when it concerns no monitored asset."""
        source = str(event.get("source") or "").lower()
        raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}

        if source == "suricata":
            if str(event.get("event_type")) != "network_alert":
                return None  # flow/http/dns metadata: only IDS alerts are behavioural signals
            src, dst = raw.get("src_ip"), raw.get("dest_ip")
            for victim, peer in ((dst, src), (src, dst)):
                if self.is_monitored_ip(victim):
                    return self.by_ip.get(str(victim), str(victim)), (str(peer) if peer else None)
            return None

        if source == "wazuh":
            agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
            name = str(agent.get("name") or "").lower()
            if name in self.by_alias:
                return self.by_alias[name], None
            if str(agent.get("ip")) in self.by_ip:
                return self.by_ip[str(agent.get("ip"))], None

        return self.canonical(event.get("host_id")), None


_cache: tuple[tuple[str, float], AssetMap] | None = None


def get_assets() -> AssetMap:
    """Asset map from rules/assets.json, reloaded when the file changes."""
    global _cache
    path = assets_path()
    key = (str(path), path.stat().st_mtime if path.exists() else 0.0)
    if _cache is None or _cache[0] != key:
        _cache = (key, AssetMap.load(path))
    return _cache[1]
