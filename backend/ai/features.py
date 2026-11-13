from __future__ import annotations

import ipaddress
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

WINDOW_SECONDS = 300

FEATURE_NAMES = [
    # process behaviour (Sysmon 1)
    "process_count",
    "unique_process_images",
    "shell_process_count",
    "lolbin_process_count",
    "suspicious_cmdline_count",
    "max_cmdline_length",
    "user_writable_exec_count",
    "office_spawn_count",
    # network behaviour (Sysmon 3)
    "network_connect_count",
    "unique_dst_ip",
    "unique_dst_port",
    "external_connection_count",
    # DNS behaviour (Sysmon 22)
    "dns_query_count",
    "unique_domains",
    "max_domain_entropy",
    # file / registry / credential access (Sysmon 11, 13, 10)
    "file_create_count",
    "executable_file_create_count",
    "registry_set_count",
    "persistence_registry_count",
    "lsass_access_count",
    # identity (Wazuh authentication failures)
    "auth_failure_count",
]

SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "powershell_ise.exe"}
LOLBINS = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "schtasks.exe", "cscript.exe", "wscript.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "csc.exe", "forfiles.exe",
}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe"}
SUSPICIOUS_CMDLINE = re.compile(
    r"(?i)(\s-e(nc|ncodedcommand)?\s|frombase64string|downloadstring|downloadfile|"
    r"invoke-webrequest|\biwr\b|invoke-expression|\biex\b|-w(indowstyle)?\s+hidden|"
    r"-exec(utionpolicy)?\s+bypass|-urlcache|/transfer|https?://|-nop\b)"
)
USER_WRITABLE_DIRS = ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\", "\\programdata\\")
EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr", ".jse")
PERSISTENCE_KEYS = ("\\currentversion\\run", "\\services\\", "\\winlogon\\", "\\image file execution options\\")


def parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    text = str(value).strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Windows SystemTime carries 7 fractional digits; Python accepts at most 6.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def window_start(timestamp: datetime, window_seconds: int = WINDOW_SECONDS) -> datetime:
    epoch = int(timestamp.timestamp())
    return datetime.fromtimestamp(epoch - epoch % window_seconds, tz=timezone.utc)


def group_windows(
    events: Iterable[dict[str, Any]], window_seconds: int = WINDOW_SECONDS
) -> dict[tuple[str, datetime], list[dict[str, Any]]]:
    """Group events by (host_id, window start). Events without a timestamp are skipped."""
    windows: dict[tuple[str, datetime], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        timestamp = parse_timestamp(event.get("timestamp"))
        if timestamp is None:
            continue
        host = str(event.get("host_id") or "unknown")
        windows[(host, window_start(timestamp, window_seconds))].append(event)
    return dict(windows)


def _data(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("raw")
    if not isinstance(raw, dict):
        return {}
    data = raw.get("data")
    return data if isinstance(data, dict) else raw


def _basename(path: Any) -> str:
    return str(path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _is_external_ip(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = defaultdict(int)
    for char in text:
        counts[char] += 1
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def window_features(events: Iterable[dict[str, Any]]) -> dict[str, float]:
    """Compute the fixed feature vector for one host/window."""
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    images: set[str] = set()
    dst_ips: set[str] = set()
    dst_ports: set[str] = set()
    domains: set[str] = set()

    for event in events:
        event_type = str(event.get("event_type") or "").lower()
        data = _data(event)

        if event_type == "process_create":
            image = str(data.get("Image") or "").replace("/", "\\").lower()
            name = _basename(image)
            command_line = str(data.get("CommandLine") or "")
            f["process_count"] += 1
            if image:
                images.add(image)
            if name in SHELLS:
                f["shell_process_count"] += 1
            if name in LOLBINS:
                f["lolbin_process_count"] += 1
            if SUSPICIOUS_CMDLINE.search(f" {command_line} "):
                f["suspicious_cmdline_count"] += 1
            f["max_cmdline_length"] = max(f["max_cmdline_length"], float(len(command_line)))
            if any(directory in image for directory in USER_WRITABLE_DIRS):
                f["user_writable_exec_count"] += 1
            if _basename(data.get("ParentImage")) in OFFICE_PARENTS:
                f["office_spawn_count"] += 1

        elif event_type == "network_connect":
            f["network_connect_count"] += 1
            destination = data.get("DestinationIp")
            if destination:
                dst_ips.add(str(destination))
                if _is_external_ip(destination):
                    f["external_connection_count"] += 1
            if data.get("DestinationPort"):
                dst_ports.add(str(data["DestinationPort"]))

        elif event_type == "dns_query":
            f["dns_query_count"] += 1
            domain = str(data.get("QueryName") or "").lower().strip(".")
            if domain:
                domains.add(domain)
                f["max_domain_entropy"] = max(f["max_domain_entropy"], _entropy(domain.split(".")[0]))

        elif event_type == "file_create":
            f["file_create_count"] += 1
            if str(data.get("TargetFilename") or "").lower().endswith(EXECUTABLE_EXTENSIONS):
                f["executable_file_create_count"] += 1

        elif event_type == "registry_set":
            f["registry_set_count"] += 1
            if any(key in str(data.get("TargetObject") or "").lower() for key in PERSISTENCE_KEYS):
                f["persistence_registry_count"] += 1

        elif event_type == "process_access":
            if _basename(data.get("TargetImage")) == "lsass.exe":
                f["lsass_access_count"] += 1

        elif event_type == "authentication_failure":
            f["auth_failure_count"] += 1

    f["unique_process_images"] = float(len(images))
    f["unique_dst_ip"] = float(len(dst_ips))
    f["unique_dst_port"] = float(len(dst_ports))
    f["unique_domains"] = float(len(domains))
    f["max_domain_entropy"] = round(f["max_domain_entropy"], 4)
    return f
