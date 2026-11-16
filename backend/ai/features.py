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
    # identity (Wazuh: Windows 4624/4625, sshd, ...)
    "auth_failure_count",
    "auth_failure_src_count",
    "rdp_logon_count",
    "auth_success_after_failures",
    # network IDS (Suricata alerts where this host is the target)
    "ids_alert_count",
    "ids_scan_count",
    "ids_bruteforce_count",
    "ids_web_attack_count",
    "ids_attacker_count",
    # web server logs (Wazuh web/accesslog rules)
    "web_attack_count",
    # attack techniques in command lines / Windows events (EDR + Wazuh)
    "discovery_cmd_count",
    "credential_dump_cmd_count",
    "remote_exec_count",
    "service_install_count",
    "account_change_count",
    "defense_evasion_count",
    "inhibit_recovery_count",
    "ransom_note_count",
    # DNS tunnelling (Sysmon 22)
    "max_dns_query_length",
    "long_dns_query_count",
    # network attacks (Suricata + Wazuh)
    "sqli_count",
    "ids_dos_count",
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

WAZUH_AUTH_FAILURE_GROUPS = {"authentication_failed", "authentication_failures", "invalid_login",
                             "win_authentication_failed"}
WAZUH_AUTH_SUCCESS_GROUPS = {"authentication_success"}
WAZUH_WEB_ATTACK_GROUPS = {"attack", "sql_injection", "xss", "web_scan", "recon", "web_attack"}
IDS_SCAN = re.compile(r"(?i)(\bscan\b|nmap|masscan|portscan|port sweep|network scan)")
IDS_BRUTEFORCE = re.compile(r"(?i)(brute|password guess|login attempt|failed login|excessive|"
                            r"\brdp\b|ms-rdp|\bssh\b.*(attempt|scan)|smb.*(logon|auth))")
# "sql" alone would also match port scans such as "inbound to MSSQL port 1433".
IDS_WEB_ATTACK = re.compile(r"(?i)(sql.?injection|\bsqli\b|union\s+(all\s+)?select|sqlmap|select\s+sleep|"
                            r"xss|cross.site|web_server|web_specific|directory traversal|command injection|"
                            r"\blfi\b|\brfi\b|web application attack)")
SQLI = re.compile(r"(?i)(sql.?injection|\bsqli\b|union\s+(all\s+)?select|sqlmap|select\s+sleep)")
IDS_DOS = re.compile(r"(?i)(\bdos\b|ddos|flood|slowloris|denial.of.service)")

# Discovery: distinct tools per window, so one benign "whoami" from an IDE stays low.
DISCOVERY_TOOLS = {"whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "nltest.exe",
                   "quser.exe", "qwinsta.exe", "tasklist.exe", "arp.exe", "netstat.exe", "route.exe",
                   "nslookup.exe", "dsquery.exe", "hostname.exe", "query.exe", "klist.exe", "cmdkey.exe"}
DISCOVERY_PS = re.compile(r"(?i)(get-(aduser|adcomputer|addomain|adgroupmember|localuser|localgroupmember|"
                          r"netipconfiguration|nettcpconnection|process|wmiobject\s+win32_(computersystem|"
                          r"operatingsystem|useraccount)))")
CREDENTIAL_DUMP = re.compile(r"(?i)(reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|ntdsutil|sekurlsa|lsadump|"
                             r"mimikatz|comsvcs(\.dll)?.{0,4}(#24|minidump)|procdump(64)?(\.exe)?\s.*lsass|"
                             r"\\ntds\\ntds\.dit|invoke-mimikatz|out-minidump)")
REMOTE_EXEC_PARENTS = {"wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe", "psexesvc.exe", "paexesvc.exe"}
REMOTE_EXEC_IMAGES = {"psexesvc.exe", "paexesvc.exe", "remcomsvc.exe"}
REMOTE_EXEC_CMD = re.compile(r"(?i)(wmic(\.exe)?\s+/node:|invoke-(command|wmimethod)\s.*-computername|"
                             r"enter-pssession|new-pssession|psexec(64)?(\.exe)?\s+\\\\|paexec|"
                             r"winrs(\.exe)?\s+-r:|copy\s.*\\\\[\w.-]+\\(admin|c)\$)")
SERVICE_INSTALL_CMD = re.compile(r"(?i)(\bsc(\.exe)?\s+(\\\\\S+\s+)?create\b|new-service\b)")
ACCOUNT_CHANGE_CMD = re.compile(r"(?i)(\bnet1?(\.exe)?\s+(user|localgroup|group)\s.*\s/add\b|new-localuser|"
                                r"add-localgroupmember|new-aduser|add-adgroupmember)")
DEFENSE_EVASION_CMD = re.compile(r"(?i)(wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog|remove-eventlog|"
                                 r"set-mppreference\s.*-disable\w*\s+(\$?true|1)|add-mppreference\s.*-exclusion|"
                                 r"\bsc(\.exe)?\s+(stop|config|delete)\s+windefend|"
                                 r"netsh(\.exe)?\s+(adv)?firewall\s+set\s.*state\s+off|auditpol(\.exe)?\s.*/clear|"
                                 r"fsutil(\.exe)?\s+usn\s+deletejournal)")
INHIBIT_RECOVERY_CMD = re.compile(r"(?i)(vssadmin(\.exe)?\s+(delete|resize)\s+shadows?|"
                                  r"wmic(\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy.*delete|"
                                  r"bcdedit(\.exe)?\s.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|"
                                  r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup))")
# Ransom notes and typical encrypted-file extensions ("readme" alone is far too common).
RANSOM_FILE = re.compile(r"(?i)((decrypt|ransom|restore[_ -]?(my[_ -]?)?files|recover[_ -]?files|"
                         r"how[_ -]?to[_ -]?(decrypt|restore|recover))[^\\]*\.(txt|html?|hta)$|"
                         r"\.(locked|encrypted|crypted|crypt|wncry|lockbit|ryk|enc)$)")
WAZUH_ACCOUNT_EVENTS = {"4720", "4722", "4724", "4728", "4732", "4738", "4756"}
WAZUH_ACCOUNT_GROUPS = {"adduser", "account_changed", "group_changed"}
WAZUH_SERVICE_EVENTS = {"7045", "4697"}
WAZUH_LOG_CLEARED_EVENTS = {"1102", "104"}
LONG_DNS_LABEL = 40
LONG_DNS_QUERY = 100


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
    # Wazuh/Suricata write offsets as +0000; older Pythons only accept +00:00.
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def window_start(timestamp: datetime, window_seconds: int = WINDOW_SECONDS) -> datetime:
    epoch = int(timestamp.timestamp())
    return datetime.fromtimestamp(epoch - epoch % window_seconds, tz=timezone.utc)


def group_windows(
    events: Iterable[dict[str, Any]], window_seconds: int = WINDOW_SECONDS, assets: Any = None
) -> dict[tuple[str, datetime], list[dict[str, Any]]]:
    """Group events by (monitored host, window start).

    The asset map turns Wazuh agent names and Suricata IPs into the same host as
    the EDR agent, so one window holds every source's view of that machine.
    Events without a timestamp or without a monitored host are skipped.
    """
    from ai.assets import get_assets

    assets = assets if assets is not None else get_assets()
    windows: dict[tuple[str, datetime], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        timestamp = parse_timestamp(event.get("timestamp"))
        resolved = assets.resolve(event) if timestamp is not None else None
        if resolved is None:
            continue
        host, peer = resolved
        windows[(host, window_start(timestamp, window_seconds))].append(
            {**event, "_peer_ip": peer} if peer else event)
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


def _wazuh_parts(event: dict[str, Any]) -> tuple[set[str], str, dict[str, Any], str]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    system = win.get("system") if isinstance(win.get("system"), dict) else {}
    source_ip = str(eventdata.get("ipAddress") or data.get("srcip") or "").strip()
    return ({str(g).lower() for g in groups}, str(rule.get("description") or "").lower(),
            {**eventdata, "_event_id": str(system.get("eventID") or "")}, source_ip)


def window_features(events: Iterable[dict[str, Any]]) -> dict[str, float]:
    """Compute the fixed feature vector for one host/window."""
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    images: set[str] = set()
    dst_ips: set[str] = set()
    dst_ports: set[str] = set()
    domains: set[str] = set()
    auth_sources: set[str] = set()
    attackers: set[str] = set()
    discovery_tools: set[str] = set()
    auth_successes = 0

    for event in events:
        event_type = str(event.get("event_type") or "").lower()
        source = str(event.get("source") or "").lower()
        data = _data(event)

        if source == "suricata":
            if event_type == "network_alert":
                raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
                alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
                text = f"{alert.get('signature', '')} | {alert.get('category', '')}"
                f["ids_alert_count"] += 1
                if IDS_SCAN.search(text):
                    f["ids_scan_count"] += 1
                if IDS_BRUTEFORCE.search(text):
                    f["ids_bruteforce_count"] += 1
                if IDS_WEB_ATTACK.search(text):
                    f["ids_web_attack_count"] += 1
                if SQLI.search(text):
                    f["sqli_count"] += 1
                if IDS_DOS.search(text):
                    f["ids_dos_count"] += 1
                if event.get("_peer_ip"):
                    attackers.add(str(event["_peer_ip"]))
            continue

        if source == "wazuh":
            groups, description, eventdata, source_ip = _wazuh_parts(event)
            usable_ip = bool(source_ip) and source_ip not in {"-", "::1", "127.0.0.1"}
            if (event_type == "authentication_failure" or eventdata["_event_id"] == "4625"
                    or groups & WAZUH_AUTH_FAILURE_GROUPS):
                f["auth_failure_count"] += 1
                if usable_ip:
                    auth_sources.add(source_ip)
            elif eventdata["_event_id"] == "4624" or groups & WAZUH_AUTH_SUCCESS_GROUPS:
                auth_successes += 1
                if str(eventdata.get("logonType")) == "10":
                    f["rdp_logon_count"] += 1
            web_rule = ("web" in groups or "accesslog" in groups) and groups & WAZUH_WEB_ATTACK_GROUPS
            if web_rule or "sql injection" in description or "xss" in description:
                f["web_attack_count"] += 1
                if "sql_injection" in groups or "sql injection" in description:
                    f["sqli_count"] += 1
                if usable_ip:
                    attackers.add(source_ip)
            windows_event = eventdata["_event_id"]
            if windows_event in WAZUH_ACCOUNT_EVENTS or groups & WAZUH_ACCOUNT_GROUPS:
                f["account_change_count"] += 1
            if windows_event in WAZUH_SERVICE_EVENTS:
                f["service_install_count"] += 1
            if windows_event in WAZUH_LOG_CLEARED_EVENTS or "logs_cleared" in groups:
                f["defense_evasion_count"] += 1
            continue

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
            parent = _basename(data.get("ParentImage"))
            if parent in OFFICE_PARENTS:
                f["office_spawn_count"] += 1
            if name in DISCOVERY_TOOLS:
                discovery_tools.add("net.exe" if name == "net1.exe" else name)
            for match in DISCOVERY_PS.finditer(command_line):
                discovery_tools.add(match.group(1).lower().split()[0])
            if CREDENTIAL_DUMP.search(command_line):
                f["credential_dump_cmd_count"] += 1
            # Executed remotely (PsExec service, WMI, WinRM) or launching remote execution.
            if (name in REMOTE_EXEC_IMAGES
                    or (parent in REMOTE_EXEC_PARENTS and (name in SHELLS or name in LOLBINS or name in DISCOVERY_TOOLS))
                    or REMOTE_EXEC_CMD.search(command_line)):
                f["remote_exec_count"] += 1
            if SERVICE_INSTALL_CMD.search(command_line):
                f["service_install_count"] += 1
            if ACCOUNT_CHANGE_CMD.search(command_line):
                f["account_change_count"] += 1
            if DEFENSE_EVASION_CMD.search(command_line):
                f["defense_evasion_count"] += 1
            if INHIBIT_RECOVERY_CMD.search(command_line):
                f["inhibit_recovery_count"] += 1

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
                f["max_dns_query_length"] = max(f["max_dns_query_length"], float(len(domain)))
                if len(domain) >= LONG_DNS_QUERY or max(len(label) for label in domain.split(".")) >= LONG_DNS_LABEL:
                    f["long_dns_query_count"] += 1

        elif event_type == "file_create":
            f["file_create_count"] += 1
            target = str(data.get("TargetFilename") or "").lower()
            if target.endswith(EXECUTABLE_EXTENSIONS):
                f["executable_file_create_count"] += 1
            if RANSOM_FILE.search(target):
                f["ransom_note_count"] += 1

        elif event_type == "registry_set":
            f["registry_set_count"] += 1
            if any(key in str(data.get("TargetObject") or "").lower() for key in PERSISTENCE_KEYS):
                f["persistence_registry_count"] += 1

        elif event_type == "process_access":
            if _basename(data.get("TargetImage")) == "lsass.exe":
                f["lsass_access_count"] += 1

        elif event_type == "authentication_failure":
            f["auth_failure_count"] += 1

    f["auth_failure_src_count"] = float(len(auth_sources))
    f["auth_success_after_failures"] = 1.0 if auth_successes and f["auth_failure_count"] >= 3 else 0.0
    f["ids_attacker_count"] = float(len(attackers))
    f["discovery_cmd_count"] = float(len(discovery_tools))
    f["unique_process_images"] = float(len(images))
    f["unique_dst_ip"] = float(len(dst_ips))
    f["unique_dst_port"] = float(len(dst_ports))
    f["unique_domains"] = float(len(domains))
    f["max_domain_entropy"] = round(f["max_domain_entropy"], 4)
    return f
