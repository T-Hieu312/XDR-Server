import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "backend"))

from detection.ioc_engine import match_iocs
from detection.rule_engine import load_default_rules, match_event


def test_sysmon_rules_match_nested_fields_case_insensitively() -> None:
    event = {
        "event_type": "process_create",
        "raw": {
            "data": {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe",
                "CommandLine": "powershell.exe -ENC abc123",
            }
        },
    }

    matches = match_event(event, load_default_rules())

    assert [rule["id"] for rule in matches] == ["sysmon-powershell-encoded-command"]


def test_ioc_matching_supports_cidr_domains_and_hashes() -> None:
    sha256 = "a" * 64
    iocs = {
        "ips": ["203.0.113.0/24"],
        "domains": ["malicious.example"],
        "file_hashes": [sha256],
    }
    event = {
        "raw": {
            "data": {
                "DestinationIp": "203.0.113.42",
                "QueryName": "sub.malicious.example",
                "Hashes": f"SHA256={sha256}",
            }
        }
    }

    matches = match_iocs(event, iocs)

    assert {(rule["id"].split("-")[1], rule["name"].rsplit(": ", 1)[-1]) for rule in matches} == {
        ("ip", "203.0.113.42"),
        ("domain", "malicious.example"),
        ("hash", sha256),
    }
