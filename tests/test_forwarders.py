import importlib.util
import io
import json
from pathlib import Path

ROOT = Path(__file__).parents[1] / "forwarders"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


suricata = _load("suricata_to_xdr", ROOT / "suricata" / "suricata_to_xdr.py")
wazuh = _load("custom_xdr", ROOT / "wazuh" / "custom-xdr.py")


def test_suricata_reader_sends_only_complete_alert_lines() -> None:
    alert = {"event_type": "alert", "alert": {"signature": "ET SCAN Nmap"}}
    flow = {"event_type": "flow"}
    data = (json.dumps(alert) + "\n" + json.dumps(flow) + "\n" + "not json\n" + json.dumps(alert) + "\n"
            + '{"event_type": "alert", "half": ').encode()  # last line is still being written
    handle = io.BytesIO(data)
    events, offset = suricata.read_batch(handle, ["alert"], batch_size=100)
    assert events == [alert, alert]
    assert offset == data.rindex(b"\n") + 1  # resumes at the start of the unfinished line
    assert handle.tell() == offset


def test_suricata_reader_respects_batch_size() -> None:
    line = (json.dumps({"event_type": "alert"}) + "\n").encode()
    handle = io.BytesIO(line * 5)
    events, offset = suricata.read_batch(handle, ["alert"], batch_size=2)
    assert len(events) == 2 and offset == len(line) * 2


def test_suricata_state_round_trip(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    suricata.save_state(str(state), 42, 1234)
    assert suricata.load_state(str(state)) == {"inode": 42, "offset": 1234}
    assert suricata.load_state(str(tmp_path / "missing.json")) == {}


def test_wazuh_integration_reads_alert_file(tmp_path: Path) -> None:
    alert = {"id": "1", "agent": {"name": "WIN10-01"}, "rule": {"level": 5}}
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(alert) + "\n", encoding="utf-8")
    assert wazuh.read_alert(str(path)) == alert
    assert wazuh.main(["custom-xdr"]) == 1  # missing arguments
