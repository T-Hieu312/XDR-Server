import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parents[1] / "backend"))

from main import app


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("XDR_DATABASE_PATH", str(tmp_path / "xdr.sqlite3"))
    monkeypatch.setenv("XDR_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("XDR_BOOTSTRAP_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("XDR_WAZUH_INGEST_KEY", "test-wazuh-secret")
    monkeypatch.setenv("XDR_SURICATA_INGEST_KEY", "test-suricata-secret")
    with TestClient(app) as test_client:
        login = test_client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "test-admin-password"},
        )
        assert login.status_code == 200
        test_client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        yield test_client


def test_api_routes_require_account_session(client: TestClient) -> None:
    protected_routes = [
        ("GET", "/api/events"),
        ("POST", "/api/events"),
        ("GET", "/api/alerts"),
        ("PATCH", "/api/alerts/alert-01"),
        ("GET", "/api/incidents"),
        ("PATCH", "/api/incidents/incident-01"),
        ("GET", "/api/hosts"),
        ("GET", "/api/users"),
        ("POST", "/api/response/isolate-host"),
    ]
    for method, path in protected_routes:
        response = client.request(
            method,
            path,
            headers={"Authorization": ""},
            json={"event_type": "test", "source": "test", "host_id": "host-01"},
        )
        assert response.status_code == 401, path

    assert client.get("/api/auth/me").json()["role"] == "admin"


def test_login_rejects_invalid_credentials(client: TestClient) -> None:
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )
    assert response.status_code == 401


def test_logout_revokes_the_current_session(client: TestClient) -> None:
    headers = {"Authorization": client.headers["Authorization"]}
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_viewer_is_read_only_and_cannot_manage_users(client: TestClient) -> None:
    event = client.post(
        "/api/events",
        json={
            "event_type": "suspicious_process",
            "source": "test",
            "host_id": "host-01",
        },
    )
    alert_id = event.json()["alerts"][0]["alert_id"]
    created = client.post(
        "/api/users",
        json={
            "username": "viewer01",
            "password": "viewer-password-123",
            "role": "viewer",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "viewer01", "password": "viewer-password-123"},
    )
    viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert client.get("/api/events", headers=viewer_headers).status_code == 200
    assert client.get("/api/alerts", headers=viewer_headers).status_code == 200
    assert client.patch(
        f"/api/alerts/{alert_id}",
        headers=viewer_headers,
        json={"status": "acknowledged"},
    ).status_code == 403
    assert client.post(
        "/api/events",
        headers=viewer_headers,
        json={"event_type": "test", "source": "test", "host_id": "host-01"},
    ).status_code == 403
    assert client.get("/api/users", headers=viewer_headers).status_code == 403
    assert client.post(
        "/api/response/isolate-host",
        headers=viewer_headers,
        json={"host_id": "host-01", "reason": "Investigate active suspicious behavior"},
    ).status_code == 403


def test_admin_can_assign_roles_and_revoke_deactivated_accounts(client: TestClient) -> None:
    created = client.post(
        "/api/users",
        json={
            "username": "analyst01",
            "password": "analyst-password-123",
            "role": "analyst",
        },
    )
    assert created.status_code == 201
    user = created.json()
    assert "password_hash" not in user
    assert "password_salt" not in user
    assert client.post(
        "/api/users",
        json={
            "username": "ANALYST01",
            "password": "another-password-123",
            "role": "viewer",
        },
    ).status_code == 409

    login = client.post(
        "/api/auth/login",
        json={"username": "analyst01", "password": "analyst-password-123"},
    )
    analyst_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.post(
        "/api/events",
        headers=analyst_headers,
        json={"event_type": "suspicious_process", "source": "test", "host_id": "host-02"},
    ).status_code == 201
    analyst_alert = client.get("/api/alerts", headers=analyst_headers).json()[0]
    assert client.patch(
        f"/api/alerts/{analyst_alert['alert_id']}",
        headers=analyst_headers,
        json={"status": "acknowledged"},
    ).status_code == 200

    update = client.patch(
        f"/api/users/{user['user_id']}",
        json={"is_active": False},
    )
    assert update.status_code == 200
    assert client.get("/api/auth/me", headers=analyst_headers).status_code == 401


def test_last_admin_cannot_be_demoted_or_deactivated(client: TestClient) -> None:
    user_id = client.get("/api/auth/me").json()["user_id"]
    demote = client.patch(f"/api/users/{user_id}", json={"role": "viewer"})
    deactivate = client.patch(f"/api/users/{user_id}", json={"is_active": False})

    assert demote.status_code == 409
    assert deactivate.status_code == 400


def test_user_can_change_password_and_old_sessions_are_revoked(client: TestClient) -> None:
    current_password = "test-admin-password"
    response = client.post(
        "/api/auth/password",
        json={
            "current_password": current_password,
            "new_password": "updated-admin-password",
        },
    )
    assert response.status_code == 204
    assert client.get("/api/auth/me").status_code == 401
    assert client.post(
        "/api/auth/login",
        json={"username": "admin", "password": current_password},
    ).status_code == 401
    assert client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "updated-admin-password"},
    ).status_code == 200


def test_event_creates_alert_incident_and_host_summary(client: TestClient) -> None:
    payload = {
        "event_type": "suspicious_process",
        "source": "test-collector",
        "host_id": "endpoint-01",
        "severity": "medium",
        "raw": {"process_name": "powershell.exe"},
    }

    ingested = client.post("/api/events", json=payload)

    assert ingested.status_code == 201
    result = ingested.json()
    assert result["event"]["event_id"]
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["severity"] == "high"
    # severity high (70) x rule confidence 0.9; the AI score is added later when
    # the host's 5-minute window is analysed (see tests/test_ai.py).
    assert alert["risk_score"] == 63
    assert alert["ai_score"] == 0.0
    assert alert["incident_id"] == result["incident_id"]

    assert client.get("/api/events").json()[0]["event_type"] == "suspicious_process"
    assert client.get("/api/alerts").json()[0]["alert_id"] == alert["alert_id"]
    incident = client.get("/api/incidents").json()[0]
    assert incident["alert_ids"] == [alert["alert_id"]]
    host = client.get("/api/hosts").json()[0]
    assert host["host_id"] == "endpoint-01"
    assert host["event_count"] == 1
    assert host["open_alert_count"] == 1

    assert client.patch(
        f"/api/alerts/{alert['alert_id']}", json={"status": "resolved"}
    ).json()["status"] == "resolved"
    assert client.get("/api/incidents").json()[0]["status"] == "resolved"
    assert client.get("/api/hosts").json()[0]["open_alert_count"] == 0

    duplicate = client.post(
        "/api/events",
        json={**payload, "event_id": result["event"]["event_id"]},
    )
    assert duplicate.status_code == 409


def test_unmatched_event_is_stored_without_alert(client: TestClient) -> None:
    response = client.post(
        "/api/events",
        json={
            "event_type": "routine_login",
            "source": "test-collector",
            "host_id": "endpoint-02",
        },
    )

    assert response.status_code == 201
    assert response.json()["alerts"] == []
    assert response.json()["incident_id"] is None
    assert client.get("/api/alerts").json() == []
    assert client.get("/api/hosts").json()[0]["event_count"] == 1


def test_authenticated_edr_batch_is_normalized_and_idempotent(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDR_AGENT_KEY", "test-agent-secret")
    headers = {
        "X-Agent-Id": "agent-01",
        "X-Agent-Key": "test-agent-secret",
        "Authorization": "",
    }
    batch = [
        {
            "source": "sysmon",
            "event_type": "process_create",
            "timestamp": "2026-10-25T10:00:00Z",
            "computer": "endpoint-01",
            "record_id": "1234",
            "data": {"Image": "C:\\Windows\\notepad.exe"},
        }
    ]

    response = client.post("/api/events/batch", json=batch, headers=headers)

    assert response.status_code == 200
    assert response.json() == {"received": 1, "duplicates": 0}
    stored = client.get("/api/events").json()[0]
    assert stored["event_id"] == "edr:agent-01:endpoint-01:1234"
    assert stored["source"] == "edr"
    assert stored["host_id"] == "endpoint-01"
    assert stored["raw"]["data"]["Image"] == "C:\\Windows\\notepad.exe"
    assert stored["raw"]["agent_id"] == "agent-01"

    replay = client.post("/api/events/batch", json=batch, headers=headers)

    assert replay.status_code == 200
    assert replay.json() == {"received": 0, "duplicates": 1}
    assert client.get("/api/hosts").json()[0]["event_count"] == 1


def test_edr_batch_requires_valid_agent_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDR_AGENT_KEY", "expected-secret")

    response = client.post(
        "/api/events/batch",
        json=[{"event_type": "process_create"}],
        headers={"X-Agent-Id": "agent-01", "X-Agent-Key": "wrong-secret"},
    )

    assert response.status_code == 401


def test_wazuh_alerts_are_ingested_normalized_and_deduplicated(client: TestClient) -> None:
    headers = {"X-Collector-Key": "test-wazuh-secret"}
    alert = {
        "id": "wazuh-alert-001",
        "timestamp": "2026-11-02T10:00:00Z",
        "agent": {"id": "001", "name": "server-01"},
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: authentication failed",
            "groups": ["authentication_failed"],
        },
        "data": {"srcip": "192.0.2.10"},
    }

    response = client.post(
        "/api/collectors/wazuh/events",
        headers=headers,
        json={"alerts": [alert]},
    )
    assert response.status_code == 200
    assert response.json() == {"received": 1, "duplicates": 0}
    stored = client.get("/api/events").json()[0]
    assert stored["source"] == "wazuh"
    assert stored["event_type"] == "authentication_failure"
    assert stored["host_id"] == "server-01"
    assert stored["severity"] == "high"
    assert stored["event_id"] == "wazuh:wazuh-alert-001"

    replay = client.post(
        "/api/collectors/wazuh/events",
        headers=headers,
        json={"alerts": [alert]},
    )
    assert replay.status_code == 200
    assert replay.json() == {"received": 0, "duplicates": 1}


def test_suricata_eve_is_ingested_normalized_and_deduplicated(client: TestClient) -> None:
    headers = {
        "X-Collector-Id": "sensor-01",
        "X-Collector-Key": "test-suricata-secret",
    }
    eve_record = {
        "timestamp": "2026-11-02T10:01:00Z",
        "event_type": "alert",
        "src_ip": "192.0.2.20",
        "dest_ip": "198.51.100.15",
        "proto": "TCP",
        "alert": {"signature": "Suspicious connection", "severity": 1},
    }

    response = client.post(
        "/api/collectors/suricata/events",
        headers=headers,
        json=[eve_record],
    )
    assert response.status_code == 200
    assert response.json() == {"received": 1, "duplicates": 0}
    stored = client.get("/api/events").json()[0]
    assert stored["source"] == "suricata"
    assert stored["event_type"] == "network_alert"
    assert stored["host_id"] == "192.0.2.20"
    assert stored["severity"] == "high"
    assert stored["raw"]["collector_id"] == "sensor-01"

    replay = client.post(
        "/api/collectors/suricata/events",
        headers=headers,
        json=[eve_record],
    )
    assert replay.status_code == 200
    assert replay.json() == {"received": 0, "duplicates": 1}


def test_collector_ingest_requires_source_specific_key(client: TestClient) -> None:
    response = client.post(
        "/api/collectors/wazuh/events",
        headers={"X-Collector-Key": "wrong-key"},
        json={"alerts": [{"id": "one"}]},
    )
    assert response.status_code == 401

    invalid = client.post(
        "/api/collectors/suricata/events",
        headers={
            "X-Collector-Id": "sensor-01",
            "X-Collector-Key": "test-suricata-secret",
        },
        json=[{"event_type": "alert", "alert": {"severity": "bad"}}],
    )
    assert invalid.status_code == 422


def test_response_actions_require_two_person_approval_and_never_execute(
    client: TestClient,
) -> None:
    observed = client.post(
        "/api/events",
        json={
            "event_type": "routine_login",
            "source": "test",
            "host_id": "endpoint-01",
        },
    )
    assert observed.status_code == 201
    pending = client.post(
        "/api/response/isolate-host",
        json={"host_id": "endpoint-01", "reason": "Investigate active suspicious behavior"},
    )
    assert pending.status_code == 202
    request_id = pending.json()["request_id"]
    assert pending.json()["status"] == "pending"

    self_review = client.patch(
        f"/api/response/requests/{request_id}",
        json={"status": "approved"},
    )
    assert self_review.status_code == 409

    second_admin = client.post(
        "/api/users",
        json={
            "username": "reviewer",
            "password": "reviewer-password-123",
            "role": "admin",
        },
    )
    reviewer_login = client.post(
        "/api/auth/login",
        json={"username": "reviewer", "password": "reviewer-password-123"},
    )
    reviewer_headers = {
        "Authorization": f"Bearer {reviewer_login.json()['access_token']}"
    }
    approved = client.patch(
        f"/api/response/requests/{request_id}",
        headers=reviewer_headers,
        json={"status": "approved", "review_note": "Approved for manual action"},
    )
    assert second_admin.status_code == 201
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["reviewed_by"] == second_admin.json()["user_id"]
    assert client.get("/api/events").json()[0]["event_type"] == "routine_login"


def test_response_request_validates_target_and_review_state(client: TestClient) -> None:
    assert client.post(
        "/api/response/block-ip",
        json={"ip_address": "not-an-ip", "reason": "Block the suspicious address"},
    ).status_code == 422
    assert client.post(
        "/api/response/kill-process",
        json={
            "host_id": "unknown-host",
            "process_id": 42,
            "reason": "Stop the suspected process",
        },
    ).status_code == 404

    observed = client.post(
        "/api/events",
        json={"event_type": "routine_login", "source": "test", "host_id": "host-02"},
    )
    request = client.post(
        "/api/response/kill-process",
        json={
            "host_id": "host-02",
            "process_id": 42,
            "reason": "Stop the suspected process",
        },
    )
    assert observed.status_code == 201
    assert request.status_code == 202
    assert request.json()["target"]["process_id"] == 42
