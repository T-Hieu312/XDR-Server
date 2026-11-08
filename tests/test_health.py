import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parents[1] / "backend"))

from main import app


def test_health_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDR_DATABASE_PATH", str(tmp_path / "health.sqlite3"))
    monkeypatch.setenv("XDR_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("XDR_BOOTSTRAP_ADMIN_PASSWORD", "test-admin-password")
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_dashboard_is_served_by_the_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDR_DATABASE_PATH", str(tmp_path / "dashboard.sqlite3"))
    monkeypatch.setenv("XDR_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("XDR_BOOTSTRAP_ADMIN_PASSWORD", "test-admin-password")
    with TestClient(app) as client:
        page = client.get("/dashboard/")
        script = client.get("/dashboard/dashboard.js")

    assert page.status_code == 200
    assert "Trung tâm giám sát" in page.text
    assert 'id="auth-dialog"' in page.text
    assert script.status_code == 200
    assert "api/events?limit=500" in script.text
    assert "/api/auth/login" in script.text