from datetime import datetime, timezone

from ai_engine.detect_threat import analyse_login
from tests.conftest import auth_header


class _Log:
    def __init__(self, ip, ts, status):
        self.ip_address = ip
        self.timestamp = ts
        self.login_status = status


def test_normal_login_detection():
    now = datetime.now(timezone.utc)
    logs = [_Log("10.0.0.8", now, "success") for _ in range(2)]
    result = analyse_login(None, "10.0.0.8", now, "success", logs, [])
    assert result["risk_score"] <= 40
    assert result["severity"] in ("LOW", "MEDIUM")


def test_anomalous_login_detection():
    now = datetime.now(timezone.utc)
    logs = [_Log("198.51.100.10", now, "failed") for _ in range(12)]
    result = analyse_login(None, "198.51.100.10", now.replace(hour=2), "failed", logs, [])
    assert result["risk_score"] >= 50
    assert result["anomaly_prediction"] == "anomalous"
    assert result["severity"] in ("HIGH", "CRITICAL")
    assert "failed" in result["detection_reason"].lower()


def test_threat_alert_creation(client):
    headers = auth_header(client, "admin@soc.local", "Admin@123")
    res = client.post(
        "/api/security/simulate",
        headers=headers,
        json={"mode": "anomalous", "email": "user@soc.local", "repeats": 6},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["events"]
    alerts = client.get("/api/security/alerts", headers=headers)
    assert alerts.status_code == 200
    assert alerts.get_json()["total"] >= 1


def test_dashboard_data_retrieval(client):
    headers = auth_header(client, "admin@soc.local", "Admin@123")
    res = client.get("/api/dashboard/admin", headers=headers)
    assert res.status_code == 200
    kpis = res.get_json()["kpis"]
    assert "registered_users" in kpis
    assert kpis["registered_users"] >= 2
