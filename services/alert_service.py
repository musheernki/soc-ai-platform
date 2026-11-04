from extensions import db, socketio
from models.threat_alert import ThreatAlert


def maybe_create_alert(user_id, login_log, analysis):
    score = analysis["risk_score"]
    severity = analysis["severity"]
    anomalous = analysis["anomaly_prediction"] == "anomalous"
    if not anomalous and score < 40:
        return None
    alert = ThreatAlert(
        user_id=user_id,
        risk_score=score,
        severity=severity,
        detection_reason=analysis["detection_reason"],
        alert_status="New",
        login_log_id=login_log.id if login_log else None,
    )
    db.session.add(alert)
    db.session.flush()
    payload = alert.to_dict()
    socketio.emit("security_alert", payload, namespace="/")
    return alert
