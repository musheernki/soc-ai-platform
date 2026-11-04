from datetime import datetime, timezone

from extensions import db
from models.activity_log import ActivityLog
from models.login_log import LoginLog


def utcnow():
    return datetime.now(timezone.utc)


def client_ip(request):
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.remote_addr or "0.0.0.0")[:64]


def record_login(user_id, ip_address, status, user_agent, email_attempted, analysis):
    log = LoginLog(
        user_id=user_id,
        ip_address=ip_address,
        timestamp=utcnow(),
        login_status=status,
        user_agent=(user_agent or "")[:512],
        email_attempted=email_attempted,
        anomaly_prediction=analysis.get("anomaly_prediction"),
        risk_score=analysis.get("risk_score"),
        severity=analysis.get("severity"),
        detection_reason=analysis.get("detection_reason"),
    )
    db.session.add(log)
    db.session.flush()
    return log


def record_activity(user_id, activity_type, resource_accessed=None):
    row = ActivityLog(
        user_id=user_id,
        activity_type=activity_type,
        timestamp=utcnow(),
        resource_accessed=resource_accessed,
    )
    db.session.add(row)
    return row
