from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required
from sqlalchemy import func

from extensions import db
from models.login_log import LoginLog
from models.threat_alert import ThreatAlert
from models.user import User
from services.authz import role_required
from services.logging_service import record_activity

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


def utcnow():
    return datetime.now(timezone.utc)


@dashboard_bp.get("/admin")
@role_required("admin")
def admin_stats():
    record_activity(int(get_jwt_identity()), "view_admin_dashboard", "/dashboard")
    users = User.query.count()
    total_logins = LoginLog.query.count()
    success = LoginLog.query.filter_by(login_status="success").count()
    failed = LoginLog.query.filter_by(login_status="failed").count()
    suspicious = LoginLog.query.filter(LoginLog.anomaly_prediction == "anomalous").count()
    high = ThreatAlert.query.filter(ThreatAlert.severity.in_(["HIGH", "CRITICAL"])).count()
    critical = ThreatAlert.query.filter_by(severity="CRITICAL").count()
    recent = [e.to_dict() for e in LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(12).all()]

    days = []
    succ_series = []
    fail_series = []
    threat_series = []
    for i in range(13, -1, -1):
        day = (utcnow() - timedelta(days=i)).date()
        start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        days.append(day.isoformat())
        succ_series.append(
            LoginLog.query.filter(LoginLog.login_status == "success", LoginLog.timestamp >= start, LoginLog.timestamp < end).count()
        )
        fail_series.append(
            LoginLog.query.filter(LoginLog.login_status == "failed", LoginLog.timestamp >= start, LoginLog.timestamp < end).count()
        )
        threat_series.append(
            ThreatAlert.query.filter(ThreatAlert.created_at >= start, ThreatAlert.created_at < end).count()
        )

    severity_counts = {
        row[0]: row[1]
        for row in db.session.query(ThreatAlert.severity, func.count(ThreatAlert.id)).group_by(ThreatAlert.severity).all()
    }
    db.session.commit()
    return jsonify(
        {
            "kpis": {
                "registered_users": users,
                "total_login_attempts": total_logins,
                "successful_logins": success,
                "failed_logins": failed,
                "suspicious_activities": suspicious,
                "high_risk_threats": high,
                "critical_alerts": critical,
            },
            "recent_events": recent,
            "charts": {
                "labels": days,
                "successful": succ_series,
                "failed": fail_series,
                "threats": threat_series,
                "severity": {
                    "LOW": severity_counts.get("LOW", 0),
                    "MEDIUM": severity_counts.get("MEDIUM", 0),
                    "HIGH": severity_counts.get("HIGH", 0),
                    "CRITICAL": severity_counts.get("CRITICAL", 0),
                },
            },
        }
    )


@dashboard_bp.get("/user")
@jwt_required()
def user_stats():
    uid = int(get_jwt_identity())
    claims = get_jwt()
    if claims.get("role") == "admin":
        return admin_stats()
    record_activity(uid, "view_user_dashboard", "/dashboard")
    logs = LoginLog.query.filter_by(user_id=uid).order_by(LoginLog.timestamp.desc()).limit(50).all()
    success = LoginLog.query.filter_by(user_id=uid, login_status="success").count()
    failed = LoginLog.query.filter_by(user_id=uid, login_status="failed").count()
    alerts = ThreatAlert.query.filter_by(user_id=uid).order_by(ThreatAlert.created_at.desc()).limit(20).all()
    db.session.commit()
    return jsonify(
        {
            "kpis": {
                "successful_logins": success,
                "failed_logins": failed,
                "alerts": ThreatAlert.query.filter_by(user_id=uid).count(),
            },
            "login_history": [x.to_dict() for x in logs],
            "alerts": [a.to_dict() for a in alerts],
        }
    )
