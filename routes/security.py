from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from extensions import db
from models.activity_log import ActivityLog
from models.login_log import LoginLog
from models.threat_alert import ThreatAlert
from models.user import User
from services.alert_service import maybe_create_alert
from services.authz import role_required
from services.logging_service import client_ip, record_activity, record_login
from services.risk_service import score_attempt

security_bp = Blueprint("security", __name__, url_prefix="/api/security")


def utcnow():
    return datetime.now(timezone.utc)


def paginate(query):
    try:
        page = max(int(request.args.get("page", 1)), 1)
        per_page = min(max(int(request.args.get("per_page", 15)), 1), 100)
    except ValueError:
        page, per_page = 1, 15
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return page, per_page, total, items


@security_bp.get("/logs")
@jwt_required()
def logs():
    claims = get_jwt()
    uid = int(get_jwt_identity())
    query = LoginLog.query
    if claims.get("role") != "admin":
        query = query.filter(LoginLog.user_id == uid)
    q = (request.args.get("q") or "").strip()
    status = request.args.get("status")
    severity = request.args.get("severity")
    prediction = request.args.get("prediction")
    if q:
        query = query.filter(
            (LoginLog.ip_address.ilike(f"%{q}%"))
            | (LoginLog.email_attempted.ilike(f"%{q}%"))
            | (LoginLog.detection_reason.ilike(f"%{q}%"))
        )
    if status:
        query = query.filter(LoginLog.login_status == status)
    if severity:
        query = query.filter(LoginLog.severity == severity)
    if prediction:
        query = query.filter(LoginLog.anomaly_prediction == prediction)
    query = query.order_by(LoginLog.timestamp.desc())
    page, per_page, total, items = paginate(query)
    record_activity(uid, "view_security_logs", "/security/logs")
    db.session.commit()
    return jsonify({"page": page, "per_page": per_page, "total": total, "items": [i.to_dict() for i in items]})


@security_bp.get("/alerts")
@jwt_required()
def alerts():
    claims = get_jwt()
    uid = int(get_jwt_identity())
    query = ThreatAlert.query
    if claims.get("role") != "admin":
        query = query.filter(ThreatAlert.user_id == uid)
    status = request.args.get("status")
    severity = request.args.get("severity")
    if status:
        query = query.filter(ThreatAlert.alert_status == status)
    if severity:
        query = query.filter(ThreatAlert.severity == severity)
    query = query.order_by(ThreatAlert.created_at.desc())
    page, per_page, total, items = paginate(query)
    record_activity(uid, "view_alerts", "/security/alerts")
    db.session.commit()
    return jsonify({"page": page, "per_page": per_page, "total": total, "items": [i.to_dict() for i in items]})


@security_bp.post("/alerts/<int:alert_id>/status")
@role_required("admin")
def update_alert(alert_id):
    data = request.get_json(silent=True) or {}
    status = data.get("alert_status")
    if status not in ("New", "Investigating", "Resolved"):
        return jsonify({"error": "alert_status must be New, Investigating, or Resolved"}), 400
    alert = db.session.get(ThreatAlert, alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    alert.alert_status = status
    record_activity(int(get_jwt_identity()), "update_alert", f"/security/alerts/{alert_id}")
    db.session.commit()
    return jsonify({"alert": alert.to_dict()})


@security_bp.get("/activity")
@jwt_required()
def activity():
    claims = get_jwt()
    uid = int(get_jwt_identity())
    query = ActivityLog.query
    if claims.get("role") != "admin":
        query = query.filter(ActivityLog.user_id == uid)
    query = query.order_by(ActivityLog.timestamp.desc())
    page, per_page, total, items = paginate(query)
    db.session.commit()
    return jsonify({"page": page, "per_page": per_page, "total": total, "items": [i.to_dict() for i in items]})


@security_bp.post("/simulate")
@role_required("admin")
def simulate():
    """Safe test-mode: insert simulated login events. Does not scan networks."""
    data = request.get_json(silent=True) or {}
    mode = data.get("mode") or "anomalous"
    email = (data.get("email") or "user@soc.local").strip().lower()
    user = User.query.filter_by(email=email).first()
    ip = data.get("ip_address") or ("203.0.113.50" if mode == "anomalous" else client_ip(request))
    status = data.get("login_status") or ("failed" if mode == "anomalous" else "success")
    repeats = min(int(data.get("repeats") or (6 if mode == "anomalous" else 1)), 12)
    created = []
    for _ in range(repeats):
        analysis = score_attempt(user, ip, utcnow(), status)
        log = record_login(user.id if user else None, ip, status, "SOC-Simulator/1.0", email, analysis)
        alert = maybe_create_alert(user.id if user else None, log, analysis)
        created.append({"log": log.to_dict(), "alert": alert.to_dict() if alert else None, "analysis": analysis})
    record_activity(int(get_jwt_identity()), "simulate_events", "/security/simulate")
    db.session.commit()
    return jsonify({"message": "Simulated events recorded", "events": created})
