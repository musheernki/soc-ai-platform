<<<<<<< HEAD
import os
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify

from config import config_by_name
from extensions import bcrypt, db, jwt, socketio
from models import ActivityLog, LoginLog, ThreatAlert, TokenBlocklist, User
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.pages import pages_bp
from routes.reports import reports_bp
from routes.security import security_bp


def create_app(config_name=None):
    config_name = config_name or os.getenv("FLASK_ENV", "development")
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_by_name.get(config_name, config_by_name["development"]))
    os.makedirs(app.instance_path, exist_ok=True)
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///"):
        db_name = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
        if not os.path.isabs(db_name) and db_name != ":memory:":
            app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, os.path.basename(db_name))

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode=app.config.get("SOCKETIO_ASYNC_MODE", "threading"))

    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(reports_bp)

    @jwt.token_in_blocklist_loader
    def _revoked(_jwt_header, jwt_payload):
        jti = jwt_payload.get("jti")
        return TokenBlocklist.query.filter_by(jti=jti).first() is not None

    @jwt.unauthorized_loader
    def _unauth(msg):
        return jsonify({"error": "Missing or invalid token", "detail": msg}), 401

    @jwt.revoked_token_loader
    def _revoked_resp(_h, _p):
        return jsonify({"error": "Token revoked"}), 401

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify({"error": "Internal server error"}), 500

    with app.app_context():
        db.create_all()
        if not app.config.get("TESTING"):
            seed_if_empty()
            try:
                from ai_engine.detect_threat import load_models

                load_models()
            except Exception as exc:
                app.logger.warning("Model load deferred: %s", exc)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    return app


def seed_if_empty():
    if User.query.first():
        return
    from extensions import bcrypt as _bcrypt

    admin = User(
        name="SOC Administrator",
        email="admin@soc.local",
        password_hash=_bcrypt.generate_password_hash("Admin@123").decode("utf-8"),
        role="admin",
        account_status="active",
    )
    user = User(
        name="Jordan Hale",
        email="user@soc.local",
        password_hash=_bcrypt.generate_password_hash("User@123").decode("utf-8"),
        role="user",
        account_status="active",
    )
    db.session.add_all([admin, user])
    db.session.flush()
    now = datetime.now(timezone.utc)
    samples = [
        (user.id, "10.0.0.21", now - timedelta(hours=30), "success", "normal", 12, "LOW", "Isolation Forest baseline; typical office-hour login"),
        (user.id, "10.0.0.21", now - timedelta(hours=8), "success", "normal", 18, "LOW", "Isolation Forest baseline; known IP"),
        (user.id, "10.0.0.21", now - timedelta(hours=2), "failed", "normal", 28, "MEDIUM", "single failed password from known IP"),
        (user.id, "203.0.113.88", now - timedelta(minutes=40), "failed", "anomalous", 72, "HIGH", "Isolation Forest flagged anomaly; 5 failed logins in 1 hour; new IP during off-hours"),
        (admin.id, "10.0.0.5", now - timedelta(hours=5), "success", "normal", 8, "LOW", "Isolation Forest baseline; admin console login"),
    ]
    for uid, ip, ts, status, pred, score, sev, reason in samples:
        log = LoginLog(
            user_id=uid,
            ip_address=ip,
            timestamp=ts,
            login_status=status,
            user_agent="Mozilla/5.0 (synthetic seed)",
            email_attempted="user@soc.local" if uid == user.id else "admin@soc.local",
            anomaly_prediction=pred,
            risk_score=score,
            severity=sev,
            detection_reason=reason,
        )
        db.session.add(log)
        db.session.flush()
        if pred == "anomalous":
            db.session.add(
                ThreatAlert(
                    user_id=uid,
                    risk_score=score,
                    severity=sev,
                    detection_reason=reason,
                    alert_status="New",
                    login_log_id=log.id,
                    created_at=ts,
                )
            )
        db.session.add(ActivityLog(user_id=uid, activity_type="login" if status == "success" else "failed_login", timestamp=ts, resource_accessed="/login"))
    db.session.commit()


app = create_app()


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True, allow_unsafe_werkzeug=True)
=======
import os
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify

from config import config_by_name
from extensions import bcrypt, db, jwt, socketio
from models import ActivityLog, LoginLog, ThreatAlert, TokenBlocklist, User
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.pages import pages_bp
from routes.reports import reports_bp
from routes.security import security_bp


def create_app(config_name=None):
    config_name = config_name or os.getenv("FLASK_ENV", "development")
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_by_name.get(config_name, config_by_name["development"]))
    os.makedirs(app.instance_path, exist_ok=True)
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///"):
        db_name = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")
        if not os.path.isabs(db_name) and db_name != ":memory:":
            app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, os.path.basename(db_name))

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode=app.config.get("SOCKETIO_ASYNC_MODE", "threading"))

    app.register_blueprint(pages_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(reports_bp)

    @jwt.token_in_blocklist_loader
    def _revoked(_jwt_header, jwt_payload):
        jti = jwt_payload.get("jti")
        return TokenBlocklist.query.filter_by(jti=jti).first() is not None

    @jwt.unauthorized_loader
    def _unauth(msg):
        return jsonify({"error": "Missing or invalid token", "detail": msg}), 401

    @jwt.revoked_token_loader
    def _revoked_resp(_h, _p):
        return jsonify({"error": "Token revoked"}), 401

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify({"error": "Internal server error"}), 500

    with app.app_context():
        db.create_all()
        if not app.config.get("TESTING"):
            seed_if_empty()
            try:
                from ai_engine.detect_threat import load_models

                load_models()
            except Exception as exc:
                app.logger.warning("Model load deferred: %s", exc)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    return app


def seed_if_empty():
    if User.query.first():
        return
    from extensions import bcrypt as _bcrypt

    admin = User(
        name="SOC Administrator",
        email="admin@soc.local",
        password_hash=_bcrypt.generate_password_hash("Admin@123").decode("utf-8"),
        role="admin",
        account_status="active",
    )
    user = User(
        name="Jordan Hale",
        email="user@soc.local",
        password_hash=_bcrypt.generate_password_hash("User@123").decode("utf-8"),
        role="user",
        account_status="active",
    )
    db.session.add_all([admin, user])
    db.session.flush()
    now = datetime.now(timezone.utc)
    samples = [
        (user.id, "10.0.0.21", now - timedelta(hours=30), "success", "normal", 12, "LOW", "Isolation Forest baseline; typical office-hour login"),
        (user.id, "10.0.0.21", now - timedelta(hours=8), "success", "normal", 18, "LOW", "Isolation Forest baseline; known IP"),
        (user.id, "10.0.0.21", now - timedelta(hours=2), "failed", "normal", 28, "MEDIUM", "single failed password from known IP"),
        (user.id, "203.0.113.88", now - timedelta(minutes=40), "failed", "anomalous", 72, "HIGH", "Isolation Forest flagged anomaly; 5 failed logins in 1 hour; new IP during off-hours"),
        (admin.id, "10.0.0.5", now - timedelta(hours=5), "success", "normal", 8, "LOW", "Isolation Forest baseline; admin console login"),
    ]
    for uid, ip, ts, status, pred, score, sev, reason in samples:
        log = LoginLog(
            user_id=uid,
            ip_address=ip,
            timestamp=ts,
            login_status=status,
            user_agent="Mozilla/5.0 (synthetic seed)",
            email_attempted="user@soc.local" if uid == user.id else "admin@soc.local",
            anomaly_prediction=pred,
            risk_score=score,
            severity=sev,
            detection_reason=reason,
        )
        db.session.add(log)
        db.session.flush()
        if pred == "anomalous":
            db.session.add(
                ThreatAlert(
                    user_id=uid,
                    risk_score=score,
                    severity=sev,
                    detection_reason=reason,
                    alert_status="New",
                    login_log_id=log.id,
                    created_at=ts,
                )
            )
        db.session.add(ActivityLog(user_id=uid, activity_type="login" if status == "success" else "failed_login", timestamp=ts, resource_accessed="/login"))
    db.session.commit()


app = create_app()


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True, allow_unsafe_werkzeug=True)
>>>>>>> 5aeceaef23432e326a4511ac1320d8e8a6060045
