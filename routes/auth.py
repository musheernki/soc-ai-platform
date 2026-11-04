import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
)
from sqlalchemy import func

from extensions import bcrypt, db
from models.login_log import LoginLog
from models.password_reset import PasswordResetToken
from models.token_blocklist import TokenBlocklist
from models.user import User
from services.alert_service import maybe_create_alert
from services.logging_service import client_ip, record_activity, record_login
from services.risk_service import score_attempt

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def utcnow():
    return datetime.now(timezone.utc)


def validate_email(email):
    if not email or "@" not in email or len(email) > 255:
        return False
    local, _, domain = email.partition("@")
    return bool(local and domain and "." in domain)


def validate_password(password):
    if not password or len(password) < 8:
        return "Password must be at least 8 characters"
    if password.lower() == password or password.upper() == password:
        return "Password must include upper and lower case letters"
    if not any(c.isdigit() for c in password):
        return "Password must include a number"
    return None


def recent_failures(user):
    window = utcnow() - timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
    return (
        LoginLog.query.filter(
            LoginLog.user_id == user.id,
            LoginLog.login_status == "failed",
            LoginLog.timestamp >= window,
        ).count()
    )


def is_locked(user):
    if user.account_status == "deactivated":
        return True, "Account is deactivated"
    if user.account_status == "locked":
        last_fail = (
            LoginLog.query.filter_by(user_id=user.id, login_status="failed")
            .order_by(LoginLog.timestamp.desc())
            .first()
        )
        if last_fail:
            unlock_at = last_fail.timestamp.replace(tzinfo=timezone.utc) + timedelta(
                minutes=current_app.config["LOCKOUT_MINUTES"]
            )
            if utcnow() < unlock_at:
                return True, "Account locked after repeated failed logins. Try later."
            user.account_status = "active"
            db.session.commit()
        else:
            user.account_status = "active"
            db.session.commit()
    if recent_failures(user) >= current_app.config["MAX_FAILED_LOGINS"]:
        user.account_status = "locked"
        db.session.commit()
        return True, "Account locked after repeated failed logins. Try later."
    return False, None


@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not name or len(name) > 120:
        return jsonify({"error": "Name is required"}), 400
    if not validate_email(email):
        return jsonify({"error": "Valid email is required"}), 400
    pw_err = validate_password(password)
    if pw_err:
        return jsonify({"error": pw_err}), 400
    if User.query.filter(func.lower(User.email) == email).first():
        return jsonify({"error": "Email already registered"}), 409
    user = User(
        name=name,
        email=email,
        password_hash=bcrypt.generate_password_hash(password).decode("utf-8"),
        role="user",
        account_status="active",
    )
    db.session.add(user)
    db.session.commit()
    record_activity(user.id, "register", "/register")
    db.session.commit()
    return jsonify({"message": "Registered", "user": user.to_dict()}), 201


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    ip = client_ip(request)
    ua = request.headers.get("User-Agent", "")
    user = User.query.filter(func.lower(User.email) == email).first()

    if user:
        locked, reason = is_locked(user)
        if locked:
            analysis = score_attempt(user, ip, utcnow(), "failed")
            log = record_login(user.id, ip, "failed", ua, email, analysis)
            maybe_create_alert(user.id, log, analysis)
            db.session.commit()
            return jsonify({"error": reason, "risk_score": analysis["risk_score"]}), 423

    valid = bool(user and bcrypt.check_password_hash(user.password_hash, password))
    status = "success" if valid else "failed"
    analysis = score_attempt(user, ip, utcnow(), status)
    log = record_login(user.id if user else None, ip, status, ua, email, analysis)
    maybe_create_alert(user.id if user else None, log, analysis)

    if not valid:
        if user and recent_failures(user) >= current_app.config["MAX_FAILED_LOGINS"]:
            user.account_status = "locked"
        db.session.commit()
        return jsonify({"error": "Invalid email or password"}), 401

    record_activity(user.id, "login", "/login")
    db.session.commit()
    token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "email": user.email, "account_status": user.account_status},
    )
    resp = jsonify(
        {
            "access_token": token,
            "user": user.to_dict(),
            "risk_score": analysis["risk_score"],
            "severity": analysis["severity"],
        }
    )
    set_access_cookies(resp, token)
    return resp


@auth_bp.post("/logout")
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti))
    uid = int(get_jwt_identity())
    record_activity(uid, "logout", "/logout")
    db.session.commit()
    resp = jsonify({"message": "Logged out"})
    unset_jwt_cookies(resp)
    return resp


@auth_bp.get("/me")
@jwt_required()
def me():
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"user": user.to_dict()})


@auth_bp.put("/profile")
@jwt_required()
def update_profile():
    user = db.session.get(User, int(get_jwt_identity()))
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or user.name).strip()
    if not name or len(name) > 120:
        return jsonify({"error": "Invalid name"}), 400
    user.name = name
    new_pw = data.get("password")
    if new_pw:
        err = validate_password(new_pw)
        if err:
            return jsonify({"error": err}), 400
        user.password_hash = bcrypt.generate_password_hash(new_pw).decode("utf-8")
    record_activity(user.id, "update_profile", "/profile")
    db.session.commit()
    return jsonify({"user": user.to_dict()})


@auth_bp.post("/forgot-password")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    user = User.query.filter(func.lower(User.email) == email).first()
    payload = {"message": "If that account exists, a reset token was issued."}
    if not user:
        return jsonify(payload)
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    row = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=utcnow() + timedelta(minutes=30),
        used=False,
    )
    db.session.add(row)
    record_activity(user.id, "forgot_password", "/forgot-password")
    db.session.commit()
    if current_app.config.get("EXPOSE_RESET_TOKEN"):
        payload["reset_token"] = raw
        payload["dev_note"] = "Token returned only because EXPOSE_RESET_TOKEN=true. Disable in production."
    return jsonify(payload)


@auth_bp.post("/reset-password")
def reset_password():
    data = request.get_json(silent=True) or {}
    raw = data.get("token") or ""
    password = data.get("password") or ""
    err = validate_password(password)
    if err:
        return jsonify({"error": err}), 400
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    row = PasswordResetToken.query.filter_by(token_hash=token_hash, used=False).first()
    if not row:
        return jsonify({"error": "Invalid or used token"}), 400
    exp = row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
    if exp < utcnow():
        return jsonify({"error": "Token expired"}), 400
    user = db.session.get(User, row.user_id)
    user.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user.account_status = "active"
    row.used = True
    record_activity(user.id, "reset_password", "/reset-password")
    db.session.commit()
    return jsonify({"message": "Password updated"})
