from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity

from extensions import db
from models.user import User
from services.authz import role_required
from services.logging_service import record_activity

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/users")
@role_required("admin")
def list_users():
    q = (request.args.get("q") or "").strip().lower()
    query = User.query
    if q:
        query = query.filter((User.email.ilike(f"%{q}%")) | (User.name.ilike(f"%{q}%")))
    users = query.order_by(User.created_at.desc()).all()
    record_activity(int(get_jwt_identity()), "list_users", "/admin/users")
    db.session.commit()
    return jsonify({"users": [u.to_dict() for u in users]})


@admin_bp.post("/users/<int:user_id>/status")
@role_required("admin")
def set_status(user_id):
    data = request.get_json(silent=True) or {}
    status = data.get("account_status")
    if status not in ("active", "deactivated", "locked"):
        return jsonify({"error": "account_status must be active, deactivated, or locked"}), 400
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.role == "admin" and status != "active":
        return jsonify({"error": "Cannot deactivate the admin account"}), 400
    user.account_status = status
    record_activity(int(get_jwt_identity()), "set_user_status", f"/admin/users/{user_id}")
    db.session.commit()
    return jsonify({"user": user.to_dict()})
