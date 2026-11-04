from functools import wraps

from flask import jsonify
from flask_jwt_extended import get_jwt, jwt_required, verify_jwt_in_request


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") not in roles:
                return jsonify({"error": "Forbidden: insufficient role"}), 403
            if claims.get("account_status") == "deactivated":
                return jsonify({"error": "Account deactivated"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def current_role():
    verify_jwt_in_request()
    return get_jwt().get("role")
