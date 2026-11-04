from flask import Blueprint, render_template

pages_bp = Blueprint("pages", __name__)


@pages_bp.get("/")
def index():
    return render_template("login.html")


@pages_bp.get("/login")
def login_page():
    return render_template("login.html")


@pages_bp.get("/register")
def register_page():
    return render_template("register.html")


@pages_bp.get("/forgot-password")
def forgot_page():
    return render_template("forgot_password.html")


@pages_bp.get("/reset-password")
def reset_page():
    return render_template("reset_password.html")


@pages_bp.get("/app/dashboard")
def dashboard_page():
    return render_template("admin_dashboard.html")


@pages_bp.get("/app/user")
def user_dashboard_page():
    return render_template("user_dashboard.html")


@pages_bp.get("/app/users")
def users_page():
    return render_template("users.html")


@pages_bp.get("/app/monitoring")
def monitoring_page():
    return render_template("security_monitoring.html")


@pages_bp.get("/app/threats")
def threats_page():
    return render_template("threat_detection.html")


@pages_bp.get("/app/alerts")
def alerts_page():
    return render_template("alerts.html")


@pages_bp.get("/app/history")
def history_page():
    return render_template("login_history.html")


@pages_bp.get("/app/reports")
def reports_page():
    return render_template("reports.html")


@pages_bp.get("/app/settings")
def settings_page():
    return render_template("settings.html")
