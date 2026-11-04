from models.activity_log import ActivityLog
from models.login_log import LoginLog
from ai_engine.detect_threat import analyse_login


def score_attempt(user, ip_address, timestamp, login_status, resource_accessed=None):
    user_id = user.id if user else None
    login_query = LoginLog.query
    activity_query = ActivityLog.query
    if user_id:
        login_logs = login_query.filter(LoginLog.user_id == user_id).order_by(LoginLog.timestamp.desc()).limit(500).all()
        activity_logs = activity_query.filter(ActivityLog.user_id == user_id).order_by(ActivityLog.timestamp.desc()).limit(500).all()
    else:
        login_logs = []
        activity_logs = []
    return analyse_login(
        user,
        ip_address,
        timestamp,
        login_status,
        login_logs,
        activity_logs,
        resource_accessed=resource_accessed,
    )
