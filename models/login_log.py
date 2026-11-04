from datetime import datetime, timezone

from extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class LoginLog(db.Model):
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    login_status = db.Column(db.String(20), nullable=False)
    user_agent = db.Column(db.String(512), nullable=True)
    email_attempted = db.Column(db.String(255), nullable=True)
    anomaly_prediction = db.Column(db.String(20), nullable=True)
    risk_score = db.Column(db.Float, nullable=True)
    severity = db.Column(db.String(20), nullable=True)
    detection_reason = db.Column(db.Text, nullable=True)

    user = db.relationship("User", back_populates="login_logs")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.user.email if self.user else self.email_attempted,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "login_status": self.login_status,
            "user_agent": self.user_agent,
            "anomaly_prediction": self.anomaly_prediction,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "detection_reason": self.detection_reason,
        }
