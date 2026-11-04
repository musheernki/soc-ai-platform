from datetime import datetime, timezone

from extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class ThreatAlert(db.Model):
    __tablename__ = "threat_alerts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    risk_score = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)
    detection_reason = db.Column(db.Text, nullable=False)
    alert_status = db.Column(db.String(20), nullable=False, default="New", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    login_log_id = db.Column(db.Integer, db.ForeignKey("login_logs.id"), nullable=True)

    user = db.relationship("User", back_populates="threat_alerts")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.user.email if self.user else None,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "detection_reason": self.detection_reason,
            "alert_status": self.alert_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "login_log_id": self.login_log_id,
        }
