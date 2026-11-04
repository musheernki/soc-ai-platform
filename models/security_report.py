from datetime import datetime, timezone

from extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class SecurityReport(db.Model):
    __tablename__ = "security_reports"

    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(80), nullable=False)
    report_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    generated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "report_type": self.report_type,
            "report_data": self.report_data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "generated_by": self.generated_by,
        }
