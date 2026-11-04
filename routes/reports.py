import csv
import io
import json
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request
from flask_jwt_extended import get_jwt_identity
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from extensions import db
from models.login_log import LoginLog
from models.security_report import SecurityReport
from models.threat_alert import ThreatAlert
from services.authz import role_required
from services.logging_service import record_activity

reports_bp = Blueprint("reports", __name__, url_prefix="/api/reports")


def utcnow():
    return datetime.now(timezone.utc)


def build_summary():
    logs = LoginLog.query.all()
    alerts = ThreatAlert.query.all()
    by_day = {}
    for log in logs:
        key = log.timestamp.date().isoformat() if log.timestamp else "unknown"
        by_day.setdefault(key, {"success": 0, "failed": 0, "anomalous": 0})
        by_day[key][log.login_status] = by_day[key].get(log.login_status, 0) + 1
        if log.anomaly_prediction == "anomalous":
            by_day[key]["anomalous"] += 1
    severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for a in alerts:
        severity[a.severity] = severity.get(a.severity, 0) + 1
    return {
        "generated_at": utcnow().isoformat(),
        "total_login_attempts": len(logs),
        "failed_login_attempts": sum(1 for x in logs if x.login_status == "failed"),
        "successful_logins": sum(1 for x in logs if x.login_status == "success"),
        "detected_anomalies": sum(1 for x in logs if x.anomaly_prediction == "anomalous"),
        "threat_severity": severity,
        "date_wise_activity": by_day,
        "alert_count": len(alerts),
    }


@reports_bp.get("/summary")
@role_required("admin")
def summary():
    data = build_summary()
    row = SecurityReport(report_type="summary", report_data=json.dumps(data), generated_by=int(get_jwt_identity()))
    db.session.add(row)
    record_activity(int(get_jwt_identity()), "generate_report", "/reports/summary")
    db.session.commit()
    return jsonify({"report": data, "id": row.id})


@reports_bp.get("/export.csv")
@role_required("admin")
def export_csv():
    data = build_summary()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["metric", "value"])
    writer.writerow(["generated_at", data["generated_at"]])
    writer.writerow(["total_login_attempts", data["total_login_attempts"]])
    writer.writerow(["failed_login_attempts", data["failed_login_attempts"]])
    writer.writerow(["successful_logins", data["successful_logins"]])
    writer.writerow(["detected_anomalies", data["detected_anomalies"]])
    writer.writerow([])
    writer.writerow(["severity", "count"])
    for k, v in data["threat_severity"].items():
        writer.writerow([k, v])
    writer.writerow([])
    writer.writerow(["date", "success", "failed", "anomalous"])
    for day, vals in sorted(data["date_wise_activity"].items()):
        writer.writerow([day, vals.get("success", 0), vals.get("failed", 0), vals.get("anomalous", 0)])
    record_activity(int(get_jwt_identity()), "export_csv", "/reports/export.csv")
    db.session.commit()
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc-security-report.csv"},
    )


@reports_bp.get("/export.pdf")
@role_required("admin")
def export_pdf():
    data = build_summary()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("SOC Security Report (Synthetic / Local Telemetry)", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Generated: {data['generated_at']}", styles["Normal"]),
        Spacer(1, 12),
    ]
    table_data = [
        ["Metric", "Value"],
        ["Total login attempts", str(data["total_login_attempts"])],
        ["Failed logins", str(data["failed_login_attempts"])],
        ["Successful logins", str(data["successful_logins"])],
        ["Detected anomalies", str(data["detected_anomalies"])],
        ["Alerts", str(data["alert_count"])],
        ["LOW", str(data["threat_severity"]["LOW"])],
        ["MEDIUM", str(data["threat_severity"]["MEDIUM"])],
        ["HIGH", str(data["threat_severity"]["HIGH"])],
        ["CRITICAL", str(data["threat_severity"]["CRITICAL"])],
    ]
    table = Table(table_data, colWidths=[250, 200])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1f3a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f4f7fb")),
            ]
        )
    )
    story.append(table)
    doc.build(story)
    record_activity(int(get_jwt_identity()), "export_pdf", "/reports/export.pdf")
    db.session.commit()
    return Response(
        buf.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=soc-security-report.pdf"},
    )
