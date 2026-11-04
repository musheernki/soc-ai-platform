"""Score a login event with Isolation Forest + documented security rules."""

from pathlib import Path

import joblib
import numpy as np

from ai_engine.preprocess import FEATURE_NAMES, extract_features
from ai_engine.train_model import RF_PATH, ISO_PATH, SCALER_PATH, train

_iso = None
_rf = None
_scaler = None


RESTRICTED_RESOURCES = {"/admin", "/api/admin", "/settings/security", "/reports"}


def load_models(force=False):
    global _iso, _rf, _scaler
    if _iso is not None and not force:
        return _iso, _rf, _scaler
    if not ISO_PATH.exists() or not SCALER_PATH.exists():
        train()
    _iso = joblib.load(ISO_PATH)
    _scaler = joblib.load(SCALER_PATH)
    _rf = joblib.load(RF_PATH) if RF_PATH.exists() else None
    return _iso, _rf, _scaler


def isolation_risk(features):
    iso, _rf, scaler = load_models()
    x = np.array(features, dtype=float).reshape(1, -1)
    x_s = scaler.transform(x)
    pred = iso.predict(x_s)[0]
    # score_samples: higher is more normal. Typical range roughly [-0.5, 0.2]
    raw = float(iso.score_samples(x_s)[0])
    # Map more-anomalous (lower raw) to 0-100 risk.
    risk = int(np.clip((0.15 - raw) / 0.55 * 100, 0, 100))
    return pred == -1, risk, raw


def apply_rules(features, login_status, resource_accessed=None):
    """Return (boost 0-100, list of reason strings).

    Unusual IPs are a weak signal only. A new IP never becomes HIGH by itself.
    """
    reasons = []
    boost = 0
    failed_1h, failed_24h, success_24h, login_hour, is_weekend, unique_ips, ip_is_new, logins_10min, minutes_since_last, activity_24h, fail_ratio = features

    if failed_1h >= 10:
        boost += 40
        reasons.append(f"{int(failed_1h)} failed logins in 1 hour (lockout threshold)")
    elif failed_1h >= 5:
        boost += 25
        reasons.append(f"{int(failed_1h)} failed logins in 1 hour")
    elif failed_1h >= 3:
        boost += 12
        reasons.append(f"{int(failed_1h)} failed logins in 1 hour")

    if fail_ratio >= 0.7 and failed_24h >= 4:
        boost += 10
        reasons.append(f"high 24h failure ratio ({fail_ratio:.2f})")

    if logins_10min >= 12:
        boost += 20
        reasons.append(f"burst of {int(logins_10min)} attempts in 10 minutes")
    elif logins_10min >= 8:
        boost += 10
        reasons.append(f"elevated frequency: {int(logins_10min)} attempts in 10 minutes")

    unusual_hour = login_hour <= 5 or login_hour >= 23
    if unusual_hour and ip_is_new:
        boost += 12
        reasons.append("new IP during off-hours (supporting signal, not proof of malice)")
    elif unusual_hour and login_status == "failed":
        boost += 8
        reasons.append("failed attempt during off-hours")

    if unique_ips >= 4:
        boost += 10
        reasons.append(f"{int(unique_ips)} distinct IPs in 24h")
    elif ip_is_new and login_status == "success":
        boost += 4
        reasons.append("first-seen IP for this account (informational)")

    if resource_accessed in RESTRICTED_RESOURCES and login_status != "success":
        boost += 15
        reasons.append(f"restricted resource access: {resource_accessed}")

    return min(boost, 50), reasons


def severity_from_score(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def analyse_login(user, ip_address, timestamp, login_status, login_logs, activity_logs, resource_accessed=None):
    features = extract_features(user, ip_address, timestamp, login_logs, activity_logs)
    is_anom, ml_risk, raw = isolation_risk(features)
    boost, rule_reasons = apply_rules(features, login_status, resource_accessed)
    score = int(np.clip(ml_risk + boost, 0, 100))
    # Successful quiet logins should not be escalated solely by a noisy model edge.
    if login_status == "success" and not rule_reasons and not is_anom:
        score = min(score, 20)
    reasons = []
    if is_anom:
        reasons.append(f"Isolation Forest flagged anomaly (score_samples={raw:.4f}, ml_risk={ml_risk})")
    else:
        reasons.append(f"Isolation Forest baseline (score_samples={raw:.4f}, ml_risk={ml_risk})")
    reasons.extend(rule_reasons)
    prediction = "anomalous" if is_anom or score >= 50 else "normal"
    return {
        "features": dict(zip(FEATURE_NAMES, features)),
        "anomaly_prediction": prediction,
        "isolation_forest_anomalous": bool(is_anom),
        "ml_risk": ml_risk,
        "rule_boost": boost,
        "risk_score": score,
        "severity": severity_from_score(score),
        "detection_reason": "; ".join(reasons),
        "raw_score_samples": raw,
    }
