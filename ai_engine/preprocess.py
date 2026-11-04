"""Feature extraction for login events.

Features (all numeric):
0 failed_1h           - failed logins for this identity in the last hour
1 failed_24h          - failed logins in the last 24 hours
2 success_24h         - successful logins in the last 24 hours
3 login_hour          - hour of day 0-23
4 is_weekend          - 1 if Saturday/Sunday
5 unique_ips_24h      - distinct IPs for this user in 24h
6 ip_is_new           - 1 if this IP was not seen for the user in 30 days
7 logins_10min        - login attempts in last 10 minutes
8 minutes_since_last  - minutes since previous attempt (capped)
9 activity_24h        - activity_log rows in last 24 hours
10 fail_ratio_24h     - failed / max(total, 1) in 24 hours
"""

from datetime import datetime, timedelta, timezone

FEATURE_NAMES = [
    "failed_1h",
    "failed_24h",
    "success_24h",
    "login_hour",
    "is_weekend",
    "unique_ips_24h",
    "ip_is_new",
    "logins_10min",
    "minutes_since_last",
    "activity_24h",
    "fail_ratio_24h",
]


def _aware(dt):
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def extract_features(user, ip_address, timestamp, login_logs, activity_logs):
    ts = _aware(timestamp)
    hour_ago = ts - timedelta(hours=1)
    day_ago = ts - timedelta(hours=24)
    ten_min = ts - timedelta(minutes=10)
    month_ago = ts - timedelta(days=30)

    failed_1h = 0
    failed_24h = 0
    success_24h = 0
    ips_24h = set()
    known_ips = set()
    logins_10min = 0
    last_ts = None
    total_24h = 0

    for log in login_logs:
        lts = _aware(log.timestamp)
        if lts > ts:
            continue
        if log.ip_address and lts >= month_ago:
            known_ips.add(log.ip_address)
        if lts >= day_ago:
            total_24h += 1
            if log.ip_address:
                ips_24h.add(log.ip_address)
            if log.login_status == "failed":
                failed_24h += 1
            elif log.login_status == "success":
                success_24h += 1
        if lts >= hour_ago and log.login_status == "failed":
            failed_1h += 1
        if lts >= ten_min:
            logins_10min += 1
        if last_ts is None or lts > last_ts:
            last_ts = lts

    ips_24h.add(ip_address)
    ip_is_new = 0 if ip_address in known_ips else 1
    minutes_since_last = 1440.0
    if last_ts is not None:
        minutes_since_last = min(1440.0, max(0.0, (ts - last_ts).total_seconds() / 60.0))

    activity_24h = 0
    for act in activity_logs:
        if _aware(act.timestamp) >= day_ago:
            activity_24h += 1

    fail_ratio = failed_24h / max(total_24h, 1)
    is_weekend = 1 if ts.weekday() >= 5 else 0

    return [
        float(failed_1h),
        float(failed_24h),
        float(success_24h),
        float(ts.hour),
        float(is_weekend),
        float(len(ips_24h)),
        float(ip_is_new),
        float(logins_10min + 1),
        float(minutes_since_last),
        float(activity_24h),
        float(fail_ratio),
    ]
