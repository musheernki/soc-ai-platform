"""Write dataset/security_logs.csv with synthetic feature rows."""

from pathlib import Path

import numpy as np
import pandas as pd

from ai_engine.preprocess import FEATURE_NAMES

RNG = np.random.default_rng(42)


def main():
    rows = []
    for _ in range(320):
        hour = int(RNG.integers(8, 18))
        rows.append(
            {
                "failed_1h": float(RNG.integers(0, 2)),
                "failed_24h": float(RNG.integers(0, 3)),
                "success_24h": float(RNG.integers(1, 8)),
                "login_hour": float(hour),
                "is_weekend": 0.0,
                "unique_ips_24h": float(RNG.integers(1, 3)),
                "ip_is_new": 0.0,
                "logins_10min": float(RNG.integers(1, 3)),
                "minutes_since_last": float(RNG.integers(20, 400)),
                "activity_24h": float(RNG.integers(2, 20)),
                "fail_ratio_24h": float(RNG.uniform(0.0, 0.2)),
                "label": "normal",
            }
        )
    for _ in range(40):
        rows.append(
            {
                "failed_1h": float(RNG.integers(5, 14)),
                "failed_24h": float(RNG.integers(6, 20)),
                "success_24h": float(RNG.integers(0, 2)),
                "login_hour": float(RNG.choice([1, 2, 3, 4, 23])),
                "is_weekend": float(RNG.integers(0, 2)),
                "unique_ips_24h": float(RNG.integers(3, 8)),
                "ip_is_new": 1.0,
                "logins_10min": float(RNG.integers(8, 20)),
                "minutes_since_last": float(RNG.integers(0, 4)),
                "activity_24h": float(RNG.integers(0, 4)),
                "fail_ratio_24h": float(RNG.uniform(0.6, 1.0)),
                "label": "anomalous",
            }
        )
    df = pd.DataFrame(rows, columns=FEATURE_NAMES + ["label"])
    out = Path(__file__).resolve().parent / "security_logs.csv"
    df.to_csv(out, index=False)
    print(f"Wrote {len(df)} rows to {out}")


if __name__ == "__main__":
    main()
