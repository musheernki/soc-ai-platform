"""Train Isolation Forest on the synthetic security_logs.csv sample.

The CSV is labelled for analysis only. Isolation Forest is unsupervised
and is trained on rows marked label=normal so the model learns a baseline
of typical office-hour, low-failure, stable-IP behaviour. Anomalous rows
are held out for evaluation, not used as ground-truth attack accuracy.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler

from ai_engine.preprocess import FEATURE_NAMES

BASE = Path(__file__).resolve().parent.parent
CSV_PATH = BASE / "dataset" / "security_logs.csv"
MODEL_DIR = Path(__file__).resolve().parent / "models"
ISO_PATH = MODEL_DIR / "isolation_forest.joblib"
RF_PATH = MODEL_DIR / "random_forest.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"


def generate_synthetic_frame(seed=42):
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(320):
        rows.append(
            [
                float(rng.integers(0, 2)),
                float(rng.integers(0, 3)),
                float(rng.integers(1, 8)),
                float(rng.integers(8, 18)),
                0.0,
                float(rng.integers(1, 3)),
                0.0,
                float(rng.integers(1, 3)),
                float(rng.integers(20, 400)),
                float(rng.integers(2, 20)),
                float(rng.uniform(0.0, 0.2)),
                "normal",
            ]
        )
    for _ in range(40):
        rows.append(
            [
                float(rng.integers(5, 14)),
                float(rng.integers(6, 20)),
                float(rng.integers(0, 2)),
                float(rng.choice([1, 2, 3, 4, 23])),
                float(rng.integers(0, 2)),
                float(rng.integers(3, 8)),
                1.0,
                float(rng.integers(8, 20)),
                float(rng.integers(0, 4)),
                float(rng.integers(0, 4)),
                float(rng.uniform(0.6, 1.0)),
                "anomalous",
            ]
        )
    return pd.DataFrame(rows, columns=FEATURE_NAMES + ["label"])


def load_dataset(path=None):
    path = Path(path or CSV_PATH)
    if path.exists():
        df = pd.read_csv(path)
        missing = [c for c in FEATURE_NAMES + ["label"] if c not in df.columns]
        if missing:
            raise ValueError(f"Dataset missing columns: {missing}")
        df = df.dropna(subset=FEATURE_NAMES)
        if len(df) >= 50:
            return df
    df = generate_synthetic_frame()
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    return df


def train(path=None):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    df = load_dataset(path)
    X = df[FEATURE_NAMES].astype(float).values
    y = (df["label"].str.lower() != "normal").astype(int).values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    normal_mask = y == 0
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42,
        n_jobs=1,
    )
    iso.fit(X_scaled[normal_mask])

    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=8,
        random_state=42,
        class_weight="balanced",
    )
    rf.fit(X_scaled, y)

    iso_pred = iso.predict(X_scaled)
    iso_anom = (iso_pred == -1).astype(int)
    print("Isolation Forest vs synthetic labels (not real-world accuracy):")
    print(classification_report(y, iso_anom, target_names=["normal", "anomalous"], zero_division=0))
    print("Random Forest vs synthetic labels (optional supervised helper):")
    print(classification_report(y, rf.predict(X_scaled), target_names=["normal", "anomalous"], zero_division=0))

    joblib.dump(iso, ISO_PATH)
    joblib.dump(rf, RF_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"Saved {ISO_PATH}")
    print(f"Saved {RF_PATH}")
    print(f"Saved {SCALER_PATH}")
    return iso, rf, scaler


if __name__ == "__main__":
    train()
