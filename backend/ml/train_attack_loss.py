"""Train the AegisQ historical attack-loss calibration model.

The model predicts log(1 + reported incident loss) from incident, vulnerability,
and asset context. It is a supplementary calibration signal, not a replacement
for the deterministic FAIR-style annual exposure calculation.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "data" / "aegisq.db"
MODEL_PATH = Path(__file__).resolve().parent / "attack_loss_model.joblib"

NUMERIC = [
    "cvss_score", "epss_score", "criticality", "records_affected",
    "asset_vulnerability_count", "asset_avg_cvss", "asset_max_cvss",
    "asset_avg_epss", "asset_max_epss",
]
CATEGORICAL = ["attack_category", "actor_type", "target_type", "asset_category"]


def load() -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    q = """
    SELECT
        ai.id AS incident_id,
        ai.loss_inr,
        ai.attack_category,
        ai.actor_type,
        ai.target_type,
        COALESCE(ai.records_affected, 0) AS records_affected,
        COALESCE(v.cvss_score, 0) AS cvss_score,
        COALESCE(v.epss_score, 0) AS epss_score,
        COALESCE(a.criticality, 0) AS criticality,
        COALESCE(a.category, 'Unknown') AS asset_category,
        COALESCE(ai.incident_date, '1900-01-01') AS incident_date,
        (
            SELECT COUNT(*) FROM vulnerabilities vx
            WHERE vx.asset_id = ai.asset_id
        ) AS asset_vulnerability_count,
        (
            SELECT COALESCE(AVG(vx.cvss_score), 0) FROM vulnerabilities vx
            WHERE vx.asset_id = ai.asset_id
        ) AS asset_avg_cvss,
        (
            SELECT COALESCE(MAX(vx.cvss_score), 0) FROM vulnerabilities vx
            WHERE vx.asset_id = ai.asset_id
        ) AS asset_max_cvss,
        (
            SELECT COALESCE(AVG(vx.epss_score), 0) FROM vulnerabilities vx
            WHERE vx.asset_id = ai.asset_id
        ) AS asset_avg_epss,
        (
            SELECT COALESCE(MAX(vx.epss_score), 0) FROM vulnerabilities vx
            WHERE vx.asset_id = ai.asset_id
        ) AS asset_max_epss
    FROM attack_incidents ai
    LEFT JOIN vulnerabilities v ON v.id = ai.vulnerability_id
    LEFT JOIN assets a ON a.id = ai.asset_id
    WHERE ai.loss_inr >= 0
    ORDER BY ai.incident_date ASC, ai.id ASC
    """
    df = pd.read_sql_query(q, conn)
    conn.close()
    if df.empty:
        return df
    for col in NUMERIC + ["loss_inr"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
    for col in CATEGORICAL:
        df[col] = df[col].fillna("Unknown").astype(str)
    df["loss_log1p_inr"] = np.log1p(df["loss_inr"])
    return df


def train() -> None:
    df = load()
    if len(df) < 20:
        raise RuntimeError(f"Need at least 20 incidents; found {len(df)}")

    split = max(10, int(len(df) * 0.20))
    train_df = df.iloc[:-split].copy()
    test_df = df.iloc[-split:].copy()

    pre = ColumnTransformer([
        ("num", "passthrough", NUMERIC),
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
    ])
    model = Pipeline([
        ("preprocess", pre),
        ("model", RandomForestRegressor(
            n_estimators=500,
            max_depth=10,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    model.fit(train_df[NUMERIC + CATEGORICAL], train_df["loss_log1p_inr"])
    pred_log = model.predict(test_df[NUMERIC + CATEGORICAL])
    pred_inr = np.maximum(0.0, np.expm1(pred_log))

    metrics = {
        "mae_log": float(mean_absolute_error(test_df["loss_log1p_inr"], pred_log)),
        "rmse_log": float(np.sqrt(mean_squared_error(test_df["loss_log1p_inr"], pred_log))),
        "r2_log": float(r2_score(test_df["loss_log1p_inr"], pred_log)),
        "mae_inr": float(mean_absolute_error(test_df["loss_inr"], pred_inr)),
        "rmse_inr": float(np.sqrt(mean_squared_error(test_df["loss_inr"], pred_inr))),
    }

    artifact = {
        "model": model,
        "numeric_features": NUMERIC,
        "categorical_features": CATEGORICAL,
        "metrics": metrics,
        "rows": int(len(df)),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "target": "loss_log1p_inr",
        "warning": "Historical monetary outcomes are supplied/unverified and this model is calibration-only.",
    }
    joblib.dump(artifact, MODEL_PATH)

    print(f"Rows: {len(df)} | train: {len(train_df)} | test: {len(test_df)}")
    print(f"MAE(log): {metrics['mae_log']:.4f}")
    print(f"RMSE(log): {metrics['rmse_log']:.4f}")
    print(f"R2(log): {metrics['r2_log']:.4f}")
    print(f"MAE(INR): {metrics['mae_inr']:,.2f}")
    print(f"Saved model: {MODEL_PATH}")


if __name__ == "__main__":
    train()
