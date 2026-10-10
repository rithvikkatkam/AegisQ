"""Train AegisQ's next-day asset risk forecasting model.

The model uses only information available at or before each historical
timestamp. A time-based split prevents future leakage into training.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "data" / "aegisq.db"
MODEL_PATH = Path(__file__).resolve().parent / "risk_forecast_model.joblib"

FEATURES = [
    "criticality", "vulnerability_count", "avg_cvss", "max_cvss",
    "avg_epss", "max_epss", "risk_score", "expected_annual_loss_inr",
    "risk_lag_1", "risk_lag_7", "loss_lag_1", "risk_rolling_mean_7",
    "risk_rolling_std_7", "risk_change_7d", "loss_change_7d",
]

def load_frames():
    conn = sqlite3.connect(DB_PATH)
    history = pd.read_sql_query(
        "SELECT asset_id, date, expected_annual_loss_inr, risk_score "
        "FROM risk_scores_history ORDER BY asset_id, date", conn)
    assets = pd.read_sql_query(
        "SELECT id AS asset_id, criticality FROM assets", conn)
    vulns = pd.read_sql_query(
        "SELECT asset_id, cvss_score, epss_score FROM vulnerabilities", conn)
    conn.close()
    history["date"] = pd.to_datetime(history["date"], utc=True)
    return history, assets, vulns

def build_features(history, assets, vulns):
    vf = vulns.groupby("asset_id").agg(
        vulnerability_count=("asset_id", "count"),
        avg_cvss=("cvss_score", "mean"),
        max_cvss=("cvss_score", "max"),
        avg_epss=("epss_score", "mean"),
        max_epss=("epss_score", "max"),
    ).reset_index()
    df = history.merge(assets, on="asset_id", how="left").merge(vf, on="asset_id", how="left")
    df = df.sort_values(["asset_id", "date"]).fillna(0)
    g = df.groupby("asset_id", group_keys=False)
    df["risk_lag_1"] = g["risk_score"].shift(1)
    df["risk_lag_7"] = g["risk_score"].shift(7)
    df["loss_lag_1"] = g["expected_annual_loss_inr"].shift(1)
    df["risk_rolling_mean_7"] = g["risk_score"].transform(lambda x: x.rolling(7).mean())
    df["risk_rolling_std_7"] = g["risk_score"].transform(lambda x: x.rolling(7).std())
    df["risk_change_7d"] = df["risk_score"] - df["risk_lag_7"]
    df["loss_change_7d"] = df["expected_annual_loss_inr"] - df["loss_lag_1"]
    df["target_risk_score"] = g["risk_score"].shift(-1)
    return df.dropna(subset=FEATURES + ["target_risk_score"]).copy()

def train():
    history, assets, vulns = load_frames()
    if history.empty:
        raise RuntimeError("risk_scores_history is empty; run the data pipeline first.")
    df = build_features(history, assets, vulns)
    cutoff = df["date"].quantile(0.80)
    train_df = df[df["date"] <= cutoff]
    test_df = df[df["date"] > cutoff]
    model = RandomForestRegressor(
        n_estimators=300, max_depth=12, min_samples_leaf=2,
        random_state=42, n_jobs=-1,
    )
    model.fit(train_df[FEATURES], train_df["target_risk_score"])
    pred = model.predict(test_df[FEATURES])
    mae = mean_absolute_error(test_df["target_risk_score"], pred)
    rmse = np.sqrt(mean_squared_error(test_df["target_risk_score"], pred))
    r2 = r2_score(test_df["target_risk_score"], pred)
    importances = pd.DataFrame({"feature": FEATURES, "importance": model.feature_importances_})
    importances = importances.sort_values("importance", ascending=False)
    artifact = {
        "model": model,
        "features": FEATURES,
        "metrics": {"mae": float(mae), "rmse": float(rmse), "r2": float(r2)},
        "trained_until": str(train_df["date"].max().date()),
        "test_until": str(test_df["date"].max().date()),
        "feature_importance": importances.to_dict("records"),
    }
    joblib.dump(artifact, MODEL_PATH)
    print(f"Rows: {len(df):,} | train: {len(train_df):,} | test: {len(test_df):,}")
    print(f"MAE: {mae:.4f}")
    print(f"RMSE: {rmse:.4f}")
    print(f"R2: {r2:.4f}")
    print("\nFeature importance:")
    print(importances.to_string(index=False))
    print(f"\nSaved model: {MODEL_PATH}")

if __name__ == "__main__":
    train()
