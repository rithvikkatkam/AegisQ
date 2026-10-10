"""Inference helpers for AegisQ risk forecasting."""
from __future__ import annotations

import sqlite3
from pathlib import Path
import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "data" / "aegisq.db"
MODEL_PATH = Path(__file__).resolve().parent / "risk_forecast_model.joblib"

def load_artifact():
    if not MODEL_PATH.exists():
        raise FileNotFoundError("ML model not found. Run `python3 ml/train.py` first.")
    return joblib.load(MODEL_PATH)

def latest_features(asset_id: str):
    conn = sqlite3.connect(DB_PATH)
    h = pd.read_sql_query(
        "SELECT date, expected_annual_loss_inr, risk_score FROM risk_scores_history "
        "WHERE asset_id = ? ORDER BY date", conn, params=(asset_id,))
    a = pd.read_sql_query(
        "SELECT criticality FROM assets WHERE id = ?", conn, params=(asset_id,))
    v = pd.read_sql_query(
        "SELECT cvss_score, epss_score FROM vulnerabilities WHERE asset_id = ?", conn, params=(asset_id,))
    conn.close()
    if h.empty or a.empty:
        raise ValueError(f"Unknown asset or insufficient history: {asset_id}")
    if len(h) < 8:
        raise ValueError(f"Asset {asset_id} needs at least 8 history rows.")
    latest = h.iloc[-1]
    lag1 = h.iloc[-2]
    lag7 = h.iloc[-8]
    rolling = h["risk_score"].tail(7)
    return {
        "criticality": float(a.iloc[0]["criticality"]),
        "vulnerability_count": int(len(v)),
        "avg_cvss": float(v["cvss_score"].mean() if not v.empty else 0),
        "max_cvss": float(v["cvss_score"].max() if not v.empty else 0),
        "avg_epss": float(v["epss_score"].mean() if not v.empty else 0),
        "max_epss": float(v["epss_score"].max() if not v.empty else 0),
        "risk_score": float(latest["risk_score"]),
        "expected_annual_loss_inr": float(latest["expected_annual_loss_inr"]),
        "risk_lag_1": float(lag1["risk_score"]),
        "risk_lag_7": float(lag7["risk_score"]),
        "loss_lag_1": float(lag1["expected_annual_loss_inr"]),
        "risk_rolling_mean_7": float(rolling.mean()),
        "risk_rolling_std_7": float(rolling.std() or 0),
        "risk_change_7d": float(latest["risk_score"] - lag7["risk_score"]),
        "loss_change_7d": float(latest["expected_annual_loss_inr"] - lag1["expected_annual_loss_inr"]),
    }

def predict_asset(asset_id: str):
    artifact = load_artifact()
    vals = latest_features(asset_id)
    X = pd.DataFrame([{f: vals[f] for f in artifact["features"]}])
    prediction = float(artifact["model"].predict(X)[0])
    prediction = max(0.0, min(100.0, prediction))
    current = vals["risk_score"]
    current_loss = vals["expected_annual_loss_inr"]
    # Current risk score is a bounded display score. Use the ratio between
    # predicted and current score to estimate next-day monetary exposure.
    predicted_loss = current_loss * (prediction / current) if current > 0 else current_loss
    return {
        "asset_id": asset_id,
        "current_risk_score": round(current, 2),
        "predicted_next_day_risk_score": round(prediction, 2),
        "predicted_risk_score": round(prediction, 2),
        "risk_change": round(prediction - current, 2),
        "current_expected_annual_loss_inr": round(current_loss, 2),
        "predicted_next_day_expected_annual_loss_inr": round(predicted_loss, 2),
        "metrics": artifact["metrics"],
        "model_metrics": artifact["metrics"],
        "trained_until": artifact["trained_until"],
        "feature_importance": artifact["feature_importance"][:8],
    }
