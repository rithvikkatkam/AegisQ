"""Inference helpers for the historical attack-loss calibration model."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "data" / "aegisq.db"
MODEL_PATH = Path(__file__).resolve().parent / "attack_loss_model.joblib"


def load_attack_loss_artifact():
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Attack-loss model not found. Run `python3 ml/train_attack_loss.py`.")
    return joblib.load(MODEL_PATH)


def _build_query(extra: str = "", params=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    q = """
    SELECT
        ai.id AS incident_id,
        ai.attack_category,
        ai.actor_type,
        ai.target_type,
        COALESCE(ai.records_affected, 0) AS records_affected,
        COALESCE(ai.loss_inr, 0) AS loss_inr,
        COALESCE(v.cvss_score, 0) AS cvss_score,
        COALESCE(v.epss_score, 0) AS epss_score,
        COALESCE(a.criticality, 0) AS criticality,
        COALESCE(a.category, 'Unknown') AS asset_category,
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
    """ + extra
    row = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in row]


def _prepare(frame: pd.DataFrame, artifact: dict) -> pd.DataFrame:
    for col in artifact["numeric_features"]:
        frame[col] = pd.to_numeric(frame[col], errors="coerce").fillna(0.0)
    for col in artifact["categorical_features"]:
        frame[col] = frame[col].fillna("Unknown").astype(str)
    return frame[artifact["numeric_features"] + artifact["categorical_features"]]


def predict_incident_loss(incident_id: str) -> dict:
    artifact = load_attack_loss_artifact()
    rows = _build_query("WHERE ai.id = ?", (incident_id,))
    if not rows:
        raise ValueError(f"No attack incident with id '{incident_id}'")
    frame = pd.DataFrame(rows)
    pred_log = float(artifact["model"].predict(_prepare(frame, artifact))[0])
    predicted_inr = max(0.0, float(np.expm1(pred_log)))
    return {
        "incident_id": incident_id,
        "predicted_loss_inr": round(predicted_inr, 2),
        "model_metrics": artifact.get("metrics", {}),
        "training_rows": artifact.get("rows"),
        "note": "Historical attack-loss calibration signal; not a ground-truth annual loss estimate.",
    }


def asset_attack_loss_signal(asset_id: str) -> dict:
    artifact = load_attack_loss_artifact()
    rows = _build_query("WHERE ai.asset_id = ? ORDER BY ai.incident_date DESC", (asset_id,))
    if not rows:
        return {
            "asset_id": asset_id,
            "incident_count": 0,
            "predicted_loss_inr": None,
            "historical_reported_loss_inr": 0.0,
            "model_metrics": artifact.get("metrics", {}),
        }
    frame = pd.DataFrame(rows)
    pred_log = artifact["model"].predict(_prepare(frame, artifact))
    predicted = np.maximum(0.0, np.expm1(pred_log))
    return {
        "asset_id": asset_id,
        "incident_count": int(len(frame)),
        "predicted_loss_inr": round(float(np.median(predicted)), 2),
        "historical_reported_loss_inr": round(float(frame["loss_inr"].sum()), 2),
        "model_metrics": artifact.get("metrics", {}),
        "note": "Median predicted incident-loss signal across historical incidents linked to this asset.",
    }
