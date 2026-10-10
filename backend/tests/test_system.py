import sqlite3
import sys
from pathlib import Path

from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import main  # noqa: E402

DB = BACKEND / "data" / "aegisq.db"


def test_dataset_counts():
    conn = sqlite3.connect(DB)
    expected = {
        "assets": 52,
        "vulnerabilities": 112,
        "controls": 18,
        "control_vulnerability_map": 1069,
        "risk_scores_history": 4732,
        "attack_incidents": 100,
    }
    for table, count in expected.items():
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == count
    conn.close()


def test_ml_artifacts():
    status = main.ml_status()
    attack = main.ml_attack_loss_status()
    assert status["trained"] is True
    assert attack["trained"] is True


def test_attack_prediction_and_outlook():
    pred = main.ml_attack_loss_incident("INC-001")
    assert pred["incident_id"] == "INC-001"
    assert pred["predicted_loss_inr"] >= 0
    outlook = main.portfolio_risk_outlook()
    assert "current_risk_score" in outlook
    assert "predicted_next_day_exposure_inr" in outlook


def test_optimizer():
    result = main.optimize(main.OptimizeBody(budget_inr=5_000_000))
    assert result["total_cost_inr"] <= 5_000_000
    assert result["post_investment_exposure_inr"] <= result["current_exposure_inr"]
    assert "forecast_exposure_inr" in result
