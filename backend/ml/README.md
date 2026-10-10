# AegisQ ML layer

## Model 1: risk forecasting (available now)

`train.py` trains a Random Forest regressor on the 4,732 historical risk observations in the real dataset. It predicts the next-day asset risk score using lagged risk, trend, volatility, financial exposure, CVSS/EPSS statistics, vulnerability count, and asset criticality.

Run:

```bash
cd backend
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 ml/train.py
```

The model is saved locally as `risk_forecast_model.joblib` and is intentionally gitignored.

## Model 2: historical attack-loss regression (available after you add attack data)

`train_attack_loss.py` learns from `attack_incidents` records. It predicts monetary loss from CVSS, EPSS, asset criticality, attack type, and threat actor. It requires at least 20 real incident rows and does not treat missing attacks as negative labels.

Run after importing attack records:

```bash
python3 ml/train_attack_loss.py
```

## Why `who_did_it` is not a model target

The `threat_actor` field is historical attribution/intelligence. It is a categorical feature that can help estimate loss patterns, but AegisQ should not claim it can infer a real-world attacker from CVE data alone.
