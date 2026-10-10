# AegisQ Model Card

## Risk Forecast Model
- Type: Random Forest Regressor
- Target: next-day asset risk score
- Rows used: 4,316
- Train/test: 3,484 / 832, chronological split
- MAE: 1.1943
- RMSE: 1.6982
- R²: 0.9779
- Artifact: `backend/ml/risk_forecast_model.joblib`

The model is primarily driven by recent risk history. This is a strong forecasting baseline, but it should not be described as causal inference.

## Attack-Loss Model
- Type: Random Forest Regressor inside a preprocessing pipeline
- Target: `log(1 + loss_inr)`
- Rows: 100 historical incidents
- Train/test: 80 / 20 chronological holdout
- MAE(log): 2.6375
- RMSE(log): 3.3320
- R²(log): -0.9332
- MAE(INR): approximately ₹25.16B
- Artifact: `backend/ml/attack_loss_model.joblib`

The supplied monetary labels are unverified and may represent different kinds of financial impact. This model is therefore a calibration/stress signal, not a production-grade loss forecast.
