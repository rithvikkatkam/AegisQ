# AegisQ Final Architecture

AegisQ combines a deterministic financial-risk engine with two ML models.

1. Portfolio baseline: 52 assets, 112 vulnerabilities, 18 controls, 1,069 control-vulnerability mappings, and 4,732 historical risk observations.
2. Risk Forecast ML: Random Forest regression predicts next-day asset risk. The packaged trained artifact is `backend/ml/risk_forecast_model.joblib`.
3. Attack-Loss ML: Random Forest regression predicts incident-level monetary loss from CVSS, EPSS, asset criticality, target type, attack type/category, and threat-actor category. The packaged trained artifact is `backend/ml/attack_loss_model.joblib`.
4. The attack-loss model is surfaced as a historical calibration signal and is intentionally not added directly to annual FAIR loss, preventing double counting until the monetary labels are source-verified.
5. The optimizer uses the deterministic vulnerability-level financial exposure and exact control overlap math to recommend the highest-value control portfolio under budget.
6. The UI presents the ML signals alongside current financial exposure and investment recommendations.

## Model honesty

The risk-forecast model has a strong held-out baseline (MAE 1.1948, RMSE 1.6985, R2 0.9779). The attack-loss baseline was trained on the 100 supplied incidents, but its R2 is negative on the holdout; it is therefore a calibration/experimental signal rather than a claimed production-grade financial-loss predictor.
