# AegisQ Attack-Loss Model Card

The model is trained on the 100 supplied historical incidents after joining the supplied asset/vulnerability IDs to the AegisQ portfolio. Monetary target is `log1p(loss_inr)`.

Rows: 100
Train: 80
Test: 20
MAE (INR, back-transformed): 25,293,677,092.10
RMSE (INR, back-transformed): 64,151,133,964.18
R2 (log target): -0.8560

The model is an attack-intelligence calibration signal. The supplied incident monetary values and vulnerability links are not independently verified row-by-row; therefore the model should not be described as ground truth or as a causal loss predictor.
