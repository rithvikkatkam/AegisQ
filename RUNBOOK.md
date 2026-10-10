# AegisQ Runbook

## First-time backend setup

```bash
cd ~/Desktop/aegisq-project/backend
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 reset_db.py
python3 ml/train.py
python3 -m uvicorn main:app
```

`reset_db.py` is safe in the real-data build: it preserves the packaged 52-asset / 112-vulnerability database. Do not use the `--demo-fixture` flag for the final demo.

## Frontend

In a second terminal:

```bash
cd ~/Desktop/aegisq-project/frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

API docs are at `http://127.0.0.1:8000/docs`.

## ML endpoints

- `GET /api/ml/status`
- `GET /api/ml/predict/{asset_id}`

## Attack history

Create a CSV from `pipeline/attack_incidents_template.csv`, then import it:

```bash
cd ~/Desktop/aegisq-project/pipeline
python3 import_attack_incidents.py attack_incidents.csv
```

See `DATA_MODEL.md` for the meaning of each column.

## Optional attack-loss model

After at least 20 real incident records have been imported:

```bash
cd ~/Desktop/aegisq-project/backend
source venv/bin/activate
python3 ml/train_attack_loss.py
```

Never treat an absence of an incident record as a negative attack label. Negative labels need verified evidence.
