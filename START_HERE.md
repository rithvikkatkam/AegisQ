# AegisQ — Real Dataset Build

This build contains the original dataset:
- 52 assets
- 112 vulnerabilities
- 18 controls
- control-to-vulnerability mapping for the optimizer

## Backend
```bash
cd ~/Desktop/aegisq-project/backend
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 reset_db.py
python3 -m uvicorn main:app
```

**Do not run `python3 reset_db.py --demo-fixture` unless you intentionally want the 5-asset/7-vulnerability demo fixture.**

## Frontend (second terminal)
```bash
cd ~/Desktop/aegisq-project/frontend
npm install
npm run dev
```

Open http://localhost:5173


## ML + Attack Intelligence (new)

From `backend` after activating the venv:

```bash
python3 -m pip install -r requirements.txt
python3 ml/train.py
python3 -m uvicorn main:app
```

ML endpoints:
- `GET /api/ml/status`
- `GET /api/ml/predict/{asset_id}`

Attack history is stored separately in `attack_incidents`. Use `pipeline/attack_incidents_template.csv` and import with `pipeline/import_attack_incidents.py`. See `DATA_MODEL.md` for the schema.
