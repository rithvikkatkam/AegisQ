# AegisQ

## One-click run (VS Code)

Open the project folder in VS Code, open `run.py`, and press the **Run** button (or **F5**).
It creates the Python venv, installs dependencies, trains the ML models if needed, installs the
frontend packages, starts the backend (FastAPI) and the frontend (Vite), and opens the site.
Stop everything with Ctrl+C / the Stop button. Requirements: Python 3.11+ and Node.js 20+.

Other launch configurations (Run and Debug panel): *Retrain ML models*, *Backend only (debug)*,
*Frontend only*, and a compound that debugs backend + frontend together. From a terminal:
`python run.py [--retrain] [--no-browser] [--reload] [--setup-only]`.
Optional secrets (e.g. `ANTHROPIC_API_KEY`) go in `.env` — see `.env.example`.

AegisQ converts cybersecurity vulnerabilities into financial exposure, forecasts near-term risk from historical behavior, and recommends defensive investments under a fixed budget.

## Current data baseline

- 52 assets
- 112 vulnerabilities
- 18 controls
- 1,069 control-vulnerability mappings
- 4,732 risk-history observations
- attack incident table ready for historical incident data

## ML

### Risk forecasting
`backend/ml/train.py` trains the next-day asset risk model from historical risk data.

### Attack-loss prediction
`backend/ml/train_attack_loss.py` trains an optional loss model from `attack_incidents` after enough real incident records are imported.

## Run

Backend:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m uvicorn main:app
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Dataset schema

See `DATASET_SCHEMA.md` for canonical database field order and training dataset formats.

## Important

Do not fabricate historical incident losses, attribution, or vulnerability links. Preserve source provenance for every incident used for model training.

## Training data

The `training_data/` directory contains the cleaned 100-row attack-intelligence dataset, the compact ML training table, a baseline attack-loss model artifact, baseline metrics, and the training guide. The supplied monetary values remain marked as unverified until source-by-source validation is completed.

## UI conventions

Asset identities are shown consistently as `asset number · asset name · department` in the overview, contributor views, asset register, and selected-asset ML panel.

## Current UI identity

AegisQ uses a brighter deep-red dark-mode glass aesthetic with warm ivory typography, Apple system font fallbacks, restrained crimson accents, soft frosted surfaces, and consistent asset identity formatting (`asset number · asset name · department`).
