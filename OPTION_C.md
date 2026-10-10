# AegisQ Option C — Financial Risk Optimization

This version implements the next AegisQ milestone:

**Asset/Vulnerability data → financial EAL → control coverage → budget optimization → ROSI**

## What changed

- Added `control_vulnerability_map` to the database schema.
- Controls now reduce only the vulnerabilities they cover.
- Scenario simulation uses multiplicative stacking per vulnerability.
- Optimizer evaluates mapped avoided financial loss rather than a flat portfolio percentage.
- Exact control selection is used for the normal 15–20 control hackathon catalogue.
- `/api/optimize` now returns current exposure, post-investment exposure, avoided loss, ROSI and an exact investment curve.
- Option C can be simulated with fixture IDs `C-002`, `C-003`, `C-004` (WAF + MFA + EDR).

## Run backend

```bash
cd backend
python3 reset_db.py
pip install -r requirements.txt
uvicorn main:app --reload
```

## Test Option C

```bash
curl -X POST http://localhost:8000/api/scenario/simulate \
  -H 'Content-Type: application/json' \
  -d '{"control_ids":["C-002","C-003","C-004"]}'
```

## Test budget optimizer

```bash
curl -X POST http://localhost:8000/api/optimize \
  -H 'Content-Type: application/json' \
  -d '{"budget_inr":5000000}'
```

The optimizer is allowed to choose a different portfolio than Option C. That is intentional: **Option C is our proposed product strategy, while the optimizer must independently prove whether it is optimal for a given organization and budget.**
