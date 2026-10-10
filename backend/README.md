# AegisQ Backend

FastAPI backend for the AegisQ cyber-risk quantification platform (SIH26105).
Implements the shared contract exactly: same table names, field names, and
endpoint paths the frontend and data-pipeline teams are building against.

## What this does

- Serves assets / vulnerabilities / controls straight from SQLite.
- Runs a simplified **FAIR** risk calculation live on every request to
  `/api/risk/*` (expected_annual_loss = loss_event_frequency × loss_magnitude,
  derived from EPSS and CVSS scores — see comments in `fair_model.py` for the
  exact simplifications made and why).
- Runs an exact **0/1 knapsack** (dynamic programming) to pick the
  cost-optimal set of controls under a budget, plus a 6-point investment
  curve, in `optimizer.py`.
- Proxies natural-language questions to the Anthropic API, grounded in the
  current risk snapshot, in `llm_query.py`.
- Derives the ISO27001 / NIST-CSF / CIS / RBI compliance mapping from
  `controls.framework_tags` at request time (`compliance.py`) — there's no
  separate compliance table in the schema.
- Every response (success or failure) matches the shared contract's shapes.
  Every failure path returns `{ "error": true, "message": "...", "code": "..." }`.

## Setup

```bash
cd aegisq-backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # then fill in ANTHROPIC_API_KEY if you want /api/query to work
```

## Run

```bash
uvicorn main:app --reload
```

Backend comes up on **http://localhost:8000**. On first startup it creates
`./data/aegisq.db` if it doesn't exist and, if the `assets` table is
completely empty, seeds a small fallback fixture (5 assets, 7 vulnerabilities,
8 controls) so the API is immediately testable before the data pipeline's
real output lands. It never wipes data that's already there.

To force a full rebuild (schema + fixture) at any point, e.g. during
integration testing with the other two teams:

```bash
python3 reset_db.py                 # rebuild schema + fixture data
python3 reset_db.py --schema-only   # rebuild schema only, no fixture rows
```

## Environment variables

| Variable                | Default                        | Purpose                                                   |
|--------------------------|---------------------------------|------------------------------------------------------------|
| `ANTHROPIC_API_KEY`      | *(unset)*                      | Required for `/api/query`. Without it, that endpoint returns a clean `LLM_NOT_CONFIGURED` error instead of crashing. |
| `ANTHROPIC_MODEL`        | `claude-sonnet-4-5-20250929`   | Model used for `/api/query`. Check current model names before the demo. |
| `AEGISQ_DB_PATH`         | `./data/aegisq.db`             | SQLite file location. Matches the shared contract — only change alongside the contract doc. |
| `AEGISQ_RUPEE_MULTIPLIER`| `500000`                       | ₹ per CVSS point × criticality point in the FAIR loss-magnitude calc. |

## Endpoint reference + curl examples

### Health check
```bash
curl http://localhost:8000/api/health
```

### Assets
```bash
curl http://localhost:8000/api/assets
```

### Vulnerabilities (optionally filtered by asset)
```bash
curl http://localhost:8000/api/vulnerabilities
curl "http://localhost:8000/api/vulnerabilities?asset_id=A-001"
```

### Controls
```bash
curl http://localhost:8000/api/controls
```

### Enterprise risk summary
```bash
curl http://localhost:8000/api/risk/summary
```

### Per-asset risk detail
```bash
curl http://localhost:8000/api/risk/assets/A-001
```

### Scenario simulation
```bash
curl -X POST http://localhost:8000/api/scenario/simulate \
  -H "Content-Type: application/json" \
  -d '{"control_ids": ["C-001", "C-003"]}'
```

### Budget-constrained optimizer
```bash
curl -X POST http://localhost:8000/api/optimize \
  -H "Content-Type: application/json" \
  -d '{"budget_inr": 3000000}'
```

### Natural-language query (needs ANTHROPIC_API_KEY set)
```bash
curl -X POST http://localhost:8000/api/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Which asset contributes the most financial risk and why?"}'
```

### Compliance mapping
```bash
curl http://localhost:8000/api/compliance/mapping
```

## Documented simplifications (so judges/teammates aren't surprised)

1. **FAIR loss_event_frequency** = a vulnerability's EPSS score directly.
   EPSS is a 30-day exploitation probability, used here as a stand-in for
   annualized frequency — a known simplification, not a calibrated rate.
2. **FAIR loss_magnitude** = `cvss_score × asset.criticality × ₹5,00,000`
   (configurable). Order-of-magnitude estimate of incident cost scaled by
   severity and business criticality.
3. **Enterprise risk_score** is the max of all per-asset risk_scores (a
   portfolio is only as safe as its riskiest asset), not a weighted average.
4. **Scenario simulation** applies each control's `risk_reduction_pct`
   portfolio-wide (the schema has no control→asset/vuln mapping), combining
   multiple controls multiplicatively (`1 - Π(1 - r_i)`) so stacked controls
   can't exceed 100% reduction.
5. **Optimizer** values each control independently as
   `risk_reduction_pct × current_total_exposure`, with no interaction/overlap
   modeling between controls — same reason as #4. Costs are discretized into
   ₹1,000 buckets so the knapsack DP is exact and fast.

## Files

```
main.py          FastAPI app, all contract endpoints, request/response wiring
database.py      SQLite connection + schema (single source of truth for schema)
fair_model.py    FAIR risk calculation
optimizer.py     0/1 knapsack budget optimizer + investment curve
llm_query.py     Anthropic API call for /api/query
compliance.py    Framework/clause mapping derived from controls.framework_tags
reset_db.py      Rebuild schema + seed fixture data (for dev/integration testing)
requirements.txt
.env.example
```
