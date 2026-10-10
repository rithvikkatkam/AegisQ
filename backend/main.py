"""
main.py
-------
AegisQ backend. Implements every endpoint in the shared contract exactly as
specified (see contract doc). Run with:

    uvicorn main:app --reload

On startup, ensures the schema exists at ./data/aegisq.db (does NOT wipe
existing data -- use reset_db.py for that) and seeds a tiny fallback fixture
ONLY if the assets table is completely empty, so solo development works
before the data pipeline team's output lands.
"""
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Load environment variables (ANTHROPIC_API_KEY, ANTHROPIC_MODEL, ...) from a
# .env file BEFORE importing the local modules below -- some of them read the
# environment at import time. backend/.env wins over the project-root .env;
# real environment variables win over both.
try:
    from dotenv import load_dotenv

    _BACKEND_DIR = Path(__file__).resolve().parent
    load_dotenv(_BACKEND_DIR / ".env")
    load_dotenv(_BACKEND_DIR.parent / ".env")
except ImportError:  # python-dotenv is optional at runtime
    pass

import compliance
import fair_model
import llm_query
import optimizer
from ml.predict import predict_asset, load_artifact
from ml.attack_loss_predict import load_attack_loss_artifact, predict_incident_loss, asset_attack_loss_signal
import reset_db
from database import db_session, ensure_schema, row_counts, rows_to_dicts

app = FastAPI(title="AegisQ Backend", version="1.0.0")

# CORS: contract asks for localhost:5173 / localhost:3000 explicitly, plus a
# "*" fallback for demo laptops. FastAPI's CORSMiddleware doesn't allow
# combining an explicit origin list with allow_credentials=True and "*"
# meaningfully, so since this is hackathon-speed and no cookies/auth are in
# play, we just allow all origins outright -- simplest thing that satisfies
# "CORS enabled for all origins" from the task brief.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Shared error shape helper. EVERY failure path in this app returns this
# exact shape, per the contract: { error: true, message: str, code: str }
# ---------------------------------------------------------------------------
def error_response(message: str, code: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": True, "message": message, "code": code},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Catch-all so an unexpected bug never returns FastAPI's default HTML/
    # plain error page mid-demo -- always the contract's JSON error shape.
    return error_response(f"Unexpected server error: {exc}", "INTERNAL_ERROR", 500)


@app.on_event("startup")
def on_startup():
    ensure_schema()
    with db_session() as conn:
        counts = row_counts(conn)
    if counts["assets"] == 0:
        # Nothing in the DB yet (fresh clone, pipeline hasn't run) -- seed the
        # small fallback fixture so the API is immediately useful for
        # frontend development. Real pipeline output will simply INSERT more
        # rows next time it runs; this only fires on a genuinely empty DB.
        reset_db.rebuild(schema_only=False)


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------
class ScenarioSimulateBody(BaseModel):
    control_ids: list[str]


class OptimizeBody(BaseModel):
    budget_inr: float


class QueryBody(BaseModel):
    question: str


# ---------------------------------------------------------------------------
# Data access helpers (thin wrappers, kept here since main.py owns request
# handling and these are only used by it)
# ---------------------------------------------------------------------------
def fetch_assets(conn):
    return rows_to_dicts(conn.execute("SELECT * FROM assets").fetchall())


def fetch_vulns(conn, asset_id: str | None = None):
    if asset_id:
        rows = conn.execute(
            "SELECT * FROM vulnerabilities WHERE asset_id = ?", (asset_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM vulnerabilities").fetchall()
    return rows_to_dicts(rows)


def fetch_controls(conn):
    return rows_to_dicts(conn.execute("SELECT * FROM controls").fetchall())


def vulns_grouped_by_asset(conn):
    grouped: dict = {}
    for v in fetch_vulns(conn):
        grouped.setdefault(v["asset_id"], []).append(v)
    return grouped


def fetch_control_mappings(conn):
    rows = conn.execute(
        "SELECT control_id, vulnerability_id, reduction_pct FROM control_vulnerability_map"
    ).fetchall()
    return rows_to_dicts(rows)


def enrich_controls_for_optimizer(conn, controls, vulnerabilities, assets):
    asset_by_id = {a["id"]: a for a in assets}
    mappings = fetch_control_mappings(conn)
    vuln_by_id = {}
    for v in vulnerabilities:
        asset = asset_by_id.get(v["asset_id"])
        if not asset:
            continue
        eal = fair_model.vuln_expected_annual_loss(
            v["cvss_score"], v["epss_score"], asset["criticality"]
        )
        vuln_by_id[v["id"]] = {**v, "eal_inr": eal}

    by_control = {}
    for m in mappings:
        v = vuln_by_id.get(m["vulnerability_id"])
        if v:
            by_control.setdefault(m["control_id"], 0.0)
            by_control[m["control_id"]] += v["eal_inr"] * (m["reduction_pct"] / 100.0)

    enriched = []
    for c in controls:
        enriched.append({**c, "avoided_eal_inr": round(by_control.get(c["id"], 0.0), 2)})
    return enriched, mappings, vuln_by_id


def compute_live_risk(conn):
    """Runs the FAIR calc fresh against current DB contents."""
    assets = fetch_assets(conn)
    grouped = vulns_grouped_by_asset(conn)
    return fair_model.compute_portfolio_risk(assets, grouped), assets, grouped


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    try:
        with db_session() as conn:
            counts = row_counts(conn)
        return {"status": "ok", "db_connected": True, "row_counts": counts}
    except Exception as exc:  # noqa: BLE001
        return error_response(f"DB connection failed: {exc}", "DB_UNAVAILABLE", 500)


# ---------------------------------------------------------------------------
# Raw table reads
# ---------------------------------------------------------------------------
@app.get("/api/assets")
def get_assets():
    with db_session() as conn:
        return fetch_assets(conn)


@app.get("/api/vulnerabilities")
def get_vulnerabilities(asset_id: str | None = None):
    with db_session() as conn:
        if asset_id:
            exists = conn.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone()
            if not exists:
                return error_response(f"No asset with id '{asset_id}'", "ASSET_NOT_FOUND", 404)
        return fetch_vulns(conn, asset_id)


@app.get("/api/controls")
def get_controls():
    with db_session() as conn:
        return fetch_controls(conn)


# ---------------------------------------------------------------------------
# Risk endpoints
# ---------------------------------------------------------------------------
@app.get("/api/risk/summary")
def risk_summary():
    with db_session() as conn:
        risk, assets, _ = compute_live_risk(conn)

        asset_names = {a["id"]: a["name"] for a in assets}
        top_contributors = sorted(
            (
                {
                    "asset_id": asset_id,
                    "asset_name": asset_names.get(asset_id, asset_id),
                    "expected_annual_loss_inr": data["expected_annual_loss_inr"],
                }
                for asset_id, data in risk["per_asset"].items()
            ),
            key=lambda x: x["expected_annual_loss_inr"],
            reverse=True,
        )[:5]

        # risk_trend is sourced from the stored risk_scores_history table
        # (an audit trail populated by the data pipeline / reset_db fixture),
        # aggregated as enterprise-wide expected annual loss per date --
        # distinct from the live per-request FAIR calc used for the
        # headline numbers above.
        trend_rows = conn.execute(
            """SELECT date, SUM(expected_annual_loss_inr) AS total
               FROM risk_scores_history GROUP BY date ORDER BY date"""
        ).fetchall()
        risk_trend = [
            {"date": row["date"], "expected_annual_loss_inr": round(row["total"], 2)}
            for row in trend_rows
        ]

        return {
            "enterprise_risk_score": risk["enterprise_risk_score"],
            "total_financial_exposure_inr": risk["total_financial_exposure_inr"],
            "risk_trend": risk_trend,
            "top_risk_contributors": top_contributors,
        }


@app.get("/api/risk/assets/{asset_id}")
def risk_for_asset(asset_id: str):
    with db_session() as conn:
        asset = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if not asset:
            return error_response(f"No asset with id '{asset_id}'", "ASSET_NOT_FOUND", 404)

        risk, _, grouped = compute_live_risk(conn)
        asset_risk = risk["per_asset"].get(asset_id, {"expected_annual_loss_inr": 0.0, "risk_score": 0.0})

        return {
            "asset_id": asset_id,
            "expected_annual_loss_inr": asset_risk["expected_annual_loss_inr"],
            "risk_score": asset_risk["risk_score"],
            "vulnerabilities": grouped.get(asset_id, []),
        }


# ---------------------------------------------------------------------------
# Scenario simulation
# ---------------------------------------------------------------------------
@app.post("/api/scenario/simulate")
def scenario_simulate(body: ScenarioSimulateBody):
    with db_session() as conn:
        risk, assets, _ = compute_live_risk(conn)
        controls = fetch_controls(conn)
        vulnerabilities = fetch_vulns(conn)
        enriched, mappings, vuln_by_id = enrich_controls_for_optimizer(
            conn, controls, vulnerabilities, assets
        )
        current_exposure = risk["total_financial_exposure_inr"]
        current_score = risk["enterprise_risk_score"]

        control_ids = list(dict.fromkeys(body.control_ids))
        known = {c["id"] for c in controls}
        missing = [cid for cid in control_ids if cid not in known]
        if missing:
            return error_response(f"Unknown control_ids: {missing}", "CONTROL_NOT_FOUND", 404)

        # `scenario_eal_after_controls` expects eal_inr on vulnerability rows.
        # Rebuild a compact mapping input with those values attached.
        calc_vulns = [v for v in vuln_by_id.values()]
        before, after, per_asset = optimizer.scenario_eal_after_controls(
            assets, calc_vulns, mappings, control_ids
        )
        reduction = round(before - after, 2)
        new_score = round(max(0.0, current_score * (after / before)) if before else 0.0, 2)
        selected_cost = round(sum(c["cost_inr"] for c in controls if c["id"] in control_ids), 2)

        return {
            "selected_controls": [
                {"control_id": c["id"], "name": c["name"], "cost_inr": c["cost_inr"]}
                for c in controls if c["id"] in control_ids
            ],
            "new_enterprise_risk_score": new_score,
            "new_total_financial_exposure_inr": after,
            "delta_inr": reduction,
            "total_cost_inr": selected_cost,
            "rosi_pct": round(((reduction - selected_cost) / selected_cost) * 100, 2) if selected_cost else 0.0,
            "per_asset": per_asset,
        }


# ---------------------------------------------------------------------------
# Budget-constrained optimizer
# ---------------------------------------------------------------------------
@app.post("/api/optimize")
def optimize(body: OptimizeBody):
    if body.budget_inr is None or body.budget_inr <= 0:
        return error_response("budget_inr must be a positive number", "INVALID_BUDGET", 400)

    with db_session() as conn:
        controls = fetch_controls(conn)
        risk, assets, _ = compute_live_risk(conn)
        vulnerabilities = fetch_vulns(conn)
        current_exposure = risk["total_financial_exposure_inr"]
        try:
            outlook = portfolio_risk_outlook()
        except Exception:
            outlook = {"predicted_next_day_exposure_inr": current_exposure, "predicted_next_day_risk_score": risk["enterprise_risk_score"]}
        forecast_exposure = float(outlook.get("predicted_next_day_exposure_inr", current_exposure))

        if not controls:
            return error_response("No controls available to optimize over", "NO_CONTROLS", 404)

        enriched, mappings, vuln_by_id = enrich_controls_for_optimizer(
            conn, controls, vulnerabilities, assets
        )
        selected, total_cost, _ = optimizer.knapsack_select(
            enriched,
            body.budget_inr,
            current_exposure,
            assets=assets,
            vulnerabilities=list(vuln_by_id.values()),
            mappings=mappings,
        )
        selected_ids = [c["id"] for c in selected]
        before, after, _ = optimizer.scenario_eal_after_controls(
            assets, list(vuln_by_id.values()), mappings, selected_ids
        )
        total_reduction = round(before - after, 2)
        rosi_pct = round(((total_reduction - total_cost) / total_cost) * 100, 2) if total_cost else 0.0
        investment_curve = optimizer.build_investment_curve(
            enriched,
            body.budget_inr,
            current_exposure,
            assets=assets,
            vulnerabilities=list(vuln_by_id.values()),
            mappings=mappings,
        )

        forecast_after = forecast_exposure * (after / before) if before > 0 else forecast_exposure

        return {
            "budget_inr": body.budget_inr,
            "current_exposure_inr": current_exposure,
            "forecast_exposure_inr": round(forecast_exposure, 2),
            "post_investment_exposure_inr": after,
            "post_investment_forecast_exposure_inr": round(forecast_after, 2),
            "selected_controls": [
                {
                    "control_id": c["id"],
                    "name": c["name"],
                    "cost_inr": c["cost_inr"],
                    "mapped_avoided_eal_inr": c["avoided_eal_inr"],
                } for c in selected
            ],
            "total_cost_inr": total_cost,
            "total_risk_reduction_inr": total_reduction,
            "rosi_pct": rosi_pct,
            "investment_curve": investment_curve,
        }



# ---------------------------------------------------------------------------
# ML forecasting
# ---------------------------------------------------------------------------
@app.get("/api/ml/status")
def ml_status():
    try:
        artifact = load_artifact()
        return {
            "trained": True,
            "metrics": artifact["metrics"],
            "trained_until": artifact["trained_until"],
            "test_until": artifact["test_until"],
        }
    except FileNotFoundError:
        return {"trained": False, "message": "Run python3 ml/train.py"}


@app.get("/api/ml/attack-loss/status")
def ml_attack_loss_status():
    try:
        artifact = load_attack_loss_artifact()
        return {
            "trained": True,
            "rows": artifact.get("rows"),
            "metrics": artifact.get("metrics", {}),
            "note": "Historical attack-loss calibration model; validate monetary labels before presenting as ground truth.",
        }
    except FileNotFoundError:
        return {"trained": False, "message": "Run python3 ml/train_attack_loss.py after importing attack incidents."}


@app.get("/api/ml/attack-loss/incident/{incident_id}")
def ml_attack_loss_incident(incident_id: str):
    try:
        return predict_incident_loss(incident_id)
    except FileNotFoundError as exc:
        return error_response(str(exc), "ATTACK_LOSS_MODEL_NOT_FOUND", 500)
    except ValueError as exc:
        return error_response(str(exc), "INCIDENT_NOT_FOUND", 404)
    except Exception as exc:
        return error_response(f"Attack-loss prediction failed: {exc}", "ATTACK_LOSS_PREDICTION_ERROR", 500)


@app.get("/api/ml/attack-loss/asset/{asset_id}")
def ml_attack_loss_asset(asset_id: str):
    try:
        with db_session() as conn:
            exists = conn.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if not exists:
            return error_response(f"No asset with id '{asset_id}'", "ASSET_NOT_FOUND", 404)
        return asset_attack_loss_signal(asset_id)
    except FileNotFoundError as exc:
        return error_response(str(exc), "ATTACK_LOSS_MODEL_NOT_FOUND", 500)
    except Exception as exc:
        return error_response(f"Attack-loss asset signal failed: {exc}", "ATTACK_LOSS_SIGNAL_ERROR", 500)


@app.get("/api/ml/predict/{asset_id}")
def ml_predict(asset_id: str):
    try:
        return predict_asset(asset_id)
    except FileNotFoundError as exc:
        return error_response(str(exc), "MODEL_NOT_FOUND", 500)
    except ValueError as exc:
        return error_response(str(exc), "INVALID_ASSET", 404)
    except Exception as exc:
        return error_response(f"ML prediction failed: {exc}", "ML_PREDICTION_ERROR", 500)



@app.get("/api/ml/risk-outlook")
def portfolio_risk_outlook():
    """Forecast the portfolio headline from the trained risk model.

    The deterministic FAIR exposure remains authoritative. The ML forecast is
    used only to estimate directional future exposure for planning.
    """
    with db_session() as conn:
        risk, assets, _ = compute_live_risk(conn)
        predictions = []
        for asset in assets:
            try:
                p = predict_asset(asset["id"])
                predictions.append(p)
            except ValueError:
                continue
        current_score = float(risk["enterprise_risk_score"])
        if predictions:
            # Exposure-weighted next-day risk. Use the live exposure weights so
            # a tiny asset cannot move the enterprise forecast disproportionately.
            exposure_by_asset = risk["per_asset"]
            weight_sum = sum(float(v.get("expected_annual_loss_inr", 0)) for v in exposure_by_asset.values()) or 1.0
            forecast_score = sum(
                float(p["predicted_risk_score"]) * float(exposure_by_asset.get(p["asset_id"], {}).get("expected_annual_loss_inr", 0))
                for p in predictions
            ) / weight_sum
        else:
            forecast_score = current_score
        exposure = float(risk["total_financial_exposure_inr"])
        predicted_exposure = exposure * (forecast_score / current_score) if current_score > 0 else exposure
        return {
            "current_risk_score": round(current_score, 2),
            "predicted_next_day_risk_score": round(float(forecast_score), 2),
            "risk_change": round(float(forecast_score - current_score), 2),
            "current_exposure_inr": round(exposure, 2),
            "predicted_next_day_exposure_inr": round(predicted_exposure, 2),
            "model": "Risk Forecast Random Forest",
            "model_metrics": load_artifact()["metrics"],
            "asset_predictions": predictions,
        }

# ---------------------------------------------------------------------------
# Attack intelligence / incident records
# ---------------------------------------------------------------------------
@app.get("/api/attacks")
def get_attacks(company_name: str | None = None, attack_type: str | None = None):
    with db_session() as conn:
        sql = "SELECT * FROM attack_incidents WHERE 1=1"
        params = []
        if company_name:
            sql += " AND company_name = ?"
            params.append(company_name)
        if attack_type:
            sql += " AND attack_type = ?"
            params.append(attack_type)
        sql += " ORDER BY incident_date DESC"
        return rows_to_dicts(conn.execute(sql, params).fetchall())


@app.get("/api/attacks/summary")
def attacks_summary():
    with db_session() as conn:
        totals = conn.execute(
            "SELECT COUNT(*) AS incident_count, COALESCE(SUM(loss_inr),0) AS total_loss_inr "
            "FROM attack_incidents"
        ).fetchone()
        by_type = rows_to_dicts(conn.execute(
            "SELECT attack_type, COUNT(*) AS incidents, COALESCE(SUM(loss_inr),0) AS loss_inr "
            "FROM attack_incidents GROUP BY attack_type ORDER BY loss_inr DESC"
        ).fetchall())
        by_actor = rows_to_dicts(conn.execute(
            "SELECT COALESCE(threat_actor,'Unknown') AS threat_actor, COUNT(*) AS incidents, "
            "COALESCE(SUM(loss_inr),0) AS loss_inr FROM attack_incidents "
            "GROUP BY threat_actor ORDER BY loss_inr DESC"
        ).fetchall())
        return {
            "incident_count": totals["incident_count"],
            "total_loss_inr": round(totals["total_loss_inr"], 2),
            "by_attack_type": by_type,
            "by_threat_actor": by_actor,
        }


# ---------------------------------------------------------------------------
# Natural-language query (LLM-backed)
# ---------------------------------------------------------------------------
@app.post("/api/query")
def query(body: QueryBody):
    if not body.question or not body.question.strip():
        return error_response("question must be a non-empty string", "INVALID_QUESTION", 400)

    summary = risk_summary()
    if isinstance(summary, JSONResponse):
        # risk_summary() itself errored (shouldn't normally happen, but
        # forward the error shape rather than passing a broken context to
        # the LLM).
        return summary

    result = llm_query.answer_query(body.question, summary)
    if result.get("error"):
        return error_response(result["message"], result["code"], 502)
    return result


# ---------------------------------------------------------------------------
# Compliance mapping
# ---------------------------------------------------------------------------
@app.get("/api/compliance/mapping")
def compliance_mapping():
    with db_session() as conn:
        controls = fetch_controls(conn)
    return compliance.build_compliance_mapping(controls)
