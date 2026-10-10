"""
fair_model.py
-------------
Implements a simplified FAIR (Factor Analysis of Information Risk) style
calculation:

    expected_annual_loss = loss_event_frequency * loss_magnitude

Simplifications made explicit here (call these out to judges if asked):

- loss_event_frequency per vulnerability is taken directly as its EPSS score.
  EPSS estimates probability of exploitation within a 30-day window; we treat
  it as a stand-in for annualized exploitation frequency. This is a known
  simplification (not a calibrated annualized rate) but keeps the model
  transparent and defensible in a demo setting.

- loss_magnitude per vulnerability is:
      cvss_score * asset.criticality * RUPEE_MULTIPLIER
  i.e. severity and business criticality scale a fixed rupee constant.
  RUPEE_MULTIPLIER is configurable (env var) so judges/teammates can tune it
  without touching code.

- Per-asset expected annual loss = sum of expected annual loss over all of
  that asset's vulnerabilities (independence assumption between vulns).

- Enterprise exposure = sum of per-asset expected annual loss.

- risk_score (0-100) is NOT a FAIR-native concept; it's a display-only
  normalization of an asset's (or the enterprise's) expected annual loss
  relative to the current portfolio maximum, so the UI has something bounded
  to render as a gauge/chart.
"""
import os

# ₹5,00,000 per CVSS severity point per criticality point, per year.
# Defensible as a rough order-of-magnitude for mid-size enterprise incident
# cost (containment + downtime + regulatory exposure) scaled by how severe
# and how critical the affected asset is. Override via env var for tuning.
RUPEE_MULTIPLIER_PER_SEVERITY_PER_CRITICALITY = float(
    os.environ.get("AEGISQ_RUPEE_MULTIPLIER", 500_000)
)


def vuln_expected_annual_loss(cvss_score: float, epss_score: float, criticality: int) -> float:
    """Expected annual loss (INR) contributed by a single vulnerability."""
    loss_event_frequency = epss_score or 0.0
    loss_magnitude = (cvss_score or 0.0) * (criticality or 0) * RUPEE_MULTIPLIER_PER_SEVERITY_PER_CRITICALITY
    return loss_event_frequency * loss_magnitude


def asset_expected_annual_loss(vulnerabilities: list, criticality: int) -> float:
    """Sum expected annual loss across all vulnerabilities on one asset."""
    return sum(
        vuln_expected_annual_loss(v["cvss_score"], v["epss_score"], criticality)
        for v in vulnerabilities
    )


def normalize_risk_score(value: float, max_value: float) -> float:
    """
    Map an expected-annual-loss value into a 0-100 display score, relative to
    the largest value currently in the portfolio. Returns 0 if there's
    nothing to compare against (empty portfolio / all zeros).
    """
    if not max_value or max_value <= 0:
        return 0.0
    return round(min(value / max_value, 1.0) * 100, 2)


def compute_portfolio_risk(assets: list, vulns_by_asset: dict) -> dict:
    """
    Given a list of asset rows and a dict {asset_id: [vuln rows]}, compute:
      - per-asset expected_annual_loss_inr and risk_score
      - enterprise_risk_score and total_financial_exposure_inr

    Returns:
    {
      "per_asset": { asset_id: {"expected_annual_loss_inr": .., "risk_score": ..} },
      "total_financial_exposure_inr": float,
      "enterprise_risk_score": float
    }
    """
    per_asset_loss = {}
    for asset in assets:
        vulns = vulns_by_asset.get(asset["id"], [])
        per_asset_loss[asset["id"]] = asset_expected_annual_loss(vulns, asset["criticality"])

    total_exposure = sum(per_asset_loss.values())
    max_loss = max(per_asset_loss.values()) if per_asset_loss else 0.0

    per_asset = {
        asset_id: {
            "expected_annual_loss_inr": round(loss, 2),
            "risk_score": normalize_risk_score(loss, max_loss),
        }
        for asset_id, loss in per_asset_loss.items()
    }

    # Enterprise-wide score: normalize total exposure against itself being
    # the max observed so far isn't meaningful (it's the sum, always >= any
    # single asset's max), so instead we score the enterprise by how "hot"
    # its worst asset is -- a portfolio is only as safe as its riskiest asset
    # for the purposes of a single headline gauge number.
    enterprise_risk_score = max((v["risk_score"] for v in per_asset.values()), default=0.0)

    return {
        "per_asset": per_asset,
        "total_financial_exposure_inr": round(total_exposure, 2),
        "enterprise_risk_score": enterprise_risk_score,
    }
