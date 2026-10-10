"""Financial-risk-aware cybersecurity budget optimizer."""

from itertools import combinations

RESOLUTION_INR = 1000


def _scale(amount_inr: float, resolution: int = RESOLUTION_INR) -> int:
    return max(0, int(amount_inr // resolution))


def scenario_eal_after_controls(assets, vulnerabilities, mappings, selected_ids):
    """Calculate portfolio EAL after selected controls are applied.

    Multiple controls on the same vulnerability stack multiplicatively:
    remaining_risk = product(1 - reduction_i).
    """
    selected = set(selected_ids)
    by_vuln = {}
    for m in mappings:
        if m["control_id"] in selected:
            by_vuln.setdefault(m["vulnerability_id"], []).append(
                float(m["reduction_pct"])
            )

    total_before = 0.0
    total_after = 0.0
    per_asset = {
        a["id"]: {"before_inr": 0.0, "after_inr": 0.0}
        for a in assets
    }

    for v in vulnerabilities:
        base = float(v["eal_inr"])
        survival = 1.0
        for pct in by_vuln.get(v["id"], []):
            survival *= 1.0 - pct / 100.0
        after = base * survival

        total_before += base
        total_after += after

        if v["asset_id"] in per_asset:
            per_asset[v["asset_id"]]["before_inr"] += base
            per_asset[v["asset_id"]]["after_inr"] += after

    return round(total_before, 2), round(total_after, 2), per_asset


def _portfolio_value(controls, assets, vulnerabilities, mappings):
    """Return exact avoided EAL for a selected control set."""
    ids = [c["id"] for c in controls]
    before, after, _ = scenario_eal_after_controls(
        assets, vulnerabilities, mappings, ids
    )
    return before - after


def knapsack_select(
    controls,
    budget_inr,
    current_exposure_inr,
    *,
    assets=None,
    vulnerabilities=None,
    mappings=None,
    resolution=RESOLUTION_INR,
):
    """Select controls that maximize avoided EAL under the budget.

    For the normal hackathon-sized catalogue (<=24 controls), exhaustive
    search evaluates the *actual combined scenario* for every affordable
    subset, so overlapping controls are handled correctly. For larger
    catalogues, a greedy marginal-value fallback is used.
    """
    if budget_inr <= 0 or not controls:
        return [], 0.0, 0.0

    use_exact = (
        assets is not None
        and vulnerabilities is not None
        and mappings is not None
        and len(controls) <= 24
    )

    if use_exact:
        best_value = -1.0
        best_cost = float("inf")
        best_selection = []
        n = len(controls)

        # Enumerate subsets by size to allow deterministic tie-breaking.
        for r in range(1, n + 1):
            for chosen in combinations(controls, r):
                cost = sum(float(c.get("cost_inr", 0.0)) for c in chosen)
                if cost > budget_inr:
                    continue

                value = _portfolio_value(
                    list(chosen), assets, vulnerabilities, mappings
                )
                if value > best_value or (
                    abs(value - best_value) < 1e-9 and cost < best_cost
                ):
                    best_value = value
                    best_cost = cost
                    best_selection = list(chosen)

        if not best_selection:
            return [], 0.0, 0.0

        return (
            best_selection,
            round(best_cost, 2),
            round(best_value, 2),
        )

    # Larger-catalogue fallback: greedy marginal benefit/cost.
    remaining = list(controls)
    selected = []
    remaining_budget = float(budget_inr)
    value = 0.0

    while remaining:
        affordable = [
            c for c in remaining
            if 0 < float(c.get("cost_inr", 0.0)) <= remaining_budget
        ]
        if not affordable:
            break

        if assets is not None and vulnerabilities is not None and mappings is not None:
            current_value = _portfolio_value(
                selected, assets, vulnerabilities, mappings
            ) if selected else 0.0

            best = None
            for c in affordable:
                candidate = selected + [c]
                candidate_value = _portfolio_value(
                    candidate, assets, vulnerabilities, mappings
                )
                marginal = candidate_value - current_value
                ratio = marginal / float(c["cost_inr"]) if c["cost_inr"] else 0.0
                key = (ratio, marginal, -float(c["cost_inr"]))
                if best is None or key > best[0]:
                    best = (key, c, candidate_value)

            _, chosen, value = best
        else:
            chosen = max(
                affordable,
                key=lambda c: float(c.get("avoided_eal_inr", 0.0))
                / float(c.get("cost_inr", 1.0)),
            )
            value += float(chosen.get("avoided_eal_inr", 0.0))

        selected.append(chosen)
        remaining.remove(chosen)
        remaining_budget -= float(chosen["cost_inr"])

    total_cost = sum(float(c["cost_inr"]) for c in selected)

    if assets is not None and vulnerabilities is not None and mappings is not None:
        value = _portfolio_value(selected, assets, vulnerabilities, mappings)

    return selected, round(total_cost, 2), round(value, 2)


def build_investment_curve(
    controls,
    budget_inr,
    current_exposure_inr,
    checkpoints=6,
    *,
    assets=None,
    vulnerabilities=None,
    mappings=None,
):
    """Build a budget-vs-avoided-loss curve using the same optimizer math."""
    curve = []
    for i in range(1, checkpoints + 1):
        spend = round(budget_inr * i / checkpoints, 2)
        selected, cost, _ = knapsack_select(
            controls,
            spend,
            current_exposure_inr,
            assets=assets,
            vulnerabilities=vulnerabilities,
            mappings=mappings,
        )

        if assets is not None and vulnerabilities is not None and mappings is not None:
            before, after, _ = scenario_eal_after_controls(
                assets, vulnerabilities, mappings, [c["id"] for c in selected]
            )
            reduction = round(before - after, 2)
        else:
            reduction = round(
                sum(float(c.get("avoided_eal_inr", 0.0)) for c in selected),
                2,
            )

        curve.append({
            "spend_inr": spend,
            "actual_cost_inr": cost,
            "risk_reduction_inr": reduction,
        })

    return curve
