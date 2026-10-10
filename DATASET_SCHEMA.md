# AegisQ dataset specification

This document is the canonical storage/training order for the current AegisQ build.
Do not treat an attack as a vulnerability: vulnerabilities are technical weaknesses; incidents are historical attack events.

## 1. `assets` — modeled company assets

Database order:

1. `id` — TEXT, unique asset identifier
2. `name` — TEXT
3. `category` — TEXT, e.g. Database / Web Application / Network / Endpoint / Server
4. `criticality` — INTEGER 1–5
5. `business_unit` — TEXT

Use this dataset to describe the organization's attack surface and business importance.

## 2. `vulnerabilities` — technical weaknesses

Database order:

1. `id` — TEXT, internal vulnerability identifier
2. `cve_id` — TEXT, public CVE identifier when available
3. `asset_id` — TEXT, foreign key to `assets.id`
4. `cvss_score` — REAL 0–10
5. `epss_score` — REAL 0–1
6. `description` — TEXT
7. `discovered_at` — ISO-8601 date/time

These 112 rows are the current real demo portfolio. A vulnerability does not contain company loss or threat-actor information.

## 3. `controls` — defensive investments

Database order:

1. `id`
2. `name`
3. `cost_inr`
4. `risk_reduction_pct` — baseline effectiveness
5. `framework_tags`

## 4. `control_vulnerability_map` — what each control protects

Database order:

1. `control_id`
2. `vulnerability_id`
3. `reduction_pct`

This is the critical bridge for the optimizer.

## 5. `risk_scores_history` — time-series training data

Database order:

1. `id`
2. `asset_id`
3. `date`
4. `expected_annual_loss_inr`
5. `risk_score`

Current dataset: 4,732 observations. This is the training source for the next-day risk forecasting model.

## 6. `attack_incidents` — historical real-world cyber incidents

Database order:

1. `id`
2. `company_name`
3. `attack_on`
4. `target_type`
5. `loss_inr`
6. `attack_type`
7. `threat_actor`
8. `incident_date`
9. `asset_id`
10. `vulnerability_id`
11. `description`
12. `source`

Recommended values:

- `attack_on`: human-readable target, e.g. `customer portal`, `VPN gateway`, `database`
- `target_type`: normalized category, e.g. `Web Application`, `Database`, `Network`, `Endpoint`, `Cloud`, `Identity`
- `loss_inr`: estimated/verified loss in INR; keep the source and methodology
- `attack_type`: Ransomware, DDoS, Credential Theft, RCE, Data Exfiltration, Phishing, etc.
- `threat_actor`: named group/campaign when publicly attributed; otherwise `Unknown`
- `asset_id`: optional mapping into the modeled AegisQ asset taxonomy
- `vulnerability_id`: optional CVE/vulnerability mapping when supported by the source

### Why `company_name` is not a primary ML feature

The model should learn generalized relationships rather than memorize a company's identity. `company_name` is retained for analysis and traceability. `target_type`, `attack_type`, CVSS, EPSS, criticality and other technical features are more suitable predictors.

## 7. Training-ready CSV order

### Vulnerability dataset

```csv
id,cve_id,asset_id,cvss_score,epss_score,description,discovered_at
```

### Asset dataset

```csv
id,name,category,criticality,business_unit
```

### Risk-history dataset

```csv
asset_id,date,expected_annual_loss_inr,risk_score
```

### Attack-incident dataset

```csv
id,company_name,attack_on,target_type,loss_inr,attack_type,threat_actor,incident_date,asset_id,vulnerability_id,description,source
```

## 8. Recommended ML targets

### Model A — Risk forecast
Target: `next_period_risk_score`

Source: `risk_scores_history` plus current asset/vulnerability features.

### Model B — Attack-loss prediction
Target: `loss_inr` (usually trained as `log1p(loss_inr)`).

Source: `attack_incidents` joined with `assets` and `vulnerabilities`.

Never fabricate losses, attribution, or vulnerability links simply to increase sample count. Preserve source provenance.
