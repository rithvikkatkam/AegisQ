# AegisQ Attack-Loss Training Guide

This folder contains the 100-row historical incident dataset supplied for AegisQ, its cleaned/normalized form, and an initial baseline regression artifact.

## Canonical cleaned schema

`attack_incidents_cleaned.csv` contains:

- `incident_id`
- `company_name`
- `attack_on`
- `target_type`
- `records_affected`
- `loss_inr`
- `loss_log1p_inr`
- `loss_type`
- `loss_confidence`
- `attack_type`
- `attack_category`
- `threat_actor`
- `actor_type`
- `incident_date`
- `date_precision`
- `asset_id`
- `vulnerability_id`
- `description`
- `source`
- `training_eligible`

## ML table

`attack_loss_training_data.csv` contains the compact modelling fields and uses `loss_log1p_inr = log(1 + loss_inr)` as the preferred target.

The model should ultimately join each incident to the AegisQ `assets` and `vulnerabilities` tables so that CVSS, EPSS, criticality, and other technical attributes are available.

## Validation requirement

The supplied monetary figures have not been independently verified row-by-row. Before treating the model as final evidence, classify each loss as actual loss, estimate, ransom, penalty, settlement, remediation, business interruption, or unknown; verify the source; and verify each asset/vulnerability link.

`company_name`, `incident_id`, `source`, and free-text `description` should not be used as direct predictive features.
