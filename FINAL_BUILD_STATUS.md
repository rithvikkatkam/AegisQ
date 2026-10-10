# AegisQ Final Build Status

This package consolidates the current AegisQ implementation.

## Data
- 52 assets
- 112 vulnerabilities
- 18 controls
- 1,069 control-vulnerability mappings
- 4,732 risk history observations
- 100 historical attack incidents

## Product layers
- Deterministic FAIR-style financial exposure engine
- Vulnerability-aware control scenario engine
- Budget optimizer using exact portfolio evaluation for the current control catalogue
- Risk Forecast ML
- Attack-Loss ML calibration signal
- Portfolio ML risk outlook API
- Asset-level ML prediction API
- Attack intelligence APIs
- Compliance mapping
- Grounded LLM query endpoint (requires local Anthropic API key)
- SMB/mid-market-oriented compact INR and ROSI presentation
- Japanese-blue / glass-inspired visual system with asset number, asset name and department presentation

## Important operating rule
The bundled database already contains the real dataset. Do not run `reset_db.py` during normal startup.
