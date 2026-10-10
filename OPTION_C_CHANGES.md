# AegisQ Option C Changes

Target investment strategy for the demo:

- C-003 — MFA for VPN/remote access — ₹4,00,000
- C-002 — WAF deployment — ₹9,00,000
- C-004 — EDR fleet-wide — ₹25,00,000
- Target bundle cost: ₹38,00,000

## What changed

1. Added vulnerability-aware control mapping through `control_vulnerability_map`.
2. Scenario calculations stack overlapping controls multiplicatively so risk reduction cannot exceed 100%.
3. Optimizer evaluates the actual portfolio scenario for every affordable subset when the control catalogue is small (<=24 controls).
4. Optimizer and investment curve use financial expected annual loss (EAL) as the objective.
5. `/api/optimize` now passes asset/vulnerability/control mapping data into the exact optimizer.
6. `.gitignore` excludes macOS metadata, Python environments, Node dependencies, build output, local databases, and `.env` files.

## Important

Option C is the intended demo strategy, but the optimizer is not hard-coded to always return it. It evaluates the organization's actual sample data and budget. This keeps the recommendation engine mathematically defensible.
