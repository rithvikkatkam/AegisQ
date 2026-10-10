# AegisQ data model

## 1. Vulnerabilities are weaknesses, not attacks

The `vulnerabilities` table contains the technical weakness:

| Column | Meaning | Example |
|---|---|---|
| `id` | Internal vulnerability ID | `VULN-0001` |
| `cve_id` | Public CVE identifier | `CVE-2019-2725` |
| `asset_id` | Asset affected inside the modeled company | `AST-001` |
| `cvss_score` | Severity, 0–10 | `9.8` |
| `epss_score` | Exploitation probability signal, 0–1 | `0.50` |
| `description` | Vulnerability description | `Oracle WebLogic ... RCE` |
| `discovered_at` | Date discovered/observed | ISO-8601 timestamp |

Current real dataset: **112 vulnerabilities across 52 assets**.

## 2. Attacks/incidents are separate

Your proposed fields belong in `attack_incidents`, because an attack is an event that may exploit a vulnerability. This separation is important: the same CVE can be exploited against many companies, and one real-world incident can involve multiple vulnerabilities.

`attack_incidents` fields:

| Column | What you should enter |
|---|---|
| `id` | Unique incident ID, e.g. `INC-0001` |
| `company_name` | Victim company, e.g. `Example Bank` |
| `attack_on` | What was targeted, e.g. `customer portal`, `email server`, `database` |
| `loss_inr` | Estimated monetary loss in INR |
| `attack_type` | Ransomware, phishing, credential theft, SQLi, DDoS, RCE, etc. |
| `threat_actor` | Who did it, e.g. group/campaign/unknown |
| `incident_date` | When it happened |
| `asset_id` | Optional link to one of our modeled assets |
| `vulnerability_id` | Optional link to one of our modeled vulnerabilities |
| `description` | Narrative / context |
| `source` | Dataset/report/source reference |

## 3. Example row

```csv
INC-0001,Example Bank,Customer Portal,12500000,Ransomware,Unknown Group,2026-04-12,AST-014,VULN-0031,"Customer-facing portal compromised and systems encrypted","public-report"
```

## 4. How the tables relate

```text
COMPANY / INCIDENT HISTORY
        |
        +--> attack_incidents
                 |
                 +--> vulnerability_id --> vulnerabilities --> assets
                 |
                 +--> loss_inr
                 +--> attack_type
                 +--> threat_actor

CURRENT RISK
        |
        +--> vulnerabilities + CVSS + EPSS + asset criticality
        |
        +--> FAIR-style financial exposure
        |
        +--> ML forecast
        |
        +--> optimizer
```

## 5. Why this is better for ML

Once you add enough historical incident rows, we can train a supervised model using real attack outcomes rather than pretending that an unobserved vulnerability is a negative label. The eventual target can be attack likelihood, expected loss, or both.
