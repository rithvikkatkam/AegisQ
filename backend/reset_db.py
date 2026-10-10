"""
reset_db.py
-----------
Safe database utility. By default it preserves the packaged real dataset.
Use `--demo-fixture` only when you explicitly want the small development
fixture.

Run normally: python reset_db.py
Run demo fixture: python reset_db.py --demo-fixture
"""
import sys
from datetime import datetime, timedelta, timezone

from database import DB_PATH, SCHEMA_SQL, db_session, row_counts

DROP_SQL = """
DROP TABLE IF EXISTS attack_incidents;
DROP TABLE IF EXISTS control_vulnerability_map;
DROP TABLE IF EXISTS applied_controls;
DROP TABLE IF EXISTS risk_scores_history;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS controls;
DROP TABLE IF EXISTS assets;
"""

FIXTURE_ASSETS = [
    ("A-001", "Core Banking DB", "Database", 5, "Retail Banking"),
    ("A-002", "Customer Portal Web App", "Web Application", 4, "Digital Channels"),
    ("A-003", "Employee VPN Gateway", "Network", 3, "IT Infrastructure"),
    ("A-004", "HR Payroll Server", "Server", 2, "Human Resources"),
    ("A-005", "Branch POS Terminal Fleet", "Endpoint", 3, "Retail Banking"),
]

FIXTURE_VULNS = [
    # id, cve_id, asset_id, cvss_score, epss_score, description, discovered_at
    ("V-001", "CVE-2024-3094", "A-001", 9.8, 0.62, "Backdoor in compression library used by DB tooling", "2024-03-29"),
    ("V-002", "CVE-2023-44487", "A-001", 7.5, 0.41, "HTTP/2 rapid reset DoS on exposed admin interface", "2023-10-10"),
    ("V-003", "CVE-2021-44228", "A-002", 10.0, 0.85, "Log4Shell RCE in logging dependency", "2021-12-10"),
    ("V-004", "CVE-2022-22965", "A-002", 9.8, 0.55, "Spring4Shell RCE in web framework", "2022-03-31"),
    ("V-005", "CVE-2023-20198", "A-003", 10.0, 0.70, "Unauthenticated privilege escalation on VPN web UI", "2023-10-16"),
    ("V-006", "CVE-2020-1472", "A-004", 10.0, 0.35, "Zerologon privilege escalation to domain controller", "2020-08-11"),
    ("V-007", "CVE-2019-11510", "A-005", 10.0, 0.48, "Arbitrary file read on unpatched SSL VPN endpoint", "2019-04-24"),
]

FIXTURE_CONTROLS = [
    # id, name, cost_inr, risk_reduction_pct, framework_tags
    ("C-001", "Patch management automation rollout", 1200000, 25.0, "ISO27001-A.12,NIST-PR.MA,CIS-7"),
    ("C-002", "Web Application Firewall (WAF) deployment", 900000, 18.0, "ISO27001-A.13,NIST-PR.PT,CIS-13"),
    ("C-003", "Multi-factor authentication for VPN/remote access", 400000, 20.0, "ISO27001-A.9,NIST-PR.AC,RBI-Cyber-2"),
    ("C-004", "Endpoint Detection & Response (EDR) fleet-wide", 2500000, 30.0, "ISO27001-A.12,NIST-DE.CM,CIS-10"),
    ("C-005", "Quarterly third-party penetration testing", 600000, 10.0, "ISO27001-A.18,NIST-ID.RA,RBI-Cyber-4"),
    ("C-006", "Security awareness & phishing simulation program", 250000, 8.0, "ISO27001-A.7,NIST-PR.AT,CIS-14"),
    ("C-007", "Database activity monitoring & encryption at rest", 1800000, 22.0, "ISO27001-A.10,NIST-PR.DS,RBI-Cyber-1"),
    ("C-008", "Network segmentation for branch POS fleet", 1500000, 15.0, "ISO27001-A.13,NIST-PR.AC,CIS-12"),
]


def generate_control_vulnerability_map(conn):
    """Seed realistic control-to-vulnerability coverage for the demo fixture."""
    rules = {
        "C-001": [("ALL", 35.0)],  # patch management
        "C-002": [("A-002", 65.0)], # WAF -> web app
        "C-003": [("A-003", 75.0)], # MFA -> VPN
        "C-004": [("A-004", 55.0), ("A-005", 45.0)], # EDR -> server/endpoints
        "C-005": [("ALL", 20.0)],
        "C-006": [("A-005", 20.0)],
        "C-007": [("A-001", 70.0)], # DB monitoring/encryption
        "C-008": [("A-005", 65.0)], # POS segmentation
    }
    rows = []
    for control_id, targets in rules.items():
        for target, pct in targets:
            if target == "ALL":
                vulns = conn.execute("SELECT id FROM vulnerabilities").fetchall()
            else:
                vulns = conn.execute("SELECT id FROM vulnerabilities WHERE asset_id = ?", (target,)).fetchall()
            rows.extend((control_id, v["id"], pct) for v in vulns)
    conn.executemany(
        "INSERT OR REPLACE INTO control_vulnerability_map (control_id, vulnerability_id, reduction_pct) VALUES (?,?,?)",
        rows,
    )
    conn.commit()
    print(f"[control_vulnerability_map] generated {len(rows)} mappings")


def rebuild(schema_only: bool = False):
    with db_session() as conn:
        conn.executescript(DROP_SQL)
        conn.executescript(SCHEMA_SQL)

        if not schema_only:
            conn.executemany(
                "INSERT INTO assets (id, name, category, criticality, business_unit) VALUES (?,?,?,?,?)",
                FIXTURE_ASSETS,
            )
            conn.executemany(
                """INSERT INTO vulnerabilities
                   (id, cve_id, asset_id, cvss_score, epss_score, description, discovered_at)
                   VALUES (?,?,?,?,?,?,?)""",
                FIXTURE_VULNS,
            )
            conn.executemany(
                "INSERT INTO controls (id, name, cost_inr, risk_reduction_pct, framework_tags) VALUES (?,?,?,?,?)",
                FIXTURE_CONTROLS,
            )
            generate_control_vulnerability_map(conn)

            # A tiny risk_scores_history trail (last 5 days) per asset so the
            # frontend has something to chart in risk_trend without waiting
            # on the data pipeline.
            today = datetime.now(timezone.utc).date()
            history_rows = []
            for asset_id, _, _, criticality, _ in FIXTURE_ASSETS:
                for days_ago in range(4, -1, -1):
                    date = (today - timedelta(days=days_ago)).isoformat()
                    # Simple synthetic upward-ish trend, not derived from the
                    # real FAIR calc -- this table is just history/audit trail
                    # seed data, the live numbers always come from /api/risk/*.
                    synthetic_loss = 200000 * criticality * (5 - days_ago)
                    synthetic_score = min(100.0, 10.0 * criticality * (5 - days_ago) / 5)
                    history_rows.append((asset_id, date, synthetic_loss, synthetic_score))

            conn.executemany(
                """INSERT INTO risk_scores_history (asset_id, date, expected_annual_loss_inr, risk_score)
                   VALUES (?,?,?,?)""",
                history_rows,
            )

        counts = row_counts(conn)

    print(f"Database rebuilt at {DB_PATH}")
    print(f"Row counts: {counts}")


if __name__ == "__main__":
    # The packaged project ships with the real 52-asset / 112-vulnerability dataset.
    # Do NOT destroy it on a normal startup. Use --demo-fixture only when a tiny
    # development dataset is explicitly desired.
    if "--demo-fixture" in sys.argv:
        rebuild(schema_only=False)
    else:
        from database import ensure_schema
        ensure_schema()
        with db_session() as conn:
            counts = row_counts(conn)
            mapping_count = conn.execute("SELECT COUNT(*) AS c FROM control_vulnerability_map").fetchone()["c"]
        print(f"Real dataset preserved at {DB_PATH}")
        print(f"Row counts: {counts}; control-vulnerability mappings: {mapping_count}")
