#!/usr/bin/env python3
"""
build_pipeline.py — AegisQ data pipeline for SIH26105.

Populates ./data/aegisq.db per the shared contract. Safe to re-run
(drops + rebuilds all tables every time).

Run:
    python build_pipeline.py

What it does, in order:
  1. (Re)create schema from create_schema.sql
  2. Generate a synthetic asset inventory (40-60 assets)
  3. Fetch REAL CVE data from NVD + real EPSS scores from FIRST.org.
     If the network is unavailable / rate-limited (common at hackathon
     venue wifi, or in a sandboxed dev environment), fall back to a
     curated pool of well-known, publicly documented real CVEs with
     approximate CVSS/EPSS values, cached to disk either way so re-runs
     don't hit the network again.
  4. Assign 1-4 CVEs per asset, matched sensibly to asset category.
  5. Build a controls catalogue (15-20 controls) with real ISO 27001 /
     NIST CSF / CIS Controls references.
  6. Generate 90 days of risk_scores_history per asset with a believable
     trend (some improving, some degrading).
  7. Mark a handful of controls as already applied (for demo realism).
  8. Print a health-check summary matching GET /api/health's shape.
"""

import json
import math
import random
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# --------------------------------------------------------------------------
# Paths / constants
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "aegisq.db"
SCHEMA_PATH = ROOT / "create_schema.sql"
CACHE_DIR = ROOT / "cache"
CVE_CACHE_PATH = CACHE_DIR / "cve_epss_cache.json"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"

random.seed(42)  # reproducible demo data across re-runs

NOW = datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# 1. Schema
# --------------------------------------------------------------------------

def create_schema(conn: sqlite3.Connection) -> None:
    sql = SCHEMA_PATH.read_text()
    conn.executescript(sql)
    conn.commit()
    print(f"[schema] recreated from {SCHEMA_PATH.name}")


# --------------------------------------------------------------------------
# 2. Assets
# --------------------------------------------------------------------------

ASSET_CATEGORIES = [
    "Web Server", "Database", "Employee Laptop", "Payment Gateway",
    "IoT Sensor", "Network Device", "Email Server", "API Gateway",
]
BUSINESS_UNITS = ["Finance", "HR", "Operations", "IT", "Sales", "Executive"]

# category -> (min_criticality, max_criticality) — payment/finance-adjacent
# categories are weighted high, general endpoints weighted low.
CATEGORY_CRITICALITY = {
    "Payment Gateway": (4, 5),
    "Database": (3, 5),
    "API Gateway": (3, 5),
    "Web Server": (2, 4),
    "Email Server": (2, 4),
    "Network Device": (3, 5),
    "IoT Sensor": (1, 3),
    "Employee Laptop": (1, 3),
}

ASSET_NAME_PREFIXES = {
    "Web Server": ["web", "www", "app"],
    "Database": ["db", "sql", "data"],
    "Employee Laptop": ["laptop"],
    "Payment Gateway": ["paygw", "pay"],
    "IoT Sensor": ["iot", "sensor"],
    "Network Device": ["fw", "router", "vpn"],
    "Email Server": ["mail", "smtp"],
    "API Gateway": ["api", "gw"],
}


def generate_assets(conn: sqlite3.Connection, n: int = 52):
    assets = []
    counters = {cat: 0 for cat in ASSET_CATEGORIES}
    for i in range(1, n + 1):
        category = random.choice(ASSET_CATEGORIES)
        counters[category] += 1
        bu = random.choice(BUSINESS_UNITS)
        # Payment/DB assets skew toward Finance/Operations business units
        if category in ("Payment Gateway", "Database") and random.random() < 0.6:
            bu = random.choice(["Finance", "Operations"])
        lo, hi = CATEGORY_CRITICALITY[category]
        criticality = random.randint(lo, hi)
        prefix = random.choice(ASSET_NAME_PREFIXES[category])
        name = f"{prefix}-{counters[category]:02d}.{bu.lower()}.aegisq.local"
        asset_id = f"AST-{i:03d}"
        assets.append({
            "id": asset_id, "name": name, "category": category,
            "criticality": criticality, "business_unit": bu,
        })

    conn.executemany(
        "INSERT INTO assets (id, name, category, criticality, business_unit) "
        "VALUES (:id, :name, :category, :criticality, :business_unit)",
        assets,
    )
    conn.commit()
    print(f"[assets] generated {len(assets)} assets across {len(ASSET_CATEGORIES)} categories")
    return assets


# --------------------------------------------------------------------------
# 3. CVE + EPSS data — real API first, curated real-CVE fallback second
# --------------------------------------------------------------------------

# Curated pool of well-known, PUBLICLY DOCUMENTED real CVEs (Log4Shell,
# ProxyLogon, EternalBlue, etc.). Used only if the live NVD/EPSS APIs are
# unreachable (e.g. locked-down sandbox, venue wifi, rate limiting).
# CVSS scores are the widely-published NVD base scores for these CVEs;
# EPSS values are illustrative (EPSS updates daily) — refresh via the
# live API before your final submission if you want exact current figures.
FALLBACK_CVE_POOL = [
    # (cve_id, cvss, epss, applies_to categories, short description)
    ("CVE-2021-44228", 10.0, 0.97, ["Web Server", "API Gateway", "Email Server"],
     "Apache Log4j2 JNDI lookup remote code execution (Log4Shell)"),
    ("CVE-2024-3400", 10.0, 0.95, ["Network Device"],
     "Palo Alto PAN-OS GlobalProtect command injection, unauthenticated RCE"),
    ("CVE-2023-34362", 9.8, 0.94, ["Database", "Web Server"],
     "Progress MOVEit Transfer SQL injection leading to RCE"),
    ("CVE-2017-0144", 8.1, 0.93, ["Employee Laptop", "Network Device"],
     "Windows SMBv1 remote code execution (EternalBlue)"),
    ("CVE-2021-34527", 8.8, 0.91, ["Employee Laptop", "Database"],
     "Windows Print Spooler remote code execution (PrintNightmare)"),
    ("CVE-2014-0160", 7.5, 0.85, ["Web Server", "API Gateway"],
     "OpenSSL heartbeat memory disclosure (Heartbleed)"),
    ("CVE-2017-5638", 10.0, 0.92, ["Web Server", "Payment Gateway"],
     "Apache Struts2 Jakarta Multipart parser RCE"),
    ("CVE-2019-19781", 9.8, 0.9, ["Network Device"],
     "Citrix ADC / Gateway directory traversal RCE"),
    ("CVE-2020-1472", 10.0, 0.93, ["Database", "Network Device"],
     "Netlogon elevation of privilege (Zerologon)"),
    ("CVE-2022-30190", 7.8, 0.82, ["Employee Laptop"],
     "Microsoft Windows Support Diagnostic Tool RCE (Follina)"),
    ("CVE-2023-23397", 9.8, 0.88, ["Email Server", "Employee Laptop"],
     "Microsoft Outlook elevation of privilege via crafted reminder"),
    ("CVE-2021-26855", 9.8, 0.93, ["Email Server"],
     "Microsoft Exchange Server SSRF (ProxyLogon)"),
    ("CVE-2023-4863", 8.8, 0.7, ["Employee Laptop"],
     "Chromium/WebP heap buffer overflow"),
    ("CVE-2016-10033", 9.8, 0.75, ["Web Server"],
     "PHPMailer remote code execution"),
    ("CVE-2018-13379", 9.8, 0.89, ["Network Device"],
     "Fortinet FortiOS SSL VPN path traversal, credential disclosure"),
    ("CVE-2021-21985", 9.8, 0.8, ["Database", "Web Server"],
     "VMware vCenter Server remote code execution"),
    ("CVE-2022-26134", 9.8, 0.86, ["Web Server", "API Gateway"],
     "Atlassian Confluence OGNL injection RCE"),
    ("CVE-2019-11510", 10.0, 0.91, ["Network Device"],
     "Pulse Secure VPN arbitrary file read, pre-auth"),
    ("CVE-2017-11882", 7.8, 0.78, ["Employee Laptop"],
     "Microsoft Office Equation Editor memory corruption RCE"),
    ("CVE-2019-0708", 9.8, 0.87, ["Database", "Employee Laptop"],
     "Windows Remote Desktop Services RCE (BlueKeep)"),
    ("CVE-2023-38831", 7.8, 0.65, ["Employee Laptop"],
     "WinRAR crafted archive code execution"),
    ("CVE-2021-3156", 7.8, 0.6, ["Database", "Web Server"],
     "sudo heap-based buffer overflow (Baron Samedit)"),
    ("CVE-2022-0847", 7.8, 0.55, ["Database", "Web Server"],
     "Linux kernel pipe buffer privilege escalation (Dirty Pipe)"),
    ("CVE-2021-41773", 9.8, 0.84, ["Web Server"],
     "Apache HTTP Server path traversal / RCE"),
    ("CVE-2023-27997", 9.8, 0.83, ["Network Device"],
     "Fortinet FortiOS/FortiProxy SSL-VPN heap overflow (XORtigate)"),
    ("CVE-2022-22965", 9.8, 0.81, ["Web Server", "API Gateway"],
     "Spring Framework RCE via data binding (Spring4Shell)"),
    ("CVE-2021-40444", 8.8, 0.68, ["Employee Laptop"],
     "MSHTML remote code execution via crafted Office document"),
    ("CVE-2021-36260", 9.8, 0.72, ["IoT Sensor"],
     "Hikvision IP camera command injection"),
    ("CVE-2019-2725", 9.8, 0.5, ["Database", "Web Server"],
     "Oracle WebLogic Server deserialization RCE"),
    ("CVE-2022-22947", 10.0, 0.6, ["Payment Gateway", "API Gateway"],
     "Spring Cloud Gateway Actuator RCE"),
    ("CVE-2023-22515", 9.1, 0.58, ["Web Server"],
     "Atlassian Confluence broken access control, privilege escalation"),
    ("CVE-2020-0601", 8.1, 0.4, ["Employee Laptop", "Database"],
     "Windows CryptoAPI certificate spoofing (CurveBall)"),
    ("CVE-2022-1388", 9.8, 0.76, ["Network Device", "API Gateway"],
     "F5 BIG-IP iControl REST unauthenticated RCE"),
    ("CVE-2021-22986", 9.8, 0.66, ["Network Device"],
     "F5 BIG-IP/BIG-IQ iControl REST auth bypass RCE"),
    ("CVE-2023-3519", 9.8, 0.79, ["Network Device", "Payment Gateway"],
     "Citrix ADC / Gateway unauthenticated RCE"),
    ("CVE-2021-22005", 9.8, 0.62, ["Database", "Web Server"],
     "VMware vCenter Server file upload RCE"),
    ("CVE-2020-14882", 9.8, 0.55, ["Web Server", "Database"],
     "Oracle WebLogic Server remote code execution"),
    ("CVE-2018-11776", 8.1, 0.45, ["Web Server"],
     "Apache Struts2 namespace RCE"),
    ("CVE-2022-40684", 9.8, 0.63, ["Network Device", "API Gateway"],
     "Fortinet FortiOS/FortiProxy authentication bypass"),
    ("CVE-2019-12780", 8.8, 0.3, ["IoT Sensor"],
     "D-Link router authentication bypass"),
    ("CVE-2023-29357", 9.8, 0.52, ["Database", "Payment Gateway"],
     "Microsoft SharePoint Server elevation of privilege"),
]


def fetch_live_cve_epss():
    """Attempt to pull real, current CVE + EPSS data. Returns None on any
    failure so the caller can fall back cleanly."""
    try:
        print("[cve] attempting live NVD fetch...")
        # NVD hard-caps pubStartDate..pubEndDate at a 120-day window (a wider
        # range is rejected). Compute a fresh 120-day window ending "now"
        # each run instead of a hardcoded, eventually-stale date range.
        pub_end = NOW
        pub_start = NOW - timedelta(days=120)
        params = {
            "resultsPerPage": 60,
            "pubStartDate": pub_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": pub_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        headers = {"User-Agent": "aegisq-pipeline/1.0 (SIH26105)"}

        resp = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        if resp.status_code in (403, 404, 429, 503):
            # NVD's public API is known to be intermittently flaky
            # (rate limiting / brief outages) independent of request
            # correctness. One short retry costs little and often clears it.
            print(f"[cve] NVD returned {resp.status_code}, retrying once in 5s...")
            time.sleep(5)
            resp = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            raise ValueError("NVD returned no results")

        pool = []
        for v in vulns:
            cve = v["cve"]
            cve_id = cve["id"]
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0]["cvssData"]["baseScore"]
                    break
            if cvss is None:
                continue
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            )[:300]

            # EPSS lookup (small pause to be polite to the free API)
            time.sleep(0.05)
            epss_resp = requests.get(EPSS_API, params={"cve": cve_id}, timeout=10)
            epss_score = 0.05
            if epss_resp.ok:
                data = epss_resp.json().get("data", [])
                if data:
                    epss_score = float(data[0]["epss"])

            pool.append({
                "cve_id": cve_id, "cvss": cvss, "epss": epss_score,
                "categories": random.sample(ASSET_CATEGORIES, k=random.randint(1, 3)),
                "description": desc,
            })

        if len(pool) < 10:
            raise ValueError("too few usable CVEs returned")
        print(f"[cve] live fetch succeeded: {len(pool)} CVEs with real CVSS+EPSS")
        return pool

    except Exception as e:
        print(f"[cve] live fetch failed ({e}) — using cached / fallback pool")
        return None


def load_cve_epss_pool():
    CACHE_DIR.mkdir(exist_ok=True)

    if CVE_CACHE_PATH.exists():
        print(f"[cve] loading cached pool from {CVE_CACHE_PATH.name}")
        return json.loads(CVE_CACHE_PATH.read_text())

    live_pool = fetch_live_cve_epss()
    if live_pool:
        pool = live_pool
        source = "live_nvd_epss"
    else:
        pool = [
            {"cve_id": cve, "cvss": cvss, "epss": epss, "categories": cats,
             "description": desc}
            for cve, cvss, epss, cats, desc in FALLBACK_CVE_POOL
        ]
        source = "curated_fallback_real_cves"

    CVE_CACHE_PATH.write_text(json.dumps({"source": source, "pool": pool}, indent=2))
    print(f"[cve] cached {len(pool)} CVEs (source={source}) to {CVE_CACHE_PATH.name}")
    return {"source": source, "pool": pool}


def assign_vulnerabilities(conn: sqlite3.Connection, assets, cve_cache):
    pool = cve_cache["pool"]
    by_category = {cat: [] for cat in ASSET_CATEGORIES}
    for entry in pool:
        for cat in entry["categories"]:
            if cat in by_category:
                by_category[cat].append(entry)

    rows = []
    vuln_counter = 1
    for asset in assets:
        candidates = by_category.get(asset["category"]) or pool
        n = random.randint(1, min(4, len(candidates)))
        chosen = random.sample(candidates, k=n)
        for entry in chosen:
            discovered = NOW - timedelta(days=random.randint(1, 500))
            rows.append({
                "id": f"VULN-{vuln_counter:04d}",
                "cve_id": entry["cve_id"],
                "asset_id": asset["id"],
                "cvss_score": round(float(entry["cvss"]), 1),
                "epss_score": round(float(entry["epss"]), 4),
                "description": entry["description"],
                "discovered_at": iso(discovered),
            })
            vuln_counter += 1

    conn.executemany(
        "INSERT INTO vulnerabilities "
        "(id, cve_id, asset_id, cvss_score, epss_score, description, discovered_at) "
        "VALUES (:id, :cve_id, :asset_id, :cvss_score, :epss_score, :description, :discovered_at)",
        rows,
    )
    conn.commit()
    print(f"[vulnerabilities] assigned {len(rows)} vulnerability instances "
          f"({cve_cache['source']})")
    return rows


# --------------------------------------------------------------------------
# 4. Controls catalogue — real ISO 27001 / NIST CSF / CIS Controls tags
# --------------------------------------------------------------------------

CONTROLS = [
    ("Multi-Factor Authentication rollout", 800_000, 45,
     "ISO27001-A.5.17,NIST-PR.AC-1,CIS-6"),
    ("Endpoint Detection & Response (EDR) deployment", 3_500_000, 40,
     "ISO27001-A.8.7,NIST-DE.CM-1,CIS-10"),
    ("Network segmentation", 2_500_000, 35,
     "ISO27001-A.8.22,NIST-PR.AC-5,CIS-12"),
    ("Patch management automation", 1_200_000, 50,
     "ISO27001-A.8.8,NIST-ID.RA-1,CIS-7"),
    ("Security awareness training program", 300_000, 25,
     "ISO27001-A.6.3,NIST-PR.AT-1,CIS-14"),
    ("Web Application Firewall (WAF)", 900_000, 30,
     "ISO27001-A.8.26,NIST-PR.PT-3,CIS-13"),
    ("Data Loss Prevention (DLP)", 1_800_000, 28,
     "ISO27001-A.8.12,NIST-PR.DS-5,CIS-3"),
    ("Privileged Access Management (PAM)", 2_200_000, 42,
     "ISO27001-A.8.2,NIST-PR.AC-4,CIS-5"),
    ("SIEM / centralized log monitoring upgrade", 4_000_000, 33,
     "ISO27001-A.8.15,NIST-DE.AE-3,CIS-8"),
    ("Continuous vulnerability scanning program", 700_000, 38,
     "ISO27001-A.8.8,NIST-ID.RA-1,CIS-7"),
    ("Backup & disaster recovery hardening", 1_500_000, 20,
     "ISO27001-A.8.13,NIST-RC.RP-1,CIS-11"),
    ("Email security gateway / anti-phishing", 600_000, 30,
     "ISO27001-A.8.23,NIST-PR.DS-2,CIS-9"),
    ("Cloud Security Posture Management (CSPM)", 1_600_000, 27,
     "ISO27001-A.8.9,NIST-ID.AM-2,CIS-4"),
    ("Incident response plan + retainer", 500_000, 15,
     "ISO27001-A.5.24,NIST-RS.RP-1,CIS-17"),
    ("Zero Trust Network Access (ZTNA) rollout", 3_000_000, 37,
     "ISO27001-A.8.20,NIST-PR.AC-3,CIS-12"),
    ("Database encryption at rest", 900_000, 22,
     "ISO27001-A.8.24,NIST-PR.DS-1,CIS-3"),
    ("Third-party / vendor risk assessment program", 400_000, 18,
     "ISO27001-A.5.19,NIST-ID.SC-2,CIS-15"),
    ("IoT device network isolation & firmware management", 1_100_000, 32,
     "ISO27001-A.8.9,NIST-PR.PT-3,CIS-2"),
]


def generate_controls(conn: sqlite3.Connection):
    rows = [
        {"id": f"CTRL-{i:03d}", "name": name, "cost_inr": cost,
         "risk_reduction_pct": pct, "framework_tags": tags}
        for i, (name, cost, pct, tags) in enumerate(CONTROLS, start=1)
    ]
    conn.executemany(
        "INSERT INTO controls (id, name, cost_inr, risk_reduction_pct, framework_tags) "
        "VALUES (:id, :name, :cost_inr, :risk_reduction_pct, :framework_tags)",
        rows,
    )
    conn.commit()
    print(f"[controls] generated {len(rows)} controls")
    return rows


# --------------------------------------------------------------------------
# 5. Control -> vulnerability coverage
# --------------------------------------------------------------------------

def generate_control_vulnerability_map(conn, controls, vulns, assets):
    """Create explainable control coverage from asset categories and control names."""
    rows = []
    for control in controls:
        name = control["name"].lower()
        for v in vulns:
            asset = next((a for a in assets if a["id"] == v["asset_id"]), None)
            if not asset:
                continue
            category = asset["category"].lower()
            pct = 0.0
            if "patch" in name:
                pct = 35.0
            elif "firewall" in name or "waf" in name:
                pct = 65.0 if "web" in category or "api" in category else 0.0
            elif "multi-factor" in name or "mfa" in name:
                pct = 75.0 if "network" in category or "vpn" in v["description"].lower() else 0.0
            elif "endpoint detection" in name or "edr" in name:
                pct = 55.0 if any(x in category for x in ("endpoint", "laptop", "server")) else 0.0
            elif "database" in name:
                pct = 70.0 if "database" in category else 0.0
            elif "segmentation" in name:
                pct = 65.0 if any(x in category for x in ("network", "iot")) else 0.0
            elif "vulnerability scanning" in name:
                pct = 40.0
            elif "penetration" in name:
                pct = 20.0
            elif "backup" in name or "disaster" in name:
                pct = 20.0
            elif "security awareness" in name or "phishing" in name:
                pct = 20.0
            if pct:
                rows.append((control["id"], v["id"], pct))
    conn.executemany(
        "INSERT OR REPLACE INTO control_vulnerability_map (control_id, vulnerability_id, reduction_pct) VALUES (?,?,?)",
        rows,
    )
    conn.commit()
    print(f"[control_vulnerability_map] generated {len(rows)} mappings")


# --------------------------------------------------------------------------
# 5. Risk score history (90 days, per asset, believable trend)
# --------------------------------------------------------------------------

# Impact bands (₹) by criticality — rough business-loss-if-fully-compromised
# figures used only to seed a believable EAL; the actual engine your
# backend team builds should replace this with the real Likelihood x Impact
# calculation described in your risk model.
IMPACT_BY_CRITICALITY = {
    1: 500_000, 2: 2_000_000, 3: 8_000_000, 4: 25_000_000, 5: 60_000_000,
}


def generate_risk_history(conn: sqlite3.Connection, assets, vulns, days: int = 90):
    vulns_by_asset = {}
    for v in vulns:
        vulns_by_asset.setdefault(v["asset_id"], []).append(v)

    rows = []
    for asset in assets:
        asset_vulns = vulns_by_asset.get(asset["id"], [])
        base_impact = IMPACT_BY_CRITICALITY[asset["criticality"]]

        # Aggregate likelihood proxy from EPSS + CVSS of this asset's CVEs
        if asset_vulns:
            likelihood = sum(
                0.6 * v["epss_score"] + 0.4 * (v["cvss_score"] / 10)
                for v in asset_vulns
            ) / len(asset_vulns)
        else:
            likelihood = 0.05

        # Trend: ~55% of assets improving (patching down risk over time),
        # ~30% degrading (drifting/new exposure), ~15% flat/noisy.
        trend_type = random.choices(
            ["improving", "degrading", "flat"], weights=[0.55, 0.30, 0.15]
        )[0]
        if trend_type == "improving":
            start_mult, end_mult = 1.3, 0.75
        elif trend_type == "degrading":
            start_mult, end_mult = 0.8, 1.35
        else:
            start_mult, end_mult = 1.0, 1.0

        for day_offset in range(days, -1, -1):
            date = NOW - timedelta(days=day_offset)
            progress = 1 - (day_offset / days)
            mult = start_mult + (end_mult - start_mult) * progress
            noise = random.uniform(0.92, 1.08)
            day_likelihood = max(0.01, min(0.99, likelihood * mult * noise))
            eal = round(day_likelihood * base_impact, 2)
            # Saturating curve instead of a hard linear clip, so the worst
            # assets spread out near the top instead of clustering at
            # exactly 100 — keeps the "top risk contributors" list
            # meaningfully differentiated for the demo.
            severity = day_likelihood * (0.35 + 0.13 * asset["criticality"])
            risk_score = round(100 * (1 - math.exp(-2.1 * severity)), 2)
            risk_score = max(0, min(100, risk_score))

            rows.append({
                "asset_id": asset["id"],
                "date": date.strftime("%Y-%m-%d"),
                "expected_annual_loss_inr": eal,
                "risk_score": risk_score,
            })

    conn.executemany(
        "INSERT INTO risk_scores_history (asset_id, date, expected_annual_loss_inr, risk_score) "
        "VALUES (:asset_id, :date, :expected_annual_loss_inr, :risk_score)",
        rows,
    )
    conn.commit()
    print(f"[risk_scores_history] generated {len(rows)} rows "
          f"({days + 1} days x {len(assets)} assets)")


# --------------------------------------------------------------------------
# 6. Applied controls (demo realism — a few already in place)
# --------------------------------------------------------------------------

def generate_applied_controls(conn: sqlite3.Connection, controls):
    already_applied = random.sample(controls, k=min(5, len(controls)))
    rows = []
    for c in already_applied:
        applied_at = NOW - timedelta(days=random.randint(10, 200))
        rows.append({"control_id": c["id"], "applied_at": iso(applied_at)})

    conn.executemany(
        "INSERT INTO applied_controls (control_id, applied_at) "
        "VALUES (:control_id, :applied_at)",
        rows,
    )
    conn.commit()
    names = ", ".join(c["name"] for c in already_applied)
    print(f"[applied_controls] marked {len(rows)} controls already applied: {names}")


# --------------------------------------------------------------------------
# 7. Health check (mirrors GET /api/health)
# --------------------------------------------------------------------------

def print_health(conn: sqlite3.Connection):
    counts = {}
    for table in ("assets", "vulnerabilities", "controls",
                  "risk_scores_history", "applied_controls"):
        counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    print("\n[health check] matches GET /api/health shape:")
    print(json.dumps({"status": "ok", "db_connected": True, "row_counts": counts}, indent=2))


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)

    create_schema(conn)
    assets = generate_assets(conn)
    cve_cache = load_cve_epss_pool()
    vulns = assign_vulnerabilities(conn, assets, cve_cache)
    controls = generate_controls(conn)
    generate_control_vulnerability_map(conn, controls, vulns, assets)
    generate_risk_history(conn, assets, vulns)
    generate_applied_controls(conn, controls)
    print_health(conn)

    conn.close()
    print(f"\nDone. Database written to {DB_PATH}")


if __name__ == "__main__":
    main()
