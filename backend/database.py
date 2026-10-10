"""
database.py
-----------
Single place that knows how to open a connection to the shared SQLite file.
Both main.py (API) and reset_db.py (schema/fixture builder) import from here
so the schema definition only ever lives in one spot.

Contract: ./data/aegisq.db relative to repo root, shared by backend + pipeline.
"""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

# Resolved relative to this file (not the current working directory) so the
# backend finds the same database no matter where it is launched from
# (terminal, VS Code debugger, pytest, ...). AEGISQ_DB_PATH still overrides it.
_DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "aegisq.db"
DB_PATH = os.environ.get("AEGISQ_DB_PATH") or str(_DEFAULT_DB_PATH)

# Exact schema from the shared contract. snake_case columns, no deviations.
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT,
    criticality INTEGER CHECK (criticality BETWEEN 1 AND 5),
    business_unit TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    cve_id TEXT,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    cvss_score REAL,
    epss_score REAL,
    description TEXT,
    discovered_at TEXT
);

CREATE TABLE IF NOT EXISTS controls (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    cost_inr REAL,
    risk_reduction_pct REAL,
    framework_tags TEXT
);

CREATE TABLE IF NOT EXISTS risk_scores_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    date TEXT,
    expected_annual_loss_inr REAL,
    risk_score REAL
);

CREATE TABLE IF NOT EXISTS control_vulnerability_map (
    control_id TEXT NOT NULL REFERENCES controls(id),
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id),
    reduction_pct REAL NOT NULL CHECK (reduction_pct BETWEEN 0 AND 100),
    PRIMARY KEY (control_id, vulnerability_id)
);

CREATE TABLE IF NOT EXISTS applied_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id TEXT NOT NULL REFERENCES controls(id),
    applied_at TEXT
);

CREATE TABLE IF NOT EXISTS attack_incidents (
    id TEXT PRIMARY KEY,
    company_name TEXT NOT NULL,
    attack_on TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'Unknown',
    records_affected INTEGER,
    loss_log1p_inr REAL,
    loss_type TEXT NOT NULL DEFAULT 'unknown',
    loss_confidence TEXT NOT NULL DEFAULT 'unverified',
    loss_inr REAL NOT NULL CHECK (loss_inr >= 0),
    attack_type TEXT NOT NULL,
    attack_category TEXT NOT NULL DEFAULT 'Other',
    threat_actor TEXT,
    actor_type TEXT NOT NULL DEFAULT 'Unknown',
    attribution_confidence TEXT NOT NULL DEFAULT 'unverified',
    incident_date TEXT NOT NULL,
    date_precision TEXT NOT NULL DEFAULT 'unknown',
    asset_id TEXT REFERENCES assets(id),
    vulnerability_id TEXT REFERENCES vulnerabilities(id),
    vulnerability_link_confidence TEXT NOT NULL DEFAULT 'unverified',
    description TEXT,
    source TEXT,
    training_eligible TEXT NOT NULL DEFAULT 'review_required'
);
"""


def get_connection():
    """Return a sqlite3 connection with row access by column name."""
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def db_session():
    """Context-managed connection: `with db_session() as conn:`."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def ensure_schema():
    """Create tables if missing and apply small forward-compatible migrations."""
    with db_session() as conn:
        conn.executescript(SCHEMA_SQL)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(attack_incidents)").fetchall()}
        if "target_type" not in cols:
            conn.execute("ALTER TABLE attack_incidents ADD COLUMN target_type TEXT NOT NULL DEFAULT 'Unknown'")


def row_counts(conn):
    counts = {}
    for table in ("assets", "vulnerabilities", "controls", "attack_incidents", "risk_scores_history", "control_vulnerability_map"):
        counts[table] = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
    return counts


def rows_to_dicts(rows):
    return [dict(r) for r in rows]
