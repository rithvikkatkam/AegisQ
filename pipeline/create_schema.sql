-- AegisQ schema — matches the shared contract exactly. Do not rename columns.
-- Safe to re-run: drops and recreates every table (idempotent).

DROP TABLE IF EXISTS control_vulnerability_map;
DROP TABLE IF EXISTS attack_incidents;
DROP TABLE IF EXISTS applied_controls;
DROP TABLE IF EXISTS risk_scores_history;
DROP TABLE IF EXISTS controls;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS assets;

PRAGMA foreign_keys = ON;

CREATE TABLE assets (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    category     TEXT NOT NULL,
    criticality  INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    business_unit TEXT NOT NULL
);

CREATE TABLE vulnerabilities (
    id            TEXT PRIMARY KEY,
    cve_id        TEXT NOT NULL,
    asset_id      TEXT NOT NULL REFERENCES assets(id),
    cvss_score    REAL NOT NULL CHECK (cvss_score BETWEEN 0 AND 10),
    epss_score    REAL NOT NULL CHECK (epss_score BETWEEN 0 AND 1),
    description   TEXT,
    discovered_at TEXT NOT NULL  -- ISO8601
);

CREATE TABLE controls (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    cost_inr           REAL NOT NULL,
    risk_reduction_pct REAL NOT NULL CHECK (risk_reduction_pct BETWEEN 0 AND 100),
    framework_tags     TEXT  -- comma-separated e.g. "ISO27001-A.9,NIST-PR.AC,CIS-5"
);

CREATE TABLE control_vulnerability_map (
    control_id       TEXT NOT NULL REFERENCES controls(id),
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id),
    reduction_pct    REAL NOT NULL CHECK (reduction_pct BETWEEN 0 AND 100),
    PRIMARY KEY (control_id, vulnerability_id)
);

CREATE TABLE risk_scores_history (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id                  TEXT NOT NULL REFERENCES assets(id),
    date                      TEXT NOT NULL,  -- ISO8601
    expected_annual_loss_inr  REAL NOT NULL,
    risk_score                REAL NOT NULL CHECK (risk_score BETWEEN 0 AND 100)
);

CREATE TABLE applied_controls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id  TEXT NOT NULL REFERENCES controls(id),
    applied_at  TEXT NOT NULL  -- ISO8601
);

CREATE INDEX idx_vuln_asset ON vulnerabilities(asset_id);
CREATE INDEX idx_cvm_vuln ON control_vulnerability_map(vulnerability_id);
CREATE INDEX idx_history_asset_date ON risk_scores_history(asset_id, date);


CREATE TABLE attack_incidents (
    id             TEXT PRIMARY KEY,
    company_name   TEXT NOT NULL,
    attack_on      TEXT NOT NULL,
    target_type    TEXT NOT NULL DEFAULT 'Unknown',
    loss_inr       REAL NOT NULL CHECK (loss_inr >= 0),
    attack_type    TEXT NOT NULL,
    threat_actor   TEXT,
    incident_date  TEXT NOT NULL,
    asset_id       TEXT REFERENCES assets(id),
    vulnerability_id TEXT REFERENCES vulnerabilities(id),
    description    TEXT,
    source         TEXT
);

CREATE INDEX idx_attack_company ON attack_incidents(company_name);
CREATE INDEX idx_attack_date ON attack_incidents(incident_date);
CREATE INDEX idx_attack_type ON attack_incidents(attack_type);
CREATE INDEX idx_attack_vuln ON attack_incidents(vulnerability_id);
