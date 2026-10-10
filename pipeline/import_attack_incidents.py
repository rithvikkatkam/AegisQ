"""Import/refresh historical attack incidents into AegisQ."""
from __future__ import annotations
import csv, sqlite3, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT.parent / "backend" / "data" / "aegisq.db"
BASE = ["id","company_name","attack_on","target_type","loss_inr","attack_type","threat_actor","incident_date","asset_id","vulnerability_id","description","source"]
OPTIONAL = ["records_affected","loss_log1p_inr","loss_type","loss_confidence","attack_category","actor_type","attribution_confidence","date_precision","vulnerability_link_confidence","training_eligible"]

def main(path_str: str):
    path = Path(path_str)
    if not path.exists(): raise SystemExit(f"CSV not found: {path}")
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        missing = [c for c in BASE if c not in fields]
        if missing: raise SystemExit(f"Missing columns: {missing}")
        rows=[]
        for line,row in enumerate(reader,start=2):
            if not row.get("id"): raise SystemExit(f"Line {line}: id is required")
            loss=float(row.get("loss_inr") or 0)
            records=(int(float(row["records_affected"])) if row.get("records_affected") not in (None,"",) else None)
            rows.append({
                **row,
                "loss_inr": loss,
                "records_affected": records,
                "loss_log1p_inr": row.get("loss_log1p_inr") or None,
                "loss_type": row.get("loss_type") or "unknown",
                "loss_confidence": row.get("loss_confidence") or "unverified",
                "attack_category": row.get("attack_category") or "Other",
                "actor_type": row.get("actor_type") or "Unknown",
                "attribution_confidence": row.get("attribution_confidence") or "unverified",
                "date_precision": row.get("date_precision") or "unknown",
                "vulnerability_link_confidence": row.get("vulnerability_link_confidence") or "unverified",
                "training_eligible": row.get("training_eligible") or "review_required",
                "target_type": row.get("target_type") or "Unknown",
            })
    conn=sqlite3.connect(DB_PATH); conn.execute("PRAGMA foreign_keys=ON")
    # Ensure forward-compatible columns exist.
    cols={r[1] for r in conn.execute("PRAGMA table_info(attack_incidents)").fetchall()}
    additions={
        "records_affected":"INTEGER", "loss_log1p_inr":"REAL", "loss_type":"TEXT NOT NULL DEFAULT 'unknown'",
        "loss_confidence":"TEXT NOT NULL DEFAULT 'unverified'", "attack_category":"TEXT NOT NULL DEFAULT 'Other'",
        "actor_type":"TEXT NOT NULL DEFAULT 'Unknown'", "attribution_confidence":"TEXT NOT NULL DEFAULT 'unverified'",
        "date_precision":"TEXT NOT NULL DEFAULT 'unknown'", "vulnerability_link_confidence":"TEXT NOT NULL DEFAULT 'unverified'",
        "training_eligible":"TEXT NOT NULL DEFAULT 'review_required'",
    }
    for name,typ in additions.items():
        if name not in cols: conn.execute(f"ALTER TABLE attack_incidents ADD COLUMN {name} {typ}")
    fields_out=["id","company_name","attack_on","target_type","records_affected","loss_inr","loss_log1p_inr","loss_type","loss_confidence","attack_type","attack_category","threat_actor","actor_type","attribution_confidence","incident_date","date_precision","asset_id","vulnerability_id","vulnerability_link_confidence","description","source","training_eligible"]
    sql=f"INSERT INTO attack_incidents ({','.join(fields_out)}) VALUES ({','.join('?' for _ in fields_out)}) ON CONFLICT(id) DO UPDATE SET " + ','.join(f"{c}=excluded.{c}" for c in fields_out[1:])
    values=[]
    for r in rows:
        import math
        values.append(tuple((math.log1p(r['loss_inr']) if k=='loss_log1p_inr' and not r[k] else r[k]) if k else r[k] for k in fields_out))
    conn.executemany(sql,values); conn.commit(); conn.close()
    print(f"Imported/updated {len(rows)} attack incidents into {DB_PATH}")

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("Usage: python3 import_attack_incidents.py path/to/attacks.csv")
    main(sys.argv[1])
