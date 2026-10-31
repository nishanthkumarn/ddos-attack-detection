from .config import settings

if settings.database_url.startswith("postgresql"):
    from .db_postgres import *  # noqa: F401,F403
else:
    import sqlite3
    from pathlib import Path
    from threading import Lock
    from .schemas import FlowEvent

    _lock = Lock()

    def _conn():
        Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(settings.database_path, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def init_db():
        with _lock, _conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS events(
              event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, src_ip TEXT, dst_ip TEXT,
              src_port INTEGER, dst_port INTEGER, protocol TEXT, label TEXT, probability REAL,
              confidence REAL, severity TEXT, bytes_per_second REAL, packets_per_second REAL,
              flow_duration_ms REAL, mode TEXT, model_version TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
            CREATE TABLE IF NOT EXISTS alerts(
              alert_id TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, src_ip TEXT,
              dst_ip TEXT, src_port INTEGER DEFAULT 0, dst_port INTEGER DEFAULT 0, protocol TEXT,
              severity TEXT, probability REAL, occurrences INTEGER, status TEXT, reason TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(last_seen);
            CREATE TABLE IF NOT EXISTS scans(
              scan_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, src_ip TEXT, dst_ip TEXT,
              src_port INTEGER, dst_port INTEGER, protocol TEXT, verdict TEXT, probability REAL,
              severity TEXT, attack_type TEXT, report_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(timestamp);
            """)
            cols = {r[1] for r in c.execute("PRAGMA table_info(alerts)").fetchall()}
            if "src_port" not in cols:
                c.execute("ALTER TABLE alerts ADD COLUMN src_port INTEGER DEFAULT 0")
            if "dst_port" not in cols:
                c.execute("ALTER TABLE alerts ADD COLUMN dst_port INTEGER DEFAULT 0")

    def insert_event(e: FlowEvent):
        with _lock, _conn() as c:
            c.execute("INSERT OR REPLACE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (e.event_id,e.timestamp.isoformat(),e.src_ip,e.dst_ip,e.src_port,e.dst_port,e.protocol,
                 e.label,e.probability,e.confidence,e.severity,e.bytes_per_second,e.packets_per_second,
                 e.flow_duration_ms,e.mode,e.model_version))
            c.execute("DELETE FROM events WHERE timestamp < datetime('now','-24 hours')")

    def upsert_alert(e: FlowEvent):
        if e.label != "DDoS" or e.probability < settings.alert_threshold:
            return None
        alert_id=f"{e.src_ip}|{e.src_port}|{e.dst_ip}|{e.dst_port}|{e.protocol}"
        now=e.timestamp.isoformat()
        with _lock, _conn() as c:
            row=c.execute("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)).fetchone()
            if row:
                c.execute("UPDATE alerts SET last_seen=?, severity=?, probability=?, occurrences=occurrences+1, status='OPEN' WHERE alert_id=?",
                          (now,e.severity,max(float(row['probability']),e.probability),alert_id))
            else:
                c.execute("INSERT INTO alerts(alert_id,first_seen,last_seen,src_ip,dst_ip,src_port,dst_port,protocol,severity,probability,occurrences,status,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (alert_id,now,now,e.src_ip,e.dst_ip,e.src_port,e.dst_port,e.protocol,e.severity,e.probability,1,'OPEN',
                           f"DDoS probability exceeded {settings.alert_threshold:.0%}"))
        return alert_id

    def stats():
        with _lock, _conn() as c:
            row=c.execute("SELECT COUNT(*) total, SUM(label='DDoS') attacks, SUM(label='BENIGN') benign FROM events").fetchone()
            recent=c.execute("SELECT COALESCE(AVG(packets_per_second),0) pps, COALESCE(AVG(bytes_per_second),0) bps FROM events WHERE timestamp >= datetime('now','-1 minute')").fetchone()
        total=int(row['total'] or 0); attacks=int(row['attacks'] or 0); benign=int(row['benign'] or 0)
        return total,attacks,benign,(attacks/total*100 if total else 0),float(recent['pps']),float(recent['bps'])

    def recent_events(limit=50):
        with _lock, _conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",(limit,)).fetchall()]

    def recent_alerts(limit=50):
        with _lock, _conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?",(limit,)).fetchall()]

    def timeline(minutes=30):
        with _lock, _conn() as c:
            rows=c.execute("""SELECT substr(timestamp,1,16) bucket, COUNT(*) total,
              SUM(label='DDoS') attacks, ROUND(AVG(packets_per_second),1) pps
              FROM events WHERE timestamp >= datetime('now', ?) GROUP BY bucket ORDER BY bucket""",(f'-{int(minutes)} minutes',)).fetchall()
        return [dict(r) for r in rows]

    def insert_scan(report: dict):
        import json
        with _lock, _conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    report["scan_id"],
                    report["timestamp"],
                    report.get("target", {}).get("src_ip", "0.0.0.0"),
                    report.get("target", {}).get("dst_ip", "0.0.0.0"),
                    int(report.get("target", {}).get("src_port", 0)),
                    int(report.get("target", {}).get("dst_port", 0)),
                    report.get("target", {}).get("protocol", "TCP"),
                    report.get("verdict", "BENIGN"),
                    float(report.get("probability", 0.0)),
                    report.get("threat_level", "LOW"),
                    report.get("attack_type", "Unknown"),
                    json.dumps(report),
                ),
            )

    def recent_scans(limit=20):
        import json
        with _lock, _conn() as c:
            rows = c.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                try:
                    out.append(json.loads(r["report_json"]))
                except Exception:
                    out.append(dict(r))
            return out

    def get_scan(scan_id: str):
        import json
        with _lock, _conn() as c:
            row = c.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row:
                try:
                    return json.loads(row["report_json"])
                except Exception:
                    return None
            return None
