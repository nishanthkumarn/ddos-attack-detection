"""PostgreSQL storage backend. Enabled when DATABASE_URL starts with postgresql://."""
from threading import Lock
from .config import settings
_lock=Lock()

def _conn():
    import psycopg
    return psycopg.connect(settings.database_url)

def init_db():
    with _lock, _conn() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY,timestamp TIMESTAMPTZ NOT NULL,src_ip TEXT,dst_ip TEXT,src_port INTEGER,dst_port INTEGER,protocol TEXT,label TEXT,probability DOUBLE PRECISION,confidence DOUBLE PRECISION,severity TEXT,bytes_per_second DOUBLE PRECISION,packets_per_second DOUBLE PRECISION,flow_duration_ms DOUBLE PRECISION,mode TEXT,model_version TEXT)''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp)'); c.execute('CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip)')
        c.execute('''CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,first_seen TIMESTAMPTZ,last_seen TIMESTAMPTZ,src_ip TEXT,dst_ip TEXT,src_port INTEGER DEFAULT 0,dst_port INTEGER DEFAULT 0,protocol TEXT,severity TEXT,probability DOUBLE PRECISION,occurrences INTEGER,status TEXT,reason TEXT)''')
        c.execute('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS src_port INTEGER DEFAULT 0'); c.execute('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dst_port INTEGER DEFAULT 0')
        c.execute('CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(last_seen)')

def insert_event(e):
    with _lock, _conn() as c:
        c.execute('''INSERT INTO events VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(event_id) DO NOTHING''', (e.event_id,e.timestamp,e.src_ip,e.dst_ip,e.src_port,e.dst_port,e.protocol,e.label,e.probability,e.confidence,e.severity,e.bytes_per_second,e.packets_per_second,e.flow_duration_ms,e.mode,e.model_version))
        c.execute("DELETE FROM events WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '24 hours'")

def upsert_alert(e):
    from .config import settings
    if e.label != 'DDoS' or e.probability < settings.alert_threshold: return None
    alert_id=f'{e.src_ip}|{e.src_port}|{e.dst_ip}|{e.dst_port}|{e.protocol}'
    with _lock, _conn() as c:
        row=c.execute('SELECT * FROM alerts WHERE alert_id=%s',(alert_id,)).fetchone()
        if row: c.execute("UPDATE alerts SET last_seen=%s,severity=%s,probability=GREATEST(probability,%s),occurrences=occurrences+1,status='OPEN' WHERE alert_id=%s",(e.timestamp,e.severity,e.probability,alert_id))
        else: c.execute('INSERT INTO alerts VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',(alert_id,e.timestamp,e.timestamp,e.src_ip,e.dst_ip,e.src_port,e.dst_port,e.protocol,e.severity,e.probability,1,'OPEN',f'DDoS probability exceeded {settings.alert_threshold:.0%}'))
    return alert_id

def _dicts(cur):
    cols=[d.name for d in cur.description]; return [dict(zip(cols,row)) for row in cur.fetchall()]
def recent_events(limit=50):
    with _conn() as c: return _dicts(c.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT %s',(limit,)))
def recent_alerts(limit=50):
    with _conn() as c: return _dicts(c.execute('SELECT * FROM alerts ORDER BY last_seen DESC LIMIT %s',(limit,)))
def timeline(minutes=30):
    with _conn() as c: return _dicts(c.execute("SELECT date_trunc('minute',timestamp) bucket,COUNT(*) total,COUNT(*) FILTER (WHERE label='DDoS') attacks,ROUND(AVG(packets_per_second)::numeric,1) pps FROM events WHERE timestamp >= CURRENT_TIMESTAMP - (%s * INTERVAL '1 minute') GROUP BY bucket ORDER BY bucket",(minutes,)))
def stats():
    with _conn() as c:
        row=c.execute("SELECT COUNT(*) total,COUNT(*) FILTER (WHERE label='DDoS') attacks,COUNT(*) FILTER (WHERE label='BENIGN') benign FROM events").fetchone()
        recent=c.execute("SELECT COALESCE(AVG(packets_per_second),0),COALESCE(AVG(bytes_per_second),0) FROM events WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '1 minute'").fetchone()
    total,attacks,benign=row; pps,bps=recent
    return int(total),int(attacks),int(benign),(attacks/total*100 if total else 0),float(pps),float(bps)
