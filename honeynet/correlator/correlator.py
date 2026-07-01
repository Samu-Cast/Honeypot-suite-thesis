import os
import json
import sqlite3
import time
import queue
from datetime import datetime, timedelta, timezone
import threading
from urllib.request import urlopen, Request
from urllib.error import URLError

ALERTS_LOG = "/output/alerts.log"
COWRIE_LOG = "/logs/cowrie/cowrie.json"
OPENCANARY_LOG = "/logs/opencanary/opencanary.log"
DIONAEA_DB = "/data/dionaea/dionaea.sqlite"
OUTPUT_DB = "/output/correlations.db"
AGGREGATION_INTERVAL = 2

SESSION_WINDOW = timedelta(seconds=int(os.environ.get("SESSION_WINDOW_SECS", "15")))
BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", "5"))

print(f"[config] SESSION_WINDOW={SESSION_WINDOW.seconds}s  BRUTE_FORCE_THRESHOLD={BRUTE_FORCE_THRESHOLD}")

events_lock = threading.Lock()
active_sessions = {}  # { ip: [ {timestamp, source, event_type, detail}, ... ] }
session_last_added = {}  # { ip: datetime } — wall-clock time of the MOST RECENT event for the IP

enrich_queue = queue.Queue()
known_ips = set()
known_ips_lock = threading.Lock()


def get_db_conn(path=OUTPUT_DB):
    """Open a SQLite connection with a write timeout so concurrent threads
    don't crash with 'database is locked' under load."""
    return sqlite3.connect(path, timeout=10)


def init_db():
    os.makedirs(os.path.dirname(OUTPUT_DB), exist_ok=True)
    conn = get_db_conn()
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            source_ip TEXT,
            pattern TEXT,
            hits_cowrie INTEGER,
            hits_dionaea INTEGER,
            hits_opencanary INTEGER,
            first_seen DATETIME,
            last_seen DATETIME,
            UNIQUE(source_ip, first_seen)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_intel (
            ip TEXT PRIMARY KEY,
            country TEXT,
            country_code TEXT,
            city TEXT,
            lat REAL,
            lon REAL,
            isp TEXT,
            org TEXT,
            asn TEXT,
            reverse_dns TEXT,
            is_proxy INTEGER DEFAULT 0,
            is_hosting INTEGER DEFAULT 0,
            last_updated DATETIME
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT,
            detail TEXT
        )
    ''')
    conn.commit()

    cursor.execute("SELECT ip FROM ip_intel")
    with known_ips_lock:
        for row in cursor.fetchall():
            known_ips.add(row[0])
    print(f"[init] Loaded {len(known_ips)} already-enriched IPs from cache")

    # restore in-flight events that were not finalized before last shutdown
    cursor.execute("SELECT id, source_ip, timestamp, source, event_type, detail FROM pending_events")
    recovered = cursor.fetchall()
    if recovered:
        print(f"[init] Recovering {len(recovered)} in-flight events...")
        for row in recovered:
            row_id, src_ip, ts_str, src, evt_type, detail = row
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is not None:
                    ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                ts = datetime.utcnow()
            with events_lock:
                if src_ip not in active_sessions:
                    active_sessions[src_ip] = []
                session_last_added[src_ip] = datetime.utcnow()
                active_sessions[src_ip].append({
                    'timestamp': ts,
                    'source': src,
                    'event_type': evt_type,
                    'detail': detail,
                    'pending_rowid': row_id,
                })
        print(f"[init] Recovery complete — {len(active_sessions)} sessions restored")

    conn.close()


def add_event(source_ip, timestamp, source, event_type, detail):
    if not source_ip:
        return

    with known_ips_lock:
        if source_ip not in known_ips:
            known_ips.add(source_ip)
            enrich_queue.put(source_ip)

    with events_lock:
        if source_ip not in active_sessions:
            active_sessions[source_ip] = []
        # aggiornato a OGNI evento: la finalizzazione avviene per quiescenza
        session_last_added[source_ip] = datetime.utcnow()

        if isinstance(timestamp, str):
            try:
                ts_parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                # normalise to naive UTC regardless of the original timezone offset
                if ts_parsed.tzinfo is not None:
                    ts_parsed = ts_parsed.astimezone(timezone.utc).replace(tzinfo=None)
                timestamp = ts_parsed
            except Exception:
                timestamp = datetime.utcnow()

        active_sessions[source_ip].append({
            'timestamp': timestamp,
            'source': source,
            'event_type': event_type,
            'detail': detail,
            'pending_rowid': None,  # filled in below, outside the lock
        })

    # DB write is outside events_lock to avoid holding the lock during I/O.
    # We update the pending_rowid on the last element we just appended.
    try:
        pconn = get_db_conn()
        cur = pconn.execute(
            "INSERT INTO pending_events (source_ip, timestamp, source, event_type, detail) VALUES (?, ?, ?, ?, ?)",
            (source_ip, timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp),
             source, event_type, str(detail)[:500])
        )
        pending_rowid = cur.lastrowid
        pconn.commit()
        pconn.close()
        # back-fill the rowid so process_session() can do a precise DELETE
        with events_lock:
            sessions = active_sessions.get(source_ip)
            if sessions:
                sessions[-1]['pending_rowid'] = pending_rowid
    except Exception as e:
        print(f"[pending] Write error: {e}")


def follow_file(filename, source_name):
    while not os.path.exists(filename):
        time.sleep(1)

    with open(filename, 'r', errors='ignore') as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def tail_cowrie():
    for line in follow_file(COWRIE_LOG, 'cowrie'):
        try:
            data = json.loads(line)
            src_ip = data.get('src_ip')
            ts = data.get('timestamp')
            eventid = data.get('eventid')
            if src_ip and ts:
                add_event(src_ip, ts, 'cowrie', eventid, line.strip())
        except json.JSONDecodeError:
            pass


def tail_opencanary():
    for line in follow_file(OPENCANARY_LOG, 'opencanary'):
        try:
            data = json.loads(line)
            src_ip = data.get('src_host')
            ts = data.get('local_time')
            logdata = data.get('logdata', {})
            event_type = data.get('logtype', 'unknown')
            if src_ip and ts:
                add_event(src_ip, ts, 'opencanary', str(event_type), str(logdata))
        except json.JSONDecodeError:
            pass


def poll_dionaea():
    last_rowid = 0
    while True:
        if os.path.exists(DIONAEA_DB):
            try:
                conn = sqlite3.connect(f"file:{DIONAEA_DB}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT rowid, connection_timestamp, remote_host, connection_protocol
                    FROM connections
                    WHERE rowid > ?
                    ORDER BY rowid ASC
                """, (last_rowid,))

                rows = cursor.fetchall()
                for row in rows:
                    rowid, ts_epoch, src_ip, proto = row
                    last_rowid = rowid
                    if src_ip and ts_epoch:
                        ts = datetime.utcfromtimestamp(ts_epoch)
                        add_event(src_ip, ts, 'dionaea', proto, f"Protocol: {proto}")

                conn.close()
            except sqlite3.OperationalError:
                pass
            except Exception as e:
                print(f"Dionaea poll error: {e}")

        time.sleep(2)


# Grace period (wall-clock): a session is finalized only once no new event
# has arrived for the IP in this interval.  Must be >= SESSION_WINDOW and
# comfortably larger than the Dionaea poll interval, so the slower Dionaea
# poller has time to contribute its events to the same session.
FINALIZATION_DELAY = timedelta(seconds=int(os.environ.get("FINALIZATION_DELAY_SECS", "8")))


def analyze_and_aggregate():
    while True:
        time.sleep(AGGREGATION_INTERVAL)
        now = datetime.utcnow()

        # Collect sessions ready for finalization while holding the lock,
        # then process them (DB writes) outside the lock so add_event()
        # is never blocked during I/O.
        ready = []
        with events_lock:
            for ip, events in list(active_sessions.items()):
                if not events:
                    continue

                events.sort(key=lambda x: x['timestamp'])

                sessions_to_process = []
                current_session = [events[0]]

                for e in events[1:]:
                    gap = e['timestamp'] - current_session[-1]['timestamp']
                    if gap > SESSION_WINDOW:
                        sessions_to_process.append(current_session)
                        current_session = [e]
                    else:
                        current_session.append(e)
                sessions_to_process.append(current_session)

                latest_event_time = current_session[-1]['timestamp']
                last_added = session_last_added.get(ip, now)

                # Finalize only when the session window has expired AND no new
                # event has arrived for the IP in the last FINALIZATION_DELAY:
                # this gives the slower Dionaea poller time to contribute its
                # events to the same session before it is closed.
                if (now - latest_event_time > SESSION_WINDOW
                        and now - last_added > FINALIZATION_DELAY):
                    ready.append((ip, sessions_to_process))
                    del active_sessions[ip]
                    session_last_added.pop(ip, None)

        for ip, sessions in ready:
            for s in sessions:
                process_session(ip, s)


def classify_pattern(cowrie_hits, dionaea_hits, opencanary_hits, threshold=None):
    if threshold is None:
        threshold = BRUTE_FORCE_THRESHOLD

    if cowrie_hits > 0 and dionaea_hits > 0 and opencanary_hits > 0:
        return "FULL_SPECTRUM"
    elif cowrie_hits > 0 and dionaea_hits > 0:
        return "SSH_THEN_PAYLOAD"
    elif cowrie_hits > 0 and opencanary_hits > 0:
        return "SSH_THEN_LATERAL"
    elif dionaea_hits > 0 and opencanary_hits > 0:
        return "PAYLOAD_AND_LATERAL"
    elif cowrie_hits > threshold:
        return "BRUTE_FORCE_SSH"
    elif dionaea_hits > 0:
        return "AUTOMATED_EXPLOIT"
    elif opencanary_hits > 0:
        return "RECON_ONLY"
    elif cowrie_hits > 0:
        return "LOW_SSH_ACTIVITY"
    return "UNKNOWN"


def process_session(ip, events):
    cowrie_hits = sum(1 for e in events if e['source'] == 'cowrie')
    dionaea_hits = sum(1 for e in events if e['source'] == 'dionaea')
    opencanary_hits = sum(1 for e in events if e['source'] == 'opencanary')

    pattern = classify_pattern(cowrie_hits, dionaea_hits, opencanary_hits)

    first_seen = min([e['timestamp'] for e in events])
    last_seen = max([e['timestamp'] for e in events])

    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO correlations (timestamp, source_ip, pattern, hits_cowrie, hits_dionaea, hits_opencanary, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.utcnow(), ip, pattern, cowrie_hits, dionaea_hits, opencanary_hits, first_seen, last_seen))

        rowids = [e['pending_rowid'] for e in events if e.get('pending_rowid')]
        if rowids:
            placeholders = ",".join("?" * len(rowids))
            cursor.execute(f"DELETE FROM pending_events WHERE id IN ({placeholders})", rowids)

        conn.commit()
        conn.close()
        print(f"[+] {ip} -> {pattern} (cowrie:{cowrie_hits} dionaea:{dionaea_hits} canary:{opencanary_hits})")
    except Exception as e:
        print(f"Error saving to db: {e}")


def enrich_ip(ip):
    url = (
        f"http://ip-api.com/json/{ip}"
        f"?fields=status,country,countryCode,city,lat,lon,isp,org,as,reverse,proxy,hosting"
    )
    try:
        req = Request(url, headers={"User-Agent": "HoneynetCorrelator/1.0"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") != "success":
            print(f"[enrich] ip-api returned fail for {ip}: {data}")
            return None

        return {
            "ip": ip,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as", "").split()[0] if data.get("as") else None,
            "reverse_dns": data.get("reverse"),
            "is_proxy": 1 if data.get("proxy") else 0,
            "is_hosting": 1 if data.get("hosting") else 0,
        }
    except (URLError, OSError, json.JSONDecodeError) as e:
        print(f"[enrich] Error enriching {ip}: {e}")
        return None


def save_intel(intel):
    try:
        conn = get_db_conn()
        conn.execute('''
            INSERT OR REPLACE INTO ip_intel
            (ip, country, country_code, city, lat, lon, isp, org, asn,
             reverse_dns, is_proxy, is_hosting, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            intel["ip"], intel["country"], intel["country_code"],
            intel["city"], intel["lat"], intel["lon"],
            intel["isp"], intel["org"], intel["asn"],
            intel["reverse_dns"], intel["is_proxy"], intel["is_hosting"],
            datetime.utcnow().isoformat()
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[enrich] DB error saving intel for {intel['ip']}: {e}")


HIGH_SEVERITY_PATTERNS = {"FULL_SPECTRUM", "SSH_THEN_LATERAL", "SSH_THEN_PAYLOAD", "PAYLOAD_AND_LATERAL"}
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "")
_last_alerted_id = 0


def send_alert(row):
    ip       = row["source_ip"]
    pattern  = row["pattern"]
    ts       = row["timestamp"][:19] if row["timestamp"] else "?"
    cowrie   = row["hits_cowrie"]
    dionaea  = row["hits_dionaea"]
    canary   = row["hits_opencanary"]
    country  = row["country"]  if row["country"]  else "?"
    isp      = row["isp"]      if row["isp"]      else "?"
    is_proxy = bool(row["is_proxy"]) if row["is_proxy"] else False

    line = (
        f"[ALERT] {ts} | {pattern} | {ip} | {country} / {isp} | "
        f"proxy={is_proxy} | cowrie={cowrie} dionaea={dionaea} canary={canary}"
    )

    try:
        with open(ALERTS_LOG, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[alert] Could not write to alerts.log: {e}")

    print(f"[alert] {line}")

    if ALERT_WEBHOOK_URL:
        try:
            payload = json.dumps({"content": f"**Honeynet Alert**\n```\n{line}\n```"}).encode()
            req = Request(
                ALERT_WEBHOOK_URL,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "HoneynetCorrelator/1.0"},
                method="POST"
            )
            with urlopen(req, timeout=5):
                pass
        except Exception as e:
            print(f"[alert] Webhook error: {e}")


def alert_worker():
    global _last_alerted_id
    ALERT_POLL_INTERVAL = int(os.environ.get("ALERT_POLL_SECS", "30"))

    try:
        conn = get_db_conn()
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT MAX(id) FROM correlations").fetchone()
        if row and row[0]:
            _last_alerted_id = row[0]
        conn.close()
    except Exception:
        pass

    print(f"[alert] Started (poll every {ALERT_POLL_INTERVAL}s, watermark id={_last_alerted_id})")

    while True:
        time.sleep(ALERT_POLL_INTERVAL)
        try:
            conn = get_db_conn()
            conn.row_factory = sqlite3.Row

            placeholders = ",".join("?" * len(HIGH_SEVERITY_PATTERNS))
            rows = conn.execute(f"""
                SELECT c.*, i.country, i.isp, i.is_proxy
                FROM correlations c
                LEFT JOIN ip_intel i ON c.source_ip = i.ip
                WHERE c.id > ? AND c.pattern IN ({placeholders})
                ORDER BY c.id ASC
            """, (_last_alerted_id, *HIGH_SEVERITY_PATTERNS)).fetchall()

            for row in rows:
                send_alert(row)
                _last_alerted_id = max(_last_alerted_id, row["id"])

            conn.close()
        except Exception as e:
            print(f"[alert] Poll error: {e}")


def enrichment_worker():
    while True:
        ip = enrich_queue.get()
        intel = enrich_ip(ip)
        if intel:
            save_intel(intel)
            print(f"[enrich] {ip} -> {intel['country']} | {intel['isp']} | {intel['asn']}")
        else:
            print(f"[enrich] {ip} -> failed (private/reserved?)")
        enrich_queue.task_done()
        time.sleep(1.5)


if __name__ == "__main__":
    print("Starting correlator...")
    init_db()

    threads = [
        threading.Thread(target=tail_cowrie, daemon=True),
        threading.Thread(target=tail_opencanary, daemon=True),
        threading.Thread(target=poll_dionaea, daemon=True),
        threading.Thread(target=analyze_and_aggregate, daemon=True),
        threading.Thread(target=enrichment_worker, daemon=True),
        threading.Thread(target=alert_worker, daemon=True),
    ]

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down")
