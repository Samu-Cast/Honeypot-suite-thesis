import os
import json
import sqlite3
import time
from datetime import datetime, timedelta
import threading

# paths inside the container (mapped via docker-compose volumes)
COWRIE_LOG = "/logs/cowrie/cowrie.json"
OPENCANARY_LOG = "/logs/opencanary/opencanary.log"
DIONAEA_DB = "/data/dionaea/dionaea.sqlite"
OUTPUT_DB = "/output/correlations.db"
AGGREGATION_INTERVAL = 2  # how often to check for expired sessions (secs)
SESSION_WINDOW = timedelta(seconds=15)  # sessions older than this get processed

# shared dict to collect events from all the reader threads
events_lock = threading.Lock()
# { ip_address: [ {timestamp, source, event_type, detail}, ... ] }
active_sessions = {}


def init_db():
    os.makedirs(os.path.dirname(OUTPUT_DB), exist_ok=True)
    conn = sqlite3.connect(OUTPUT_DB)
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
            last_seen DATETIME
        )
    ''')
    conn.commit()
    conn.close()


def add_event(source_ip, timestamp, source, event_type, detail):
    if not source_ip:
        return

    with events_lock:
        if source_ip not in active_sessions:
            active_sessions[source_ip] = []

        # try to parse timestamp string into datetime obj
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except Exception:
                timestamp = datetime.now()

        if getattr(timestamp, 'tzinfo', None):
            timestamp = timestamp.replace(tzinfo=None)

        active_sessions[source_ip].append({
            'timestamp': timestamp,
            'source': source,
            'event_type': event_type,
            'detail': detail
        })


def follow_file(filename, source_name):
    """keeps reading new lines appended to a file, like tail -f"""
    while not os.path.exists(filename):
        time.sleep(1)

    with open(filename, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def tail_cowrie():
    """reads cowrie json log line by line and sends events to the correlator"""
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
    """reads opencanary log and sends events to the correlator"""
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
    """polls dionaea sqlite db every 5 secs looking for new connections"""
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
                        ts = datetime.fromtimestamp(ts_epoch)
                        add_event(src_ip, ts, 'dionaea', proto, f"Protocol: {proto}")

                conn.close()
            except sqlite3.OperationalError:
                pass  # db locked or not ready yet
            except Exception as e:
                print(f"Dionaea poll error: {e}")

        time.sleep(5)


def analyze_and_aggregate():
    """every AGGREGATION_INTERVAL secs, checks if any session expired
    and if so processes it"""
    while True:
        time.sleep(AGGREGATION_INTERVAL)
        now = datetime.now()

        with events_lock:
            for ip, events in list(active_sessions.items()):
                if not events:
                    continue

                # Sort events by timestamp to process chronologically
                events.sort(key=lambda x: x['timestamp'])
                
                # Split events into distinct sessions if the gap between them is > SESSION_WINDOW
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
                # strip timezone if present, otherwise comparison with now() breaks
                if latest_event_time.tzinfo:
                    latest_event_time = latest_event_time.replace(tzinfo=None)

                # if no new events came in for longer than SESSION_WINDOW, finalize
                if now - latest_event_time > SESSION_WINDOW:
                    for s in sessions_to_process:
                        process_session(ip, s)
                    del active_sessions[ip]


def process_session(ip, events):
    """classifies the attack pattern based on which honeypots got hit, then saves to db"""
    cowrie_hits = sum(1 for e in events if e['source'] == 'cowrie')
    dionaea_hits = sum(1 for e in events if e['source'] == 'dionaea')
    opencanary_hits = sum(1 for e in events if e['source'] == 'opencanary')

    # figure out what kind of attack this looks like
    pattern = "UNKNOWN"

    if cowrie_hits > 0 and dionaea_hits > 0 and opencanary_hits > 0:
        pattern = "FULL_SPECTRUM"         # hit everything
    elif cowrie_hits > 0 and dionaea_hits > 0:
        pattern = "SSH_THEN_PAYLOAD"      # ssh bruteforce + tried exploits
    elif cowrie_hits > 0 and opencanary_hits > 0:
        pattern = "SSH_THEN_LATERAL"      # ssh + lateral movement attempt
    elif dionaea_hits > 0 and opencanary_hits > 0:
        pattern = "PAYLOAD_AND_LATERAL"
    elif cowrie_hits > 5:
        pattern = "BRUTE_FORCE_SSH"       # lots of ssh login attempts
    elif dionaea_hits > 0:
        pattern = "AUTOMATED_EXPLOIT"
    elif opencanary_hits > 0:
        pattern = "RECON_ONLY"
    elif cowrie_hits > 0:
        pattern = "LOW_SSH_ACTIVITY"

    first_seen = min([e['timestamp'] for e in events])
    last_seen = max([e['timestamp'] for e in events])

    try:
        conn = sqlite3.connect(OUTPUT_DB)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO correlations (timestamp, source_ip, pattern, hits_cowrie, hits_dionaea, hits_opencanary, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now(), ip, pattern, cowrie_hits, dionaea_hits, opencanary_hits, first_seen, last_seen))
        conn.commit()
        conn.close()
        print(f"[+] {ip} -> {pattern} (cowrie:{cowrie_hits} dionaea:{dionaea_hits} canary:{opencanary_hits})")
    except Exception as e:
        print(f"Error saving to db: {e}")


if __name__ == "__main__":
    print("Starting correlator...")
    init_db()

    threads = [
        threading.Thread(target=tail_cowrie, daemon=True),
        threading.Thread(target=tail_opencanary, daemon=True),
        threading.Thread(target=poll_dionaea, daemon=True),
        threading.Thread(target=analyze_and_aggregate, daemon=True)
    ]

    for t in threads:
        t.start()

    # keep main thread alive so daemon threads keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down")
