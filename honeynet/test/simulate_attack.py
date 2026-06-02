#!/usr/bin/env python3
"""
Honeynet test event generator.
Injects fake events into Cowrie, OpenCanary, and Dionaea logs to exercise
every attack pattern recognised by the correlator.

Usage:
    cd honeynet
    python3 test/simulate_attack.py
"""
import json
import os
import sqlite3
import random
from datetime import datetime, timezone, timedelta

COWRIE_LOG     = "cowrie/logs/cowrie.json"
OPENCANARY_LOG = "opencanary/logs/opencanary.log"
DIONAEA_DB_DIR = "dionaea/data"
DIONAEA_DB     = os.path.join(DIONAEA_DB_DIR, "dionaea.sqlite")

# Well-known public IPs so ip-api.com enrichment works during testing.
ATTACKER_IPS = [
    "45.33.32.156",    # Nmap scanme (US)
    "185.220.101.34",  # Tor exit node (DE)
    "111.7.100.13",    # China Unicom (CN)
    "91.240.118.172",  # Known scanner (RU)
    "159.89.173.104",  # DigitalOcean (US)
]


def _ts(base_time, offset_secs=0):
    return (base_time + timedelta(seconds=offset_secs)).isoformat()


def _write_cowrie(events):
    os.makedirs(os.path.dirname(COWRIE_LOG), exist_ok=True)
    with open(COWRIE_LOG, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def _write_canary(events):
    os.makedirs(os.path.dirname(OPENCANARY_LOG), exist_ok=True)
    with open(OPENCANARY_LOG, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def _write_dionaea(rows):
    """rows = list of (timestamp_epoch, ip, protocol, local_port)"""
    os.makedirs(DIONAEA_DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DIONAEA_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            connection_timestamp REAL,
            remote_host TEXT,
            connection_protocol TEXT,
            remote_port INTEGER,
            local_host TEXT,
            local_port INTEGER
        )
    """)
    for ts, ip, proto, lport in rows:
        conn.execute("""
            INSERT INTO connections
            (connection_timestamp, remote_host, connection_protocol,
             remote_port, local_host, local_port)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ts, ip, proto, random.randint(30000, 60000), "172.20.0.11", lport))
    conn.commit()
    conn.close()


def attack_full_spectrum(ip, base_time):
    session = f"test{random.randint(1000, 9999)}"
    _write_cowrie([{
        "eventid": "cowrie.session.connect", "src_ip": ip,
        "src_port": 12345, "dst_ip": "172.20.0.10", "dst_port": 2222,
        "session": session, "protocol": "ssh",
        "timestamp": _ts(base_time, 0)
    }, {
        "eventid": "cowrie.login.failed", "username": "root", "password": "123",
        "src_ip": ip, "session": session, "protocol": "ssh",
        "timestamp": _ts(base_time, 1)
    }])
    _write_dionaea([(base_time.timestamp() + 2, ip, "smbd", 445)])
    _write_canary([{
        "dst_host": "172.20.0.12", "dst_port": 8080,
        "local_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "logdata": {"PATH": "/"}, "logtype": 3000, "node_id": "opencanary-1",
        "src_host": ip, "src_port": 12345,
        "utc_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f")
    }])


def attack_ssh_then_payload(ip, base_time):
    session = f"test{random.randint(1000, 9999)}"
    _write_cowrie([{
        "eventid": "cowrie.session.connect", "src_ip": ip,
        "session": session, "timestamp": _ts(base_time, 0)
    }, {
        "eventid": "cowrie.login.failed", "username": "root",
        "src_ip": ip, "session": session, "timestamp": _ts(base_time, 1)
    }])
    _write_dionaea([(base_time.timestamp() + 2, ip, "httpd", 80)])


def attack_ssh_then_lateral(ip, base_time):
    session = f"test{random.randint(1000, 9999)}"
    _write_cowrie([{
        "eventid": "cowrie.session.connect", "src_ip": ip,
        "session": session, "timestamp": _ts(base_time, 0)
    }])
    _write_canary([{
        "dst_host": "172.20.0.12", "dst_port": 445,
        "local_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "logdata": {"AUDITACTION": "smb_file_open"}, "logtype": 5000,
        "node_id": "opencanary-1", "src_host": ip, "src_port": 12345,
        "utc_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f")
    }])


def attack_payload_lateral(ip, base_time):
    _write_dionaea([(base_time.timestamp(), ip, "smbd", 445)])
    _write_canary([{
        "dst_host": "172.20.0.12", "dst_port": 3306,
        "local_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "logdata": {"USERNAME": "root"}, "logtype": 8001,
        "node_id": "opencanary-1", "src_host": ip, "src_port": 12345,
        "utc_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f")
    }])


def attack_brute_force_ssh(ip, base_time):
    session = f"test{random.randint(1000, 9999)}"
    events = [{
        "eventid": "cowrie.session.connect", "src_ip": ip,
        "session": session, "timestamp": _ts(base_time, 0)
    }]
    for i in range(7):
        events.append({
            "eventid": "cowrie.login.failed", "username": "root", "password": "123",
            "src_ip": ip, "session": session, "timestamp": _ts(base_time, i + 1)
        })
    _write_cowrie(events)


def attack_automated_exploit(ip, base_time):
    _write_dionaea([
        (base_time.timestamp(), ip, "smbd", 445),
        (base_time.timestamp() + 1, ip, "httpd", 80)
    ])


def attack_recon_only(ip, base_time):
    _write_canary([{
        "dst_host": "172.20.0.12", "dst_port": 8080,
        "local_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "logdata": {"PATH": "/"}, "logtype": 3000,
        "node_id": "opencanary-1", "src_host": ip, "src_port": 12345,
        "utc_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f")
    }, {
        "dst_host": "172.20.0.12", "dst_port": 21,
        "local_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "logdata": {"USERNAME": "root"}, "logtype": 2000,
        "node_id": "opencanary-1", "src_host": ip, "src_port": 12345,
        "utc_time": base_time.strftime("%Y-%m-%d %H:%M:%S.%f")
    }])


def attack_low_ssh(ip, base_time):
    session = f"test{random.randint(1000, 9999)}"
    _write_cowrie([{
        "eventid": "cowrie.session.connect", "src_ip": ip,
        "session": session, "timestamp": _ts(base_time, 0)
    }, {
        "eventid": "cowrie.login.failed", "username": "root",
        "src_ip": ip, "session": session, "timestamp": _ts(base_time, 1)
    }])


SCENARIOS = {
    "FULL_SPECTRUM":      attack_full_spectrum,
    "SSH_THEN_PAYLOAD":   attack_ssh_then_payload,
    "SSH_THEN_LATERAL":   attack_ssh_then_lateral,
    "PAYLOAD_AND_LATERAL": attack_payload_lateral,
    "BRUTE_FORCE_SSH":    attack_brute_force_ssh,
    "AUTOMATED_EXPLOIT":  attack_automated_exploit,
    "RECON_ONLY":         attack_recon_only,
    "LOW_SSH_ACTIVITY":   attack_low_ssh,
}

if __name__ == "__main__":
    total_sessions = 0
    now = datetime.now(timezone.utc)

    for ip in ATTACKER_IPS:
        min_patterns = int(len(SCENARIOS) * 0.75)
        n_patterns = random.randint(min_patterns, len(SCENARIOS))
        chosen = random.sample(list(SCENARIOS.keys()), n_patterns)

        print(f"[sim] {ip} -> {n_patterns} patterns")

        for pattern in chosen:
            minutes_in_past = 600 - (total_sessions * 5)
            base_time = now - timedelta(minutes=max(minutes_in_past, 2))
            SCENARIOS[pattern](ip, base_time)
            print(f"      {pattern}")
            total_sessions += 1

    print(f"\n[sim] Done — {total_sessions} sessions injected across {len(ATTACKER_IPS)} IPs")
