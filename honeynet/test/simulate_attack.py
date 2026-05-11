#!/usr/bin/env python3
"""
Honeynet Test Event Generator
Generates fake events across Cowrie, OpenCanary, and Dionaea to exercise
every attack pattern recognised by the correlator.

Usage:
    cd honeynet
    python3 test/simulate_attack.py
"""
import json
import os
import sqlite3
import time
import random
from datetime import datetime, timezone, timedelta

# ── paths (relative to honeynet/) ──────────────────────────────────────────
COWRIE_LOG = "cowrie/logs/cowrie.json"
OPENCANARY_LOG = "opencanary/logs/opencanary.log"
DIONAEA_DB_DIR = "dionaea/data"
DIONAEA_DB = os.path.join(DIONAEA_DB_DIR, "dionaea.sqlite")

ATTACKER_IPS = [
    "10.0.0.50",
    "10.0.0.51",
    "192.168.1.100",
    "172.16.0.200",
    "45.33.32.156"
]

# ── realistic data pools ───────────────────────────────────────────────────
USERNAMES = ["root", "admin", "ubuntu", "user"]
PASSWORDS = ["admin", "123456", "password", "root"]


def _ts(base_time, offset_secs=0):
    """UTC ISO timestamp with optional offset."""
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


# ═══════════════════════════════════════════════════════════════════════════
#  ATTACK SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════

def attack_full_spectrum(ip, base_time):
    session = f"test{random.randint(1000, 9999)}"
    # Cowrie
    events = [{
        "eventid": "cowrie.session.connect", "src_ip": ip,
        "src_port": 12345, "dst_ip": "172.20.0.10", "dst_port": 2222,
        "session": session, "protocol": "ssh",
        "timestamp": _ts(base_time, 0)
    }, {
        "eventid": "cowrie.login.failed", "username": "root", "password": "123",
        "src_ip": ip, "session": session, "protocol": "ssh",
        "timestamp": _ts(base_time, 1)
    }]
    _write_cowrie(events)
    # Dionaea
    _write_dionaea([(base_time.timestamp() + 2, ip, "smbd", 445)])
    # Canary
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
            "src_ip": ip, "session": session, "timestamp": _ts(base_time, i+1)
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
    "FULL_SPECTRUM": attack_full_spectrum,
    "SSH_THEN_PAYLOAD": attack_ssh_then_payload,
    "SSH_THEN_LATERAL": attack_ssh_then_lateral,
    "PAYLOAD_AND_LATERAL": attack_payload_lateral,
    "BRUTE_FORCE_SSH": attack_brute_force_ssh,
    "AUTOMATED_EXPLOIT": attack_automated_exploit,
    "RECON_ONLY": attack_recon_only,
    "LOW_SSH_ACTIVITY": attack_low_ssh
}

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  Honeynet Test Event Generator (Fast-Forward Mode)")
    print("=" * 60)
    print()

    total_sessions = 0
    now = datetime.now(timezone.utc)
    
    # We will generate events with timestamps in the past.
    # By making them older than 60 seconds, the correlator processes them INSTANTLY!
    
    total_sessions = 0
    now = datetime.now(timezone.utc)
    
    # We will generate events with timestamps in the past.
    # By making them older than 60 seconds, the correlator processes them INSTANTLY!
    
    for ip in ATTACKER_IPS:
        # Choose at least 75% of the patterns
        min_patterns = int(len(SCENARIOS) * 0.75)
        n_patterns = random.randint(min_patterns, len(SCENARIOS))
        chosen_patterns = random.sample(list(SCENARIOS.keys()), n_patterns)
        
        print(f"── Attacker {ip} is generating {n_patterns} patterns...")
        
        for idx, pattern in enumerate(chosen_patterns):
            # Space out the attacks by 10 minutes each in the past
            # So the correlator sees them as separate, expired sessions instantly.
            minutes_in_past = 300 - (total_sessions * 10)
            base_time = now - timedelta(minutes=minutes_in_past)
            
            fn = SCENARIOS[pattern]
            fn(ip, base_time)
            
            print(f"   ✓ {pattern}")
            total_sessions += 1
        print()

    print("=" * 60)
    print(f"  {total_sessions} attack sessions injected across 5 IPs!")
    print("  Events are timestamped in the past, so the correlator will process them INSTANTLY.")
    print("=" * 60)
