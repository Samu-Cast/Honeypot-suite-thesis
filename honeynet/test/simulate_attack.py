#!/usr/bin/env python3
"""
Quick script to generate fake honeypot events for testing the correlator.
Run this from inside the honeynet/ directory.

Usage:
    cd honeynet
    python3 test/simulate_attack.py
"""
import json
import os
import sqlite3
import time
import random
from datetime import datetime, timezone

# paths relative to honeynet/ directory
COWRIE_LOG = "cowrie/logs/cowrie.json"
OPENCANARY_LOG = "opencanary/logs/opencanary.log"
DIONAEA_DB_DIR = "dionaea/data"
DIONAEA_DB = os.path.join(DIONAEA_DB_DIR, "dionaea.sqlite")

# fake attacker IPs
ATTACKER_IPS = ["10.0.0.50", "10.0.0.51", "192.168.1.100"]


def generate_cowrie_events(ip, n=5):
    """write fake cowrie ssh login attempts"""
    events = []

    # connection event
    session_id = f"test{random.randint(1000, 9999)}"
    events.append({
        "eventid": "cowrie.session.connect",
        "src_ip": ip,
        "src_port": random.randint(30000, 60000),
        "dst_ip": "172.20.0.10",
        "dst_port": 2222,
        "session": session_id,
        "protocol": "ssh",
        "message": f"New connection: {ip}",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    # login attempts (last one succeeds)
    passwords = ["admin", "root", "password", "123456", "test"]
    for i in range(n):
        events.append({
            "eventid": "cowrie.login.failed" if i < n - 1 else "cowrie.login.success",
            "username": "root",
            "password": passwords[i % len(passwords)],
            "src_ip": ip,
            "session": session_id,
            "protocol": "ssh",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    with open(COWRIE_LOG, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    print(f"  [cowrie]    {len(events)} events (SSH brute-force)")


def generate_opencanary_events(ip, n=3):
    """write fake opencanary alert entries"""
    services = [
        (2121, 5000, "FTP Login attempt"),
        (8080, 3000, "HTTP page request"),
        (2222, 4002, "SSH login attempt"),
    ]

    with open(OPENCANARY_LOG, "a") as f:
        for port, logtype, desc in services[:n]:
            ev = {
                "dst_host": "172.20.0.12",
                "dst_port": port,
                "local_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                "logdata": {"msg": desc},
                "logtype": logtype,
                "node_id": "opencanary-1",
                "src_host": ip,
                "src_port": random.randint(30000, 60000),
                "utc_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
            }
            f.write(json.dumps(ev) + "\n")

    print(f"  [canary]    {n} events (service probing)")


def generate_dionaea_events(ip, n=3):
    """create fake entries in dionaea sqlite db"""
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

    protocols = ["smbd", "httpd", "ftpd", "mysqld"]
    ports = [445, 80, 21, 3306]

    for i in range(n):
        conn.execute("""
            INSERT INTO connections
            (connection_timestamp, remote_host, connection_protocol, remote_port, local_host, local_port)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            time.time() + i,
            ip,
            protocols[i % len(protocols)],
            random.randint(30000, 60000),
            "172.20.0.11",
            ports[i % len(ports)]
        ))

    conn.commit()
    conn.close()
    print(f"  [dionaea]   {n} events (exploit connections)")


if __name__ == "__main__":
    print("=== Honeynet Test Event Generator ===\n")
    print(f"Make sure you're running this from the honeynet/ directory!")
    print(f"Cowrie log:   {COWRIE_LOG}")
    print(f"Canary log:   {OPENCANARY_LOG}")
    print(f"Dionaea DB:   {DIONAEA_DB}\n")

    for ip in ATTACKER_IPS:
        print(f"Simulating attack from {ip}:")
        generate_cowrie_events(ip, n=random.randint(3, 8))
        generate_opencanary_events(ip, n=random.randint(1, 3))
        generate_dionaea_events(ip, n=random.randint(2, 5))
        print()

    print("Done! The correlator should pick these up within ~60 seconds.")
    print("Check correlator/output/correlations.db for results.")
