#!/usr/bin/env python3
"""
Script di analisi dei log JSON prodotti da Cowrie.
Estrae statistiche su credenziali, comandi, IP e distribuzioni temporali.
"""

import json
import argparse
from collections import Counter
from datetime import datetime


def load_events(filepath):
    """Carica gli eventi dal file di log JSON (un evento per riga)."""
    events = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def top_credentials(events, n=20):
    """Restituisce le combinazioni username/password piu utilizzate."""
    creds = Counter()
    for e in events:
        if e.get("eventid") in ("cowrie.login.success", "cowrie.login.failed"):
            username = e.get("username", "")
            password = e.get("password", "")
            if username or password:
                creds[(username, password)] += 1
    return creds.most_common(n)


def top_commands(events, n=20):
    """Restituisce i comandi piu eseguiti nella shell emulata."""
    cmds = Counter()
    for e in events:
        if e.get("eventid") == "cowrie.command.input":
            cmd = e.get("input", "").strip()
            if cmd:
                cmds[cmd] += 1
    return cmds.most_common(n)


def top_ips(events, n=20):
    """Restituisce gli indirizzi IP piu attivi."""
    ips = Counter()
    for e in events:
        ip = e.get("src_ip", "")
        if ip:
            ips[ip] += 1
    return ips.most_common(n)


def attack_timeline(events):
    """Raggruppa gli eventi per ora del giorno."""
    hours = Counter()
    for e in events:
        ts = e.get("timestamp", "")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hours[dt.hour] += 1
        except (ValueError, TypeError):
            continue
    return dict(sorted(hours.items()))


def downloaded_files(events):
    """Elenca i file scaricati dagli attaccanti."""
    files = []
    for e in events:
        if e.get("eventid") == "cowrie.session.file_download":
            files.append({
                "url": e.get("url", ""),
                "shasum": e.get("shasum", ""),
                "timestamp": e.get("timestamp", ""),
                "src_ip": e.get("src_ip", ""),
            })
    return files


def print_section(title, items, formatter):
    """Stampa una sezione formattata del report."""
    print(f"\n{'=' * 60}")
    print(f" {title}")
    print(f"{'=' * 60}")
    if not items:
        print("  Nessun dato disponibile.")
        return
    for item in items:
        print(f"  {formatter(item)}")


def main():
    parser = argparse.ArgumentParser(
        description="Analisi dei log JSON di Cowrie"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Percorso del file cowrie.json"
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=20,
        help="Numero di risultati da mostrare per categoria (default: 20)"
    )
    args = parser.parse_args()

    print(f"Caricamento log da: {args.input}")
    events = load_events(args.input)
    print(f"Eventi caricati: {len(events)}")

    # Statistiche login
    logins_ok = sum(1 for e in events if e.get("eventid") == "cowrie.login.success")
    logins_fail = sum(1 for e in events if e.get("eventid") == "cowrie.login.failed")
    sessions = sum(1 for e in events if e.get("eventid") == "cowrie.session.connect")

    print(f"\n{'=' * 60}")
    print(f" Riepilogo generale")
    print(f"{'=' * 60}")
    print(f"  Sessioni totali:     {sessions}")
    print(f"  Login riusciti:      {logins_ok}")
    print(f"  Login falliti:       {logins_fail}")

    # Top credenziali
    creds = top_credentials(events, args.top)
    print_section(
        f"Top {args.top} credenziali",
        creds,
        lambda x: f"{x[1]:>6}x  {x[0][0]}:{x[0][1]}"
    )

    # Top comandi
    cmds = top_commands(events, args.top)
    print_section(
        f"Top {args.top} comandi",
        cmds,
        lambda x: f"{x[1]:>6}x  {x[0]}"
    )

    # Top IP
    ips = top_ips(events, args.top)
    print_section(
        f"Top {args.top} indirizzi IP",
        ips,
        lambda x: f"{x[1]:>6}x  {x[0]}"
    )

    # Distribuzione oraria
    timeline = attack_timeline(events)
    print_section(
        "Distribuzione oraria degli attacchi",
        sorted(timeline.items()),
        lambda x: f"{x[0]:02d}:00  {'#' * min(x[1] // 10, 50)}  ({x[1]})"
    )

    # File scaricati
    files = downloaded_files(events)
    print_section(
        "File scaricati dagli attaccanti",
        files,
        lambda x: f"{x['timestamp']}  {x['src_ip']}  {x['url']}"
    )


if __name__ == "__main__":
    main()
