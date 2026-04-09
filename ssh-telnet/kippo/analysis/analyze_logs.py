#!/usr/bin/env python3
"""
Script di analisi dei log testuali prodotti da Kippo.
Kippo non produce log in formato JSON, quindi il parsing avviene
sul formato testo semi-strutturato del file kippo.log.
"""

import re
import argparse
from collections import Counter


# Pattern per i diversi tipi di evento nel log di Kippo
PATTERN_LOGIN = re.compile(
    r"login attempt \[(?P<username>[^/]+)/(?P<password>[^\]]+)\] (?P<result>succeeded|failed)"
)
PATTERN_CMD = re.compile(r"CMD: (?P<cmd>.+)$")
PATTERN_IP = re.compile(r",[\d]+,(?P<ip>[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\]")
PATTERN_DOWNLOAD = re.compile(r"download url\((?P<url>[^)]+)\)")


def load_lines(filepath):
    """Carica le righe del file di log."""
    with open(filepath, "r", errors="replace") as f:
        return f.readlines()


def top_credentials(lines, n=20):
    """Restituisce le combinazioni username/password piu utilizzate."""
    creds = Counter()
    for line in lines:
        m = PATTERN_LOGIN.search(line)
        if m:
            creds[(m.group("username"), m.group("password"))] += 1
    return creds.most_common(n)


def top_commands(lines, n=20):
    """Restituisce i comandi piu eseguiti."""
    cmds = Counter()
    for line in lines:
        m = PATTERN_CMD.search(line)
        if m:
            cmd = m.group("cmd").strip()
            if cmd:
                cmds[cmd] += 1
    return cmds.most_common(n)


def top_ips(lines, n=20):
    """Restituisce gli IP piu attivi."""
    ips = Counter()
    for line in lines:
        m = PATTERN_IP.search(line)
        if m:
            ips[m.group("ip")] += 1
    return ips.most_common(n)


def downloaded_files(lines):
    """Elenca gli URL dei file scaricati dagli attaccanti."""
    urls = []
    for line in lines:
        m = PATTERN_DOWNLOAD.search(line)
        if m:
            urls.append(m.group("url"))
    return urls


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
        description="Analisi dei log testuali di Kippo"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Percorso del file kippo.log"
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=20,
        help="Numero di risultati per categoria (default: 20)"
    )
    args = parser.parse_args()

    print(f"Caricamento log da: {args.input}")
    lines = load_lines(args.input)
    print(f"Righe caricate: {len(lines)}")

    logins_ok = sum(1 for l in lines if "login attempt" in l and "succeeded" in l)
    logins_fail = sum(1 for l in lines if "login attempt" in l and "failed" in l)

    print(f"\n{'=' * 60}")
    print(f" Riepilogo generale")
    print(f"{'=' * 60}")
    print(f"  Login riusciti:  {logins_ok}")
    print(f"  Login falliti:   {logins_fail}")

    creds = top_credentials(lines, args.top)
    print_section(
        f"Top {args.top} credenziali",
        creds,
        lambda x: f"{x[1]:>6}x  {x[0][0]}:{x[0][1]}"
    )

    cmds = top_commands(lines, args.top)
    print_section(
        f"Top {args.top} comandi",
        cmds,
        lambda x: f"{x[1]:>6}x  {x[0]}"
    )

    ips = top_ips(lines, args.top)
    print_section(
        f"Top {args.top} indirizzi IP",
        ips,
        lambda x: f"{x[1]:>6}x  {x[0]}"
    )

    files = downloaded_files(lines)
    print_section(
        "File scaricati dagli attaccanti",
        files,
        lambda x: x
    )


if __name__ == "__main__":
    main()
