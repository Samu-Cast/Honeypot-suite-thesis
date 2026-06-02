# Honeypot Suite

Progetto di tesi triennale — Università degli Studi di L'Aquila.

Un'infrastruttura honeynet completa: tre honeypot containerizzati, un correlatore Python multi-thread che li osserva in tempo reale, e una dashboard web live. L'intero stack parte con un singolo comando.

---

## Architettura

```
                        ┌─────────────────────────────┐
  Internet / LAN        │         Docker network        │
  attacker traffic      │         172.20.0.0/24         │
        │               │                               │
        ├──SSH/Telnet──▶│  Cowrie       172.20.0.10    │
        ├──SMB/FTP/HTTP▶│  Dionaea      172.20.0.11    │
        └──interno──────│  OpenCanary   172.20.0.12    │
                        │                               │
                        │  Correlator   172.20.0.20    │──▶ correlations.db
                        │  Dashboard    172.20.0.21    │──▶ :8888
                        └─────────────────────────────┘
```

### Honeypot

| Sensore | Protocolli | Tipo |
|---|---|---|
| **Cowrie** | SSH (22), Telnet (23) | Media interazione — emula una shell, cattura credenziali e sessioni |
| **Dionaea** | SMB (445), FTP (21), HTTP/S (80/443), MySQL (3306) | Bassa interazione — cattura payload e malware automatizzati |
| **OpenCanary** | Rete interna | Tripwire — scatta alert ad alta fedeltà su movimento laterale |

### Correlatore

Demone Python con 6 thread che:

1. **Legge** i log dei tre honeypot in coda condivisa (producer)
2. **Correla** gli eventi per IP sorgente dentro una finestra temporale (`SESSION_WINDOW_SECS`)
3. **Classifica** ogni sessione in uno dei 9 pattern di attacco (funzione pura `classify_pattern`)
4. **Arricchisce** ogni IP con geolocalizzazione, ISP, ASN e flag proxy/hosting via `ip-api.com`
5. **Persiste** tutto in SQLite con WAL mode, idempotente ai riavvii
6. **Allerta** su pattern ad alta severità via log strutturato e webhook opzionale (Discord/Slack)

### Pattern di attacco riconosciuti

| Pattern | Descrizione |
|---|---|
| `FULL_SPECTRUM` | Tutti e tre i sensori colpiti — attacco coordinato |
| `SSH_THEN_PAYLOAD` | Brute-force SSH seguita da exploit di servizio |
| `SSH_THEN_LATERAL` | Brute-force SSH seguita da movimento laterale |
| `PAYLOAD_AND_LATERAL` | Exploit + movimento laterale, senza SSH |
| `BRUTE_FORCE_SSH` | SSH massivo oltre soglia, no payload |
| `AUTOMATED_EXPLOIT` | Solo Dionaea — scanner/worm automatizzato |
| `RECON_ONLY` | Solo OpenCanary — ricognizione interna |
| `LOW_SSH_ACTIVITY` | SSH sotto soglia — sonda isolata |
| `UNKNOWN` | Pattern non classificato |

---

## Avvio rapido

**Requisiti**: Docker, Docker Compose, Python 3.

```bash
# Prima esecuzione (o reset completo)
./clean.sh && ./run.sh
```

`run.sh` esegue in ordine: fix permessi sui file di log, build delle immagini custom (correlatore e dashboard), avvio dello stack, iniezione degli eventi di test via `simulate_attack.py`.

**Dashboard**: [http://localhost:8888](http://localhost:8888)

### Avvio manuale (senza test)

```bash
cd honeynet
docker compose up -d --build
```

### Configurazione senza rebuild

Le soglie del correlatore si modificano in `docker-compose.yml` nella sezione `environment` del servizio `correlator`, senza toccare il codice:

```yaml
environment:
  - SESSION_WINDOW_SECS=15       # finestra di correlazione in secondi
  - BRUTE_FORCE_THRESHOLD=5      # hit SSH per classificare come brute-force
  - ALERT_POLL_SECS=30           # frequenza polling alert worker
  - ALERT_WEBHOOK_URL=https://…  # webhook Discord/Slack (opzionale)
```

---

## Struttura del repository

```
.
├── honeynet/
│   ├── docker-compose.yml
│   ├── cowrie/
│   │   ├── config/cowrie.cfg
│   │   └── logs/               # runtime, gitignored (.gitkeep tracciato)
│   ├── dionaea/
│   │   ├── logs/               # runtime, gitignored
│   │   ├── data/               # SQLite Dionaea, gitignored
│   │   └── malware/            # payload catturati, gitignored
│   ├── opencanary/
│   │   ├── opencanary.conf
│   │   └── logs/               # runtime, gitignored
│   ├── correlator/
│   │   ├── Dockerfile
│   │   ├── correlator.py       # demone principale, 6 thread
│   │   └── output/             # correlations.db, gitignored
│   ├── dashboard/
│   │   ├── Dockerfile
│   │   ├── app.py              # Flask + /api/stats JSON endpoint
│   │   ├── templates/
│   │   │   ├── index.html      # dashboard principale, live via AJAX
│   │   │   └── ip_detail.html  # pagina dettaglio per singolo IP
│   │   └── static/
│   │       ├── css/style.css
│   │       ├── js/main.js      # grafici Chart.js
│   │       └── js/live.js      # polling AJAX ogni 10s
│   └── test/
│       ├── simulate_attack.py  # generatore eventi fittizi
│       ├── test_correlator.py  # 22 test pytest su classify_pattern
│       ├── cowrie/logs/        # runtime, gitignored
│       ├── opencanary/logs/    # runtime, gitignored
│       └── dionaea/data/       # runtime, gitignored
├── run.sh
├── clean.sh
└── README.md
```

---

## Testing

```bash
# Genera eventi fittizi (richiede lo stack Docker attivo)
cd honeynet
python3 test/simulate_attack.py

# Unit test della logica di classificazione (nessun Docker necessario)
cd honeynet/test
pytest test_correlator.py -v
```

I 22 test coprono tutti i pattern, i casi limite sulla soglia, la gerarchia di priorità, e la configurabilità via parametro.

---

## Proprietà sistemistiche

| Proprietà | Meccanismo |
|---|---|
| **Idempotenza** | `UNIQUE(source_ip, first_seen)` + `INSERT OR IGNORE` — i riavvii non duplicano dati |
| **Durabilità** | Tabella `pending_events` come WAL; cleanup per rowid precisi |
| **Correttezza temporale** | Tutti i timestamp normalizzati a naive UTC in ingresso |
| **Concorrenza SQLite** | `PRAGMA journal_mode=WAL` + `timeout=10` su ogni connessione |
| **Configurabilità** | Soglie via env vars, nessun rebuild necessario |
| **Testabilità** | `classify_pattern()` funzione pura senza effetti collaterali |
| **Osservabilità** | `/api/stats` JSON + polling AJAX 10s con badge Live |
| **Alerting** | `alert_worker` con watermark — no falsi positivi su dati storici |

---

> [!CAUTION]
> Progetto a scopo didattico. Gli honeypot sono progettati per essere attaccati — non deployare su reti di produzione o segmenti non isolati.
