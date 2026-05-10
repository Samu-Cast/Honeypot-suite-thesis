# Honeypot Suite - Tesi Triennale in Informatica

Progetto di tesi triennale incentrato sull'implementazione, il deployment e l'analisi di diverse tipologie di honeypot per lo studio delle minacce informatiche tramite un'architettura centralizzata **Infrastructure as Code** (Docker Compose).

## Struttura del progetto

Il repository è organizzato in una struttura piatta che contiene le configurazioni dei singoli sensori, orchestrati tramite un unico file Docker Compose.

```text
.
├── honeynet/
│   ├── docker-compose.yml       # Orchestratore per avviare l'intera Honeynet
│   ├── cowrie/                  # Configurazione e Log per Cowrie (SSH/Telnet)
│   ├── dionaea/                 # Configurazione, Log e Malware per Dionaea (Multi-protocol)
│   ├── opencanary/              # Configurazione e Log per OpenCanary (Alerting interno)
│   ├── correlator/              # Script Python custom e database SQLite per la correlazione
│   ├── dashboard/               # Web dashboard (Flask) per visualizzare i risultati
│   └── test/                    # Script per generare eventi di test
└── README.md
```

## Honeypots Inclusi

| Nome | Tipo | Descrizione |
|------|------|-------------|
| **Cowrie** | Media Interazione | Emula servizi SSH e Telnet, cattura credenziali brute-force e sessioni interattive. |
| **Dionaea** | Bassa Interazione | Espone vulnerabilità su SMB, FTP, HTTP, ecc. per catturare malware automatizzati. |
| **OpenCanary** | Bassa Interazione | Demone progettato per far scattare alert ad alta fedeltà quando un attaccante sonda la rete locale. |

## Componenti Custom

| Nome | Descrizione |
|------|-------------|
| **Correlator** | Demone Python che legge i log di tutti gli honeypot in tempo reale, correla gli eventi per IP sorgente e classifica i pattern di attacco (es. `BRUTE_FORCE_SSH`, `FULL_SPECTRUM`). I risultati vengono salvati in un database SQLite. |
| **Dashboard** | Interfaccia web (Flask) accessibile su `http://localhost:8888` che mostra le sessioni correlate, statistiche e un grafico dei pattern rilevati. |

## Deployment (Come avviare l'infrastruttura)

L'intero ambiente è containerizzato con Docker. Non è necessario installare i singoli honeypot sul sistema host.

1. **Requisiti**: Assicurati di avere `docker` e `docker-compose` (o `docker compose`) installati.
2. **Avvio**: Naviga nella cartella `honeynet` ed esegui il seguente comando:
   ```bash
   cd honeynet
   docker compose up -d --build
   ```
3. **Dashboard**: Una volta avviato, la dashboard è raggiungibile su `http://localhost:8888`.
4. **Log e Output**: I log dei singoli honeypot verranno generati all'interno delle rispettive cartelle (es. `cowrie/logs`, `opencanary/logs`), mentre il correlatore analizzerà gli eventi in tempo reale e li salverà in `correlator/output/correlations.db`.

## Testing

Per verificare il funzionamento del correlatore senza generare traffico reale, è disponibile uno script di test:

```bash
cd honeynet
python3 test/simulate_attack.py
```

Lo script genera eventi fittizi (connessioni SSH, alert FTP/HTTP, connessioni SMB) da 3 IP diversi. Dopo circa 60 secondi il correlatore li processerà e i risultati saranno visibili nella dashboard.

## Note sulla sicurezza

> [!CAUTION]
> Questo progetto è realizzato a scopo didattico e di ricerca. Gli honeypot sono sistemi pensati per essere esposti ad attacchi: **non vanno mai deployati su reti di produzione o segmenti non isolati**. Assicurarsi di simulare gli attacchi in un ambiente di laboratorio virtualizzato locale o su una macchina cloud isolata.

## Licenza

Progetto accademico - Università degli Studi di L'Aquila
