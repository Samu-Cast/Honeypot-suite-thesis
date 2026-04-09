# Cowrie

Cowrie è un honeypot a media interazione che emula un server SSH e Telnet. Permette di registrare attacchi brute-force, catturare le credenziali utilizzate e monitorare l'intera sessione dell'attaccante all'interno di una shell emulata. Supporta inoltre la cattura di file scaricati tramite wget/curl e la registrazione completa delle sessioni TTY.

Repository ufficiale: https://github.com/cowrie/cowrie
Documentazione: https://cowrie.readthedocs.io/

## Struttura

```
cowrie/
├── config/
│   ├── cowrie.cfg                # Configurazione principale
│   ├── userdb.txt                # Database credenziali accettate/rifiutate
│   └── docker-compose.yml        # Deploy containerizzato
├── scripts/
│   ├── install.sh                # Installazione manuale su sistema
│   ├── start.sh                  # Avvio del servizio
│   ├── stop.sh                   # Arresto del servizio
│   └── iptables-redirect.sh      # Redirect porte 22/23 verso Cowrie
├── analysis/
│   ├── analyze_logs.py           # Script di analisi dei log
│   └── requirements.txt          # Dipendenze Python
├── docs/
│   ├── installazione.md          # Guida all'installazione
│   ├── configurazione.md         # Guida alla configurazione
│   └── analisi.md                # Guida all'analisi dei dati
└── README.md
```

## Dati raccolti

Cowrie registra diversi tipi di informazioni durante gli attacchi:

- Credenziali (username e password) usate nei tentativi di login
- Comandi eseguiti nella shell emulata
- Sessioni TTY complete, riproducibili con il tool playlog
- File scaricati dagli attaccanti (malware, script)
- Fingerprint e versioni dei client SSH
- Indirizzi IP sorgente

## Quick start

Con Docker Compose:

```bash
cd config/
docker-compose up -d
```

Installazione manuale:

```bash
cd scripts/
chmod +x install.sh
./install.sh
```

## Configurazione

I file di configurazione si trovano nella cartella `config/`. Cowrie utilizza due file principali:

- `cowrie.cfg`: contiene tutte le impostazioni del servizio (hostname emulato, porte di ascolto, backend di logging, ecc.)
- `userdb.txt`: definisce le combinazioni di credenziali che vengono accettate o rifiutate dall'honeypot

Per i dettagli completi, consultare [docs/configurazione.md](docs/configurazione.md).

## Analisi

La cartella `analysis/` contiene script Python per analizzare i log JSON prodotti da Cowrie. Per dettagli, consultare [docs/analisi.md](docs/analisi.md).
