# Kippo

Kippo e un honeypot SSH a media interazione, sviluppato originariamente da Upi Tamminen (desaster). Registra gli attacchi brute-force e permette all'attaccante di interagire con una shell emulata e un filesystem virtuale, catturando i comandi eseguiti e i file scaricati.

Dal punto di vista storico, Kippo e rilevante in quanto rappresenta uno dei primi honeypot SSH ampiamente adottati dalla comunita di ricerca. Cowrie nasce come fork di Kippo nel 2015, con l'obiettivo di risolverne le limitazioni e aggiungere funzionalita come il supporto a Python 3, il logging in JSON e una migliore emulazione del protocollo SSH.

Repository ufficiale: https://github.com/desaster/kippo

Nota: Kippo non e piu mantenuto attivamente. Per nuovi deployment in produzione e preferibile usare Cowrie. L'inclusione di Kippo in questo progetto ha principalmente valore comparativo e storico.

## Struttura

```
kippo/
├── config/
│   ├── kippo.cfg                 # Configurazione principale
│   └── userdb.txt                # Credenziali accettate/rifiutate
├── scripts/
│   ├── install.sh                # Installazione manuale su sistema
│   ├── start.sh                  # Avvio del servizio
│   ├── stop.sh                   # Arresto del servizio
│   └── iptables-redirect.sh      # Redirect porta 22 verso Kippo
├── analysis/
│   ├── analyze_logs.py           # Script di analisi dei log
│   └── requirements.txt          # Dipendenze Python
├── docs/
│   ├── installazione.md          # Guida all'installazione
│   ├── configurazione.md         # Guida alla configurazione
│   └── analisi.md                # Guida all'analisi dei dati
└── README.md
```

## Differenze principali rispetto a Cowrie

| Caratteristica | Kippo | Cowrie |
|----------------|-------|--------|
| Stato | Abbandonato (~2016) | Mantenuto attivamente |
| Python | 2.x (non compatibile con 3.x) | 3.x |
| Formato log | Testo + MySQL opzionale | JSON, testo, e altri backend |
| Telnet | No | Si |
| Rilevabilita | Alta (facilmente fingerprinted) | Inferiore |

## Dati raccolti

- Credenziali usate nei tentativi brute-force
- Comandi eseguiti nella shell emulata
- File scaricati tramite wget/curl
- Sessioni TTY registrate in formato binario
- Indirizzi IP degli attaccanti

## Quick start

```bash
cd scripts/
chmod +x install.sh
./install.sh
```
