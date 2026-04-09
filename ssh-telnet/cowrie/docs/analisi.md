# Analisi dei dati raccolti da Cowrie

## Formato dei log

Cowrie produce log in formato JSON dove ogni riga rappresenta un evento. I campi principali sono:

| Campo | Descrizione |
|-------|-------------|
| timestamp | Data e ora dell'evento |
| eventid | Tipo di evento (es. cowrie.login.success, cowrie.command.input) |
| src_ip | Indirizzo IP dell'attaccante |
| session | Identificativo della sessione |
| username | Username utilizzato |
| password | Password utilizzata |
| input | Comando eseguito dall'attaccante |
| message | Descrizione testuale dell'evento |

## Tipi di eventi principali

- `cowrie.session.connect`: nuova connessione
- `cowrie.login.success`: login riuscito
- `cowrie.login.failed`: login fallito
- `cowrie.command.input`: comando eseguito nella shell
- `cowrie.session.file_download`: file scaricato dall'attaccante
- `cowrie.session.closed`: chiusura della sessione

## Utilizzo dello script di analisi

```bash
cd analysis/
pip install -r requirements.txt
python analyze_logs.py --input /percorso/cowrie.json
```

Lo script produce:
- Top 20 credenziali (username/password) piu utilizzate
- Top 20 comandi piu eseguiti
- Top 20 indirizzi IP piu attivi
- Distribuzione temporale degli attacchi
- Lista dei file scaricati dagli attaccanti

## Replay delle sessioni TTY

Cowrie registra le sessioni TTY in file binari. Per riprodurle:

```bash
# Con l'installazione manuale
/opt/cowrie/cowrie-git/bin/playlog /opt/cowrie/cowrie-git/var/lib/cowrie/tty/<session-id>

# Con Docker
docker exec cowrie-honeypot /cowrie/cowrie-git/bin/playlog /cowrie/cowrie-git/var/lib/cowrie/tty/<session-id>
```

## Analisi manuale con jq

Per analisi rapide direttamente da terminale, si puo usare `jq`:

```bash
# Contare i login riusciti
cat cowrie.json | jq -r 'select(.eventid == "cowrie.login.success")' | wc -l

# Top 10 password
cat cowrie.json | jq -r 'select(.eventid == "cowrie.login.failed") | .password' | sort | uniq -c | sort -rn | head -10

# Top 10 IP
cat cowrie.json | jq -r '.src_ip' | sort | uniq -c | sort -rn | head -10

# Comandi eseguiti
cat cowrie.json | jq -r 'select(.eventid == "cowrie.command.input") | .input'
```
