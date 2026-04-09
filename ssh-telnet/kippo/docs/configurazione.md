# Guida alla configurazione di Kippo

## File di configurazione

Kippo utilizza un unico file di configurazione: `kippo.cfg`, che deve trovarsi nella root di installazione. Il repository include un file `kippo.cfg.dist` con i valori di default; il file personalizzato lo sovrascrive.

## Parametri principali

### Sezione [honeypot]

| Parametro | Descrizione | Valore nel progetto |
|-----------|-------------|---------------------|
| ssh_port | Porta di ascolto SSH | 2222 |
| hostname | Nome host emulato | svr01 |
| log_path | Directory dei log | log |
| download_path | Directory dei file scaricati | dl |
| interactive_timeout | Timeout inattivita (secondi) | 180 |
| auth_attempts | Tentativi massimi per sessione | 3 |

## Database utenti

Il file `userdb.txt` ha lo stesso formato di Cowrie:

```
username:uid:password
```

Caratteri speciali:
- `*` accetta qualsiasi password
- `!` rifiuta sempre il login

## Logging su database MySQL

Kippo supporta il logging su MySQL oltre ai file di testo. Per abilitarlo, decommentare e compilare la sezione `[database_mysql]` nel file `kippo.cfg`:

```ini
[database_mysql]
host = localhost
database = kippo
username = kippo
password = password_sicura
port = 3306
```

Creare il database e lo schema:

```bash
mysql -u root -p < /opt/kippo/kippo-git/doc/sql/mysql.sql
```

## Filesystem virtuale

Il filesystem emulato si trova nella directory `kippo/data/fs.pickle`. Si tratta di un file binario serializzato che rappresenta la struttura delle directory virtuali. Non e modificabile direttamente: per personalizzarlo bisogna usare la utility inclusa `createfs.py`.
