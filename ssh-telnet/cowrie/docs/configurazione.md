# Guida alla configurazione di Cowrie

## File di configurazione

Cowrie utilizza due livelli di configurazione:

- `cowrie.cfg.dist`: configurazione di default, inclusa nel repository ufficiale. Non va modificata perche viene sovrascritta ad ogni aggiornamento.
- `cowrie.cfg`: configurazione personalizzata. I valori qui definiti sovrascrivono quelli nel file `.dist`.

Nel nostro progetto, il file `config/cowrie.cfg` contiene gia le impostazioni personalizzate.

## Parametri principali

### Sezione [honeypot]

| Parametro | Descrizione | Valore nel progetto |
|-----------|-------------|---------------------|
| hostname | Nome host visibile nella shell emulata | svr04 |
| ttylog | Registrazione sessioni TTY | true |
| interactive_timeout | Timeout di inattivita (secondi) | 180 |
| auth_max_tries | Tentativi massimi di login | 6 |

### Sezione [ssh]

| Parametro | Descrizione | Valore nel progetto |
|-----------|-------------|---------------------|
| listen_endpoints | Porta e interfaccia di ascolto | tcp:2222:interface=0.0.0.0 |
| version | Stringa versione SSH emulata | SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2 |

La stringa di versione e volutamente datata per simulare un server non aggiornato e attirare gli attaccanti.

### Sezione [telnet]

| Parametro | Descrizione | Valore nel progetto |
|-----------|-------------|---------------------|
| listen_endpoints | Porta e interfaccia di ascolto | tcp:2223:interface=0.0.0.0 |

## Database utenti (userdb.txt)

Il file `userdb.txt` controlla quali credenziali vengono accettate dall'honeypot. Il formato e:

```
username:uid:password
```

Caratteri speciali nel campo password:
- `*` accetta qualsiasi password per quell'utente
- `!` rifiuta sempre il login, indipendentemente dalla password
- qualsiasi altro valore rappresenta una password specifica

Esempio:

```
root:0:123456        # accetta login con root/123456
root:0:*             # accetta qualsiasi password per root
guest:1002:!         # rifiuta sempre il login per guest
```

## Personalizzazione del filesystem emulato

Cowrie include un filesystem virtuale nella cartella `honeyfs/`. E possibile personalizzarlo per rendere l'honeypot piu credibile:

- Aggiungere file finti in `/etc/`, `/var/`, `/home/`
- Modificare `/etc/issue` e `/etc/motd` per cambiare i banner
- Popolare `/etc/passwd` e `/etc/shadow` con utenti realistici

## Output e logging

Cowrie supporta diversi backend di logging. Nel nostro progetto sono attivi:

- **JSON log** (`cowrie.json`): formato strutturato, ideale per l'analisi automatica con gli script nella cartella `analysis/`
- **Text log** (`cowrie.log`): formato leggibile, utile per il monitoraggio manuale

E possibile configurare backend aggiuntivi come ELK Stack, Splunk o database SQL modificando le sezioni `[output_*]` nel file di configurazione.
