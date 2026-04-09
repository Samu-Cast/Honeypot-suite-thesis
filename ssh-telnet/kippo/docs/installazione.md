# Guida all'installazione di Kippo

## Prerequisiti

- Debian 10/11 o Ubuntu 20.04 LTS (versioni piu recenti hanno rimosso Python 2 dai repository ufficiali)
- Python 2.7
- Accesso sudo
- Connessione a Internet

Kippo richiede Python 2.x e non e compatibile con Python 3. Per questo motivo e fortemente consigliato eseguirlo in un ambiente isolato, ad esempio una macchina virtuale o un container dedicato con una distribuzione piu datata.

## Installazione

### 1. Eseguire lo script di installazione

```bash
cd ssh-telnet/kippo/scripts/
chmod +x install.sh
./install.sh
```

Lo script si occupa di:
- Installare le dipendenze di sistema (Twisted, PyCrypto, ecc.)
- Creare un utente dedicato chiamato `kippo`
- Clonare il repository ufficiale
- Copiare la configurazione personalizzata

### 2. Configurare il redirect della porta

Kippo ascolta sulla porta 2222. Per intercettare il traffico sulla porta standard 22:

```bash
chmod +x iptables-redirect.sh
./iptables-redirect.sh
```

### 3. Avviare il servizio

```bash
chmod +x start.sh
./start.sh
```

## Verifica

```bash
ss -tlnp | grep 2222
```

Test di connessione:

```bash
ssh -p 2222 root@localhost
```

## Problemi noti

**Python 2 non disponibile**: Su Ubuntu 22.04+ e Debian 12+, python2 potrebbe non essere disponibile nei repository. In questo caso e necessario compilarlo da sorgente o usare una distribuzione piu vecchia.

**Dipendenze Twisted**: Alcune versioni di Twisted non sono compatibili con Kippo. La versione consigliata e Twisted 14.x.

**Rilevabilita**: Kippo e facilmente identificabile dagli scanner di rete perche la sua emulazione SSH ha caratteristiche note. Questo lo rende meno efficace per raccogliere dati in deployment moderni, ma e comunque utile a fini didattici e comparativi.
