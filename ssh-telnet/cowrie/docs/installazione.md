# Guida all'installazione di Cowrie

## Prerequisiti

- Debian 12+ o Ubuntu 22.04/24.04 LTS
- Python 3.10 o superiore
- Accesso sudo
- Connessione a Internet

## Installazione con Docker (consigliata)

Docker e il metodo piu semplice per deployare Cowrie in un ambiente isolato.

### 1. Installare Docker e Docker Compose

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

Effettuare il logout e il login per rendere effettiva l'aggiunta al gruppo docker.

### 2. Avviare Cowrie

```bash
cd ssh-telnet/cowrie/config/
docker compose up -d
```

### 3. Verificare il funzionamento

```bash
docker ps
docker logs cowrie-honeypot
```

Provare la connessione:

```bash
ssh -p 2222 root@localhost
```

## Installazione manuale

### 1. Eseguire lo script di installazione

```bash
cd ssh-telnet/cowrie/scripts/
chmod +x install.sh
./install.sh
```

Lo script esegue automaticamente:
- Installazione delle dipendenze di sistema
- Creazione dell'utente dedicato `cowrie`
- Clone del repository
- Setup del virtual environment Python
- Copia dei file di configurazione personalizzati

### 2. Configurare il redirect delle porte

Cowrie ascolta sulle porte 2222 (SSH) e 2223 (Telnet). Per intercettare il traffico sulle porte standard 22 e 23:

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

Dopo l'avvio, verificare che Cowrie sia in ascolto:

```bash
ss -tlnp | grep -E "2222|2223"
```

Testare la connessione SSH:

```bash
ssh -p 2222 root@localhost
```

Inserire una delle password configurate in `userdb.txt` (ad esempio `root`/`123456`). Se si accede alla shell emulata, l'honeypot funziona.

## Risoluzione problemi

**Cowrie non si avvia**: controllare i log in `/opt/cowrie/cowrie-git/var/log/cowrie/cowrie.log`

**Porta gia in uso**: verificare che non ci sia un altro servizio SSH in ascolto sulla stessa porta. Se si usa la porta 22 per l'amministrazione, il redirect con iptables gestisce la separazione automaticamente.

**Permessi negati**: assicurarsi di eseguire Cowrie con l'utente `cowrie`, non come root.
