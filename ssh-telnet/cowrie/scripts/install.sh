#!/bin/bash
# Script di installazione di Cowrie su sistema Debian/Ubuntu
# Eseguire come utente non-root con privilegi sudo

set -e

COWRIE_USER="cowrie"
COWRIE_DIR="/opt/cowrie"

echo "Installazione dipendenze di sistema..."
sudo apt-get update
sudo apt-get install -y \
    git \
    python3 \
    python3-venv \
    python3-dev \
    libssl-dev \
    libffi-dev \
    build-essential \
    authbind

echo "Creazione utente dedicato..."
if ! id "$COWRIE_USER" &>/dev/null; then
    sudo adduser --disabled-password --gecos "" $COWRIE_USER
fi

echo "Clone del repository Cowrie..."
sudo mkdir -p $COWRIE_DIR
sudo chown $COWRIE_USER:$COWRIE_USER $COWRIE_DIR
sudo -u $COWRIE_USER git clone https://github.com/cowrie/cowrie.git $COWRIE_DIR/cowrie-git

echo "Configurazione virtual environment Python..."
cd $COWRIE_DIR/cowrie-git
sudo -u $COWRIE_USER python3 -m venv cowrie-env
sudo -u $COWRIE_USER $COWRIE_DIR/cowrie-git/cowrie-env/bin/pip install --upgrade pip
sudo -u $COWRIE_USER $COWRIE_DIR/cowrie-git/cowrie-env/bin/pip install -r requirements.txt

echo "Copia della configurazione personalizzata..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo -u $COWRIE_USER cp "$SCRIPT_DIR/../config/cowrie.cfg" $COWRIE_DIR/cowrie-git/etc/cowrie.cfg
sudo -u $COWRIE_USER cp "$SCRIPT_DIR/../config/userdb.txt" $COWRIE_DIR/cowrie-git/etc/userdb.txt

echo "Installazione completata."
echo "Per avviare Cowrie: ./start.sh"
echo "Per configurare il redirect delle porte: ./iptables-redirect.sh"
