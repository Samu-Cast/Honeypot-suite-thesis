#!/bin/bash
# Script di installazione di Kippo su sistema Debian/Ubuntu
#
# Nota: Kippo richiede Python 2.x e dipendenze non piu mantenute.
# Non e compatibile con Python 3. Usare una macchina virtuale o un
# container dedicato per evitare conflitti con il sistema.

set -e

KIPPO_USER="kippo"
KIPPO_DIR="/opt/kippo"

echo "Installazione dipendenze di sistema..."
sudo apt-get update
sudo apt-get install -y \
    git \
    python2 \
    python-pip \
    python-dev \
    libssl-dev \
    libffi-dev \
    build-essential \
    authbind \
    python-twisted \
    python-crypto \
    python-pyasn1 \
    python-gmpy2

echo "Creazione utente dedicato..."
if ! id "$KIPPO_USER" &>/dev/null; then
    sudo adduser --disabled-password --gecos "" $KIPPO_USER
fi

echo "Clone del repository Kippo..."
sudo mkdir -p $KIPPO_DIR
sudo chown $KIPPO_USER:$KIPPO_USER $KIPPO_DIR
sudo -u $KIPPO_USER git clone https://github.com/desaster/kippo.git $KIPPO_DIR/kippo-git

echo "Copia della configurazione personalizzata..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo -u $KIPPO_USER cp "$SCRIPT_DIR/../config/kippo.cfg" $KIPPO_DIR/kippo-git/kippo.cfg
sudo -u $KIPPO_USER cp "$SCRIPT_DIR/../config/userdb.txt" $KIPPO_DIR/kippo-git/data/userdb.txt

echo "Installazione completata."
echo "Per avviare Kippo: ./start.sh"
echo "Per configurare il redirect delle porte: ./iptables-redirect.sh"
