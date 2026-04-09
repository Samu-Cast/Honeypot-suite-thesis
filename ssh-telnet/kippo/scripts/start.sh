#!/bin/bash
# Avvio di Kippo

KIPPO_DIR="/opt/kippo/kippo-git"

echo "Avvio di Kippo..."
sudo -u kippo $KIPPO_DIR/start.sh

echo "Kippo avviato."
echo "Log: $KIPPO_DIR/log/kippo.log"
echo "Sessioni TTY: $KIPPO_DIR/log/tty/"
