#!/bin/bash
# Avvio di Cowrie

COWRIE_DIR="/opt/cowrie/cowrie-git"

echo "Avvio di Cowrie..."
sudo -u cowrie $COWRIE_DIR/bin/cowrie start

echo "Cowrie avviato."
echo "Log: $COWRIE_DIR/var/log/cowrie/cowrie.log"
echo "Log JSON: $COWRIE_DIR/var/log/cowrie/cowrie.json"
