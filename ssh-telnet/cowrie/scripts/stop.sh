#!/bin/bash
# Arresto di Cowrie

COWRIE_DIR="/opt/cowrie/cowrie-git"

echo "Arresto di Cowrie..."
sudo -u cowrie $COWRIE_DIR/bin/cowrie stop

echo "Cowrie arrestato."
