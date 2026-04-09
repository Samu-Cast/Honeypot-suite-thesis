#!/bin/bash
# Arresto di Kippo

KIPPO_DIR="/opt/kippo/kippo-git"

echo "Arresto di Kippo..."
sudo -u kippo $KIPPO_DIR/stop.sh

echo "Kippo arrestato."
