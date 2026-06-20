#!/bin/bash
set -e
cd honeynet

# Create directories and log files before starting Docker so they are owned
# by the current user. Cowrie and OpenCanary will append to these files;
# simulate_attack.py also writes to them directly from the host.
mkdir -p cowrie/logs opencanary/logs dionaea/data correlator/output
touch cowrie/logs/cowrie.json
touch opencanary/logs/opencanary.log
chmod 666 cowrie/logs/cowrie.json opencanary/logs/opencanary.log
chmod 777 dionaea/data

echo "Starting Docker containers..."
docker compose up -d --build

echo "Generating simulated attacks..."
python3 test/simulate_attack.py

echo "Opening dashboard..."
sleep 3
open http://localhost:8888 2>/dev/null || xdg-open http://localhost:8888 2>/dev/null
