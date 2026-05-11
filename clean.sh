#!/bin/bash
cd honeynet

echo "Stopping Docker containers..."
docker compose down

echo "Removing old test logs and databases..."
rm -f cowrie/logs/cowrie.json
rm -f opencanary/logs/opencanary.log
rm -f dionaea/data/dionaea.sqlite
rm -f correlator/output/correlations.db

echo "Clean completed."
