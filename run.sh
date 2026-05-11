#!/bin/bash
cd honeynet

echo "Starting Docker containers..."
docker compose up -d

echo "Generating simulated attacks..."
python3 test/simulate_attack.py

echo "Opening dashboard..."
sleep 3
xdg-open http://localhost:8888 || open http://localhost:8888
