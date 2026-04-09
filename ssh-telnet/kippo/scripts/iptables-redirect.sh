#!/bin/bash
# Redirect della porta SSH standard verso Kippo

set -e

echo "Configurazione redirect iptables..."

# Redirect porta 22 (SSH) -> 2222 (Kippo)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

echo "Redirect attivo:"
echo "  22 -> 2222 (SSH)"
echo ""
echo "Per rendere le regole persistenti:"
echo "  sudo apt-get install iptables-persistent"
echo "  sudo netfilter-persistent save"
