#!/bin/bash
# Redirect delle porte standard SSH/Telnet verso Cowrie
# Permette a Cowrie di ascoltare sulle porte 22 e 23 senza girare come root

set -e

echo "Configurazione redirect iptables..."

# Redirect porta 22 (SSH) -> 2222 (Cowrie SSH)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Redirect porta 23 (Telnet) -> 2223 (Cowrie Telnet)
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

echo "Redirect attivo:"
echo "  22 -> 2222 (SSH)"
echo "  23 -> 2223 (Telnet)"
echo ""
echo "Per rendere le regole persistenti, installare iptables-persistent:"
echo "  sudo apt-get install iptables-persistent"
echo "  sudo netfilter-persistent save"
