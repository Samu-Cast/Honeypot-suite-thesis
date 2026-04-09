# SSH/Telnet Honeypot

Questa sezione raccoglie gli honeypot progettati per emulare servizi di accesso remoto, in particolare SSH e Telnet. Sono tra i più utilizzati in ambito di ricerca perché SSH è uno dei protocolli più bersagliati in assoluto, con attacchi brute-force automatizzati che colpiscono qualsiasi IP esposto su Internet.

## Honeypot inclusi

| Nome | Tipo | Interazione | Stato |
|------|------|-------------|-------|
| [Cowrie](./cowrie/) | SSH/Telnet | Media | Configurato |
| [Kippo](./kippo/) | SSH | Media | Configurato (riferimento storico) |

## Obiettivi

- Raccogliere credenziali utilizzate negli attacchi brute-force
- Registrare i comandi eseguiti dagli attaccanti dopo l'accesso
- Catturare eventuali malware scaricati durante le sessioni
- Analizzare i pattern di attacco e le origini geografiche
