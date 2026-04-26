# Multi-Protocol Honeypot

Questa sezione raccoglie gli honeypot in grado di emulare simultaneamente più protocolli di rete. A differenza degli honeypot mono-servizio (es. Cowrie per SSH), questi sistemi espongono una superficie d'attacco più ampia, permettendo di catturare exploit, worm e malware che colpiscono servizi eterogenei come SMB, FTP, HTTP, MSSQL e altri.

## Honeypot inclusi

| Nome | Protocolli emulati | Interazione | Stato |
|------|--------------------|-------------|-------|
| [Dionaea](./dionaea/) | SMB, FTP, HTTP, MSSQL, SIP, ecc. | Bassa | In configurazione |

## Obiettivi

- Catturare campioni di malware (es. worm, ransomware) che sfruttano vulnerabilità note
- Registrare tentativi di exploit su protocolli Windows (SMB/MS17-010, ecc.)
- Raccogliere payload e shellcode per analisi statica e dinamica
- Correlare gli attacchi con feed di threat intelligence
