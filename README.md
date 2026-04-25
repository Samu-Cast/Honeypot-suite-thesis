# Honeypot Suite - Tesi Triennale in Informatica

Progetto di tesi triennale incentrato sull'implementazione, il deployment e l'analisi di diverse tipologie di honeypot per lo studio delle minacce informatiche.

## Struttura del progetto

Il repository è organizzato in macro-categorie, ciascuna contenente gli honeypot relativi a quel tipo di servizio o protocollo.

```text
.
├── ssh-telnet/              # Honeypot per protocolli di accesso remoto
│   ├── cowrie/              # SSH & Telnet a media interazione
│   └── kippo/               # SSH a media interazione (riferimento storico)
├── web/                     # Honeypot per servizi web (HTTP/HTTPS)
├── multi-protocol/          # Honeypot multi-protocollo
│   └── dionaea/             # Cattura malware su SMB, FTP, HTTP, MSSQL, ecc.
├── iot/                     # Honeypot per dispositivi IoT
└── README.md
```

## Categorie

| Categoria | Descrizione | Honeypot |
|-----------|-------------|----------|
| [**ssh-telnet**](./ssh-telnet/) | Protocolli di accesso remoto (SSH, Telnet) | Cowrie, Kippo |
| **web** | Servizi web (HTTP/HTTPS) | - |
| [**multi-protocol**](./multi-protocol/) | Cattura su più protocolli | Dionaea |
| **iot** | Dispositivi IoT | - |

La tabella verrà aggiornata man mano che verranno aggiunti nuovi honeypot.

## Requisiti generali

- **OS**: Ubuntu Server 22.04/24.04 LTS o Debian 12+
- **Python**: 3.10+
- **Docker**: 24.0+ (opzionale, per deployment containerizzato)
- **Risorse**: Minimo 2 GB RAM per honeypot
- **Rete**: IP pubblico o segmento di rete dedicato (DMZ)

## Note sulla sicurezza

> [!CAUTION]
> Questo progetto è realizzato a scopo didattico e di ricerca. Gli honeypot sono sistemi pensati per essere esposti ad attacchi: **non vanno mai deployati su reti di produzione o segmenti non isolati**. Seguire sempre le best practice di isolamento di rete descritte nella documentazione di ciascun honeypot.

## Licenza

Progetto accademico - Università degli Studi di L'Aquila
