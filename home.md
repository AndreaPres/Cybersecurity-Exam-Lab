# Exploit di CVE-2010-4221 di ProFTPD versione 1.3.3c

## Introduzione  

Per trovare questa vulnerabilità mi sono fatto aiutare da Gemini come motore di ricerca.  

L'obiettivo di questa prova è creare un exploit che possa aprire una reverse shell sfruttando una CVE nota descritta dal [NIST](https://nvd.nist.gov/vuln/detail/cve-2010-4221) nel segunete modo:

- Multiple stack-based buffer overflows in the pr_netio_telnet_gets function in netio.c in ProFTPD before 1.3.3c allow remote attackers to execute **arbitrary code** via vectors involving a TELNET IAC escape character to a (1) FTP or (2) FTPS server.

Il CVSS v2 di questa vulnerabilità è 10.0 High, come mostrato in immagine, perchè ha un impatto molto grave e ha un Access Vector da Rete, una Access Complexity Bassa e Niente autenticazione.  

![CVSS](images/CVSSv2.png)

![CVSSDet](images/CVSS_Details.png)  

## Setup

