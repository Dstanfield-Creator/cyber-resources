# Password Attacks Online

> **Source:** Confluence Page 491954
> **Updated:** 2026-01-30

## Overview

Online password attacks target authentication interfaces directly, attempting to guess login credentials.

## Why These Attacks Work

- Weak passwords (users choose easy-to-remember ones)
- Predictable usernames (firstname.lastname)
- Poor lockout policies
- Accessible interfaces

## Attack Methodology

**Dictionary Attack:** Uses common password lists

**Brute Force Attack:** Attempts all possible passwords (slow online)

## Speed Limitations

Online attacks are slow:
- Network latency
- Service response time
- Rate limiting
- Speed: hundreds to single-digit guesses/second

## Common Targets

- Web applications
- SSH/Telnet
- LDAP services
- Mail (SMTP, POP3, IMAP)
- FTP, VPN, Cloud services

## Tools

- **Hydra** - Popular, many protocols
- **Ncrack** - From Nmap makers
- **Medusa** - Thread-based parallel
- **Patator** - Python-based

## Defense

- Account lockout after N attempts
- Rate limiting / progressive delays
- Strong password requirements
- **MFA** (best defense - makes attacks useless)
- Monitor logs for patterns
- Email authentication (SPF, DKIM, DMARC)

---

**Author:** Danny Stanfield | **License:** MIT
