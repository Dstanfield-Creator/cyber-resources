#!/bin/bash

# Populate cyber-resources repo with real Wiki content
set -e

cd ~/repos/cyber-resources

echo "📝 Populating cyber-resources with real content..."
echo ""

mkdir -p techniques

# Port Scanning
cat > techniques/port-scanning.md << 'EOF'
# Host and Port Scanning

> **Source:** Confluence Page 557801
> **Updated:** 2026-01-30

## Overview

Understanding port scanning is essential for reconnaissance. This guide covers TCP/UDP port scanning techniques, interpreting scan results, and identifying service states.

## Port States

| **State** | **Description** |
| --- | --- |
| `open` | Connection established (TCP, UDP, SCTP) |
| `closed` | Port responds with RST flag |
| `filtered` | Cannot determine if open/closed |
| `unfiltered` | Port accessible, state unknown |
| `open\|filtered` | No response received |
| `closed\|filtered` | Cannot determine state |

## Discovering Open TCP Ports

### Scanning Top 10 TCP Ports

```bash
sudo nmap 10.129.2.28 --top-ports=10
```

## Port States and Responses

- **Open:** SYN-ACK response
- **Closed:** RST response
- **Filtered:** No response or ICMP error

## Common Nmap Options

| **Option** | **Description** |
| --- | --- |
| `-p <port>` | Specify ports |
| `--top-ports=<n>` | Scan top N ports |
| `-sT` | TCP Connect scan |
| `-sS` | TCP SYN scan |
| `-sU` | UDP scan |
| `-sV` | Service version detection |

---

**Author:** Danny Stanfield | **License:** MIT
EOF

echo "✓ port-scanning.md"

# Enumeration
cat > techniques/enumeration.md << 'EOF'
# Enumeration

> **Source:** Confluence Page 491972
> **Updated:** 2026-01-30

## Overview

Enumeration is the critical phase of reconnaissance. Find all possible attack vectors, not just to gain access.

## The Core Principle

> **Enumeration is the key.**

Most people think enumeration means "trying all the tools." In reality, it's about:

1. Knowing how to interact with each service
2. Understanding what's relevant in responses
3. Doing manual enumeration of configurations
4. Investigating beyond automated tools

## Why Enumeration Matters

Investing hours to understand a service will save days of trying random exploits.

## Information You Need

- Open ports and services
- Service versions
- Information provided by services
- Operating system details
- Misconfigurations

## Attack Vector Formula

To gain access, find one of these:

1. A function/resource that lets you interact with the target
2. Information that provides access or pathways

## Manual Enumeration is Critical

Automated tools have limits:
- Timeouts mark unresponsive ports as closed
- Can't bypass all security measures
- Can't interpret meaning

---

**Author:** Danny Stanfield | **License:** MIT
EOF

echo "✓ enumeration.md"

# OSINT
cat > techniques/osint.md << 'EOF'
# Open-Source Intelligence (OSINT)

> **Source:** Confluence Page 492152
> **Updated:** 2026-01-30

## Overview

OSINT finds publicly available information to reveal events, dependencies, connections, and sensitive data.

## Critical Security Gaps

Attackers find:
- Passwords (hardcoded in code)
- Hashes (from breached databases)
- SSH/API Keys (in public repos)
- Tokens (in documentation)
- Credentials (GitHub, StackOverflow)

## Common Sources

- GitHub, GitLab, Bitbucket
- StackOverflow (code with credentials)
- SearchCode (public code search)
- WHOIS, DNS records
- Certificate transparency logs

## SSH Keys Risk

Private SSH keys found in:
- Public GitHub repos
- Backup files
- Docker images
- Config files

**If exposed, revoke immediately.**

## Defense

- Scan repos for secrets
- Use secret scanning tools
- Implement .gitignore properly
- Train developers on security
- Rotate exposed credentials
- Remove commits with secrets
- Use environment variables

---

**Author:** Danny Stanfield | **License:** MIT
EOF

echo "✓ osint.md"

# Password Attacks Online
cat > techniques/password-attacks-online.md << 'EOF'
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
EOF

echo "✓ password-attacks-online.md"

# Social Engineering
cat > techniques/social-engineering.md << 'EOF'
# Social Engineering

> **Source:** Confluence Page 492080
> **Updated:** 2026-01-30

## Overview

Social engineering exploits human psychology rather than technical vulnerabilities.

## Statistics

**17% of people fall victim to social engineering.** ~2 out of 10 employees will compromise their workstation or network.

## Common Attacks

- **Phishing** - Email with urgency/fear/attachments
- **Spear Phishing (Whaling)** - Targeted at specific people
- **Vishing** - Voice/phone-based phishing
- **Smishing** - SMS-based phishing
- **Watering Hole** - Compromised website
- **Baiting** - Enticing offers (USB drops)

## Low-Tech Attacks

- **Dumpster Diving** - Searching trash for info
- **Shoulder Surfing** - Observing over shoulder
- **Tailgating** - Following through secure doors
- **Typosquatting** - Misspelled domains (www.gogle.com)

## Red Flags

- Sense of urgency
- Unexpected requests
- No proof of identity
- Suspicious contact details
- Wrong information

## Defense

**Organizational:**
- Security awareness training
- Phishing simulations
- Email filtering
- Endpoint protection
- Network monitoring

**Individual:**
- Verify identities before sharing
- Check URLs (hover over links)
- Question urgency
- Never share passwords
- Lock workstations
- Report suspicious activity

---

**Author:** Danny Stanfield | **License:** MIT
EOF

echo "✓ social-engineering.md"

echo ""
echo "✅ Content population complete!"
echo "   Created 5 comprehensive technique files"
echo ""
echo "Next: git add techniques/ && git commit && git push"
