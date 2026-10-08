# Hydra

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Hydra (THC-Hydra) is an open-source online password-guessing tool. It
tests credentials against live network services (SSH, FTP, HTTP forms,
RDP, and many others) in parallel. "Online" means it talks to the real
service rather than cracking a captured hash offline. In a lab it is used
to demonstrate weak-credential risk and, for this reference, to show what
a brute-force attempt looks like to a defender. Usage stays lab-scoped
and non-weaponised.

## Install

| Method | Source |
| --- | --- |
| Kali package | `sudo apt install hydra` |
| Git | `git clone https://github.com/vanhauser-thc/thc-hydra` |

## Common Usage

Only ever run against a lab account on a host you own, for example
`192.0.2.40`. Use a tiny, self-made wordlist in the lab.

```bash
# SSH, single known lab user, short demo wordlist
hydra -l analyst -P lab-words.txt ssh://192.0.2.40 -t 4

# FTP with a user list and a pass list
hydra -L users.txt -P lab-words.txt ftp://192.0.2.40
```

Keep the thread count (`-t`) low and the wordlist small; the goal in a
lab is to observe telemetry, not to actually crack anything.

## Detect

Online guessing is high-signal because each attempt is a real login.

- **Windows:** bursts of Security Event ID 4625 (failed logon) from one
  source, often followed by a 4624 (success) if a credential is found.
- **Linux:** repeated `Failed password` lines in `/var/log/auth.log` for
  SSH, many per second from one IP.
- **Web forms:** many POSTs to a login endpoint with varying passwords
  and a pattern of 401/200 responses.
- **Network:** many short-lived connections to one service port.

```yaml
title: Brute Force - Failed Logon Burst
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 1m
  condition: selection | count() by IpAddress > 20
level: medium
```

Tuning note: pair the failure-burst rule with a "many failures then a
success" correlation to prioritise likely-compromised accounts, and
exclude known service accounts that fail benignly.

## References

- Project page: https://github.com/vanhauser-thc/thc-hydra
- MITRE ATT&CK: T1110 Brute Force; T1110.001 Password Guessing

---

**Author:** Danny Stanfield
**License:** MIT
