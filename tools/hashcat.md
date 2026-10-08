# Hashcat

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Hashcat is an open-source, GPU-accelerated password-recovery tool. It
takes captured password hashes and attempts to recover the plaintext
offline using dictionary, rule, mask, and brute-force attacks. "Offline"
means it never touches the target system; all work happens on the
analyst's own hardware against hashes already in hand. In a lab it is
used to demonstrate password strength and hashing-scheme weakness. Usage
here is lab-scoped against self-generated hashes.

## Install

| Method | Source |
| --- | --- |
| Kali package | `sudo apt install hashcat` |
| Binaries | https://hashcat.net/hashcat/ |
| Check | `hashcat -I` to list OpenCL/CUDA devices |

## Common Usage

Generate your own test hashes in the lab; never load hashes you are not
authorised to recover.

```bash
# Identify the likely hash mode
hashcat --identify hashes.txt

# Straight dictionary attack (mode 0) against MD5 (-m 0)
hashcat -m 0 -a 0 hashes.txt lab-words.txt

# Dictionary plus a rule set
hashcat -m 0 -a 0 hashes.txt lab-words.txt -r rules/best64.rule

# Mask attack: six lowercase letters
hashcat -m 0 -a 3 hashes.txt ?l?l?l?l?l?l
```

| Flag | Meaning |
| --- | --- |
| `-m` | Hash mode (0 MD5, 1000 NTLM, 22000 WPA) |
| `-a` | Attack mode (0 dictionary, 3 mask) |
| `--show` | Show already-cracked results |

## Detect

Hashcat runs entirely offline on the attacker's machine, so there is no
network signature while it cracks. The defensive focus is the events
around it.

- **Precondition - hash theft:** cracking implies hashes were captured
  first. Detect the theft: LSASS access (Sysmon Event ID 10), `ntds.dit`
  or SAM access, and shadow-copy abuse are the real alerts.
- **Host artefacts:** presence of the `hashcat` binary, large wordlists,
  and sustained GPU utilisation on a non-rendering host (Sysmon Event ID
  1 process create).
- **Downstream:** a previously failing credential that suddenly succeeds
  can indicate an offline-cracked password now in use.

```yaml
title: Offline Cracking Tool On Host
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\hashcat.exe'
      - '/hashcat'
  condition: selection
level: low
```

Tuning note: the high-value detections are the credential-access steps
that precede cracking, not the cracking tool itself.

## References

- Official site: https://hashcat.net/hashcat/
- Mode and wiki reference: https://hashcat.net/wiki/
- MITRE ATT&CK: T1110.002 Password Cracking; T1003 OS Credential Dumping

---

**Author:** Danny Stanfield
**License:** MIT
