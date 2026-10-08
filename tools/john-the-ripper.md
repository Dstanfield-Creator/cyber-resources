# John the Ripper

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

John the Ripper (John, or JtR) is an open-source offline password
cracker. The community "jumbo" build adds hundreds of hash and cipher
formats plus a large set of `*2john` helpers that convert files (ZIP,
PDF, SSH keys, KeePass) into crackable hashes. Like Hashcat it works on
hashes already captured, never on the live target. In a lab it is used to
study password and hashing weaknesses. Usage here is lab-scoped against
self-generated material.

## Install

| Method | Source |
| --- | --- |
| Kali package | `sudo apt install john` |
| Source (jumbo) | https://github.com/openwall/john |
| Build | `./configure && make` from `src/` |

## Common Usage

Create your own test hashes in the lab; only crack material you are
authorised to recover.

```bash
# Auto-detect format and run default modes
john hashes.txt

# Wordlist mode with rules
john --wordlist=lab-words.txt --rules hashes.txt

# Convert a lab zip to a hash, then crack it
zip2john secret.zip > zip.hash
john --wordlist=lab-words.txt zip.hash

# Show cracked results
john --show hashes.txt
```

John stores progress in `john.pot`; use `--restore` to resume a session.

## Detect

Like other offline crackers, John produces no network traffic while it
runs. Detection centres on the surrounding activity.

- **Precondition - credential access:** cracking follows hash capture.
  The alerts that matter are LSASS/SAM/`ntds.dit` access and
  `/etc/shadow` reads (Sysmon Event ID 10 and file-access auditing).
- **Host artefacts:** the `john` binary, a growing `john.pot`, large
  wordlists, and use of `*2john` converters on a host (Sysmon Event ID 1
  process create; command lines containing `2john`).
- **Downstream:** a long-dormant account credential that starts
  authenticating successfully.

```yaml
title: John the Ripper Converter Usage
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: '2john'
  condition: selection
level: medium
```

Tuning note: prioritise the credential-dumping precursors; the presence
of John on an analyst workstation alone is low severity.

## References

- Project page: https://www.openwall.com/john/
- Jumbo source: https://github.com/openwall/john
- MITRE ATT&CK: T1110.002 Password Cracking; T1003 OS Credential Dumping

---

**Author:** Danny Stanfield
**License:** MIT
