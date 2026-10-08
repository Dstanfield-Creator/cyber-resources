# Password Cracking

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Password cracking is the offline recovery of plaintext credentials from captured
hashes. Because it happens on attacker-controlled hardware, it produces no logs
on the victim network. Defence therefore centres on preventing hash theft,
detecting the dumping that precedes cracking, and making hashes expensive to
crack.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1110.002 | Brute Force: Password Cracking |
| T1003 | OS Credential Dumping |
| T1555 | Credentials from Password Stores |

## How It Works

The chain is: obtain hashes, then crack them offline.

- **Acquisition** - dumping the SAM/LSASS, `/etc/shadow`, NTDS.dit, or capturing
  network hashes (T1003). This is the detectable part.
- **Attack modes** - dictionary, rule-mutated wordlists, mask/brute force, and
  hybrid approaches, run on GPUs at high speed.
- **Hash weaknesses** - fast/unsalted algorithms (MD5, unsalted SHA-1, NTLM)
  fall quickly; slow salted KDFs (bcrypt, scrypt, Argon2, PBKDF2) resist.

The cracking itself is silent; the theft and the subsequent credential reuse are
where telemetry exists.

## Detect

Focus detection on acquisition and reuse, not the crack:

| Source | Signal |
| --- | --- |
| Sysmon 10 | Suspicious process accessing lsass.exe |
| Windows Security 4688 | Credential-dumping tool command lines |
| Linux auditd | Reads of /etc/shadow by non-root processes |
| DC logs / 4662 | Abnormal NTDS.dit / DCSync-style access |
| Auth logs | Sudden successful logins after a prior breach window |

```yaml
title: Suspicious LSASS Memory Access
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
    filter:
        SourceImage|endswith:
            - '\MsMpEng.exe'
            - '\wininit.exe'
    condition: selection and not filter
falsepositives:
    - Some EDR and backup agents
level: high
```

## Mitigate

- Store passwords with slow, salted KDFs (Argon2id, bcrypt, scrypt, PBKDF2).
- Enforce length-first password policy and screen against breached-password lists.
- Deploy MFA so a cracked password alone is insufficient.
- Protect credential stores: Credential Guard, LSASS protection, restricted
  shadow/NTDS access.
- Rotate credentials promptly after any suspected hash exposure.

## Lab

Isolated lab (no internet, 192.0.2.0/24):

1. Generate test hashes in several algorithms and compare relative crack time to
   illustrate why KDF choice matters.
2. Trigger a benign LSASS access from a known tool and confirm your Sysmon rule
   fires.
3. Re-hash the same passwords with Argon2id and demonstrate the resistance
   improvement.

## References

- MITRE ATT&CK T1110.002 - https://attack.mitre.org/techniques/T1110/002/
- MITRE ATT&CK T1003 - https://attack.mitre.org/techniques/T1003/
- OWASP Password Storage Cheat Sheet - https://cheatsheetseries.owasp.org/
- NIST SP 800-63B (Authentication) - https://pages.nist.gov/800-63-3/

---

**Author:** Danny Stanfield
**License:** MIT
