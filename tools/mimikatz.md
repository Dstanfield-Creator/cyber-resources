# Mimikatz

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Mimikatz is a well-known open-source Windows post-exploitation tool that
demonstrates weaknesses in how Windows handles credentials. It is best
known for reading secrets from the Local Security Authority Subsystem
Service (LSASS) and for abusing Kerberos tickets. For this reference it
matters mainly as a detection target: it is one of the most-signatured
tools in existence, and understanding its telemetry is core defensive
knowledge. Usage below is deliberately conceptual and lab-scoped, with no
credential-theft command sequences.

## Install

Mimikatz is a Windows executable and PowerShell module published by its
author. In a lab, obtain it only from the official project and run it
exclusively on an isolated Windows VM you own.

| Item | Source |
| --- | --- |
| Source/releases | https://github.com/gentilkiwi/mimikatz |
| Lab host | An isolated, snapshotted Windows VM with no network egress |

## Common Usage

This reference intentionally does not provide credential-dumping commands.
At a conceptual level, in an isolated lab, Mimikatz is used to illustrate
capabilities such as:

- Reading secrets and hashes that Windows keeps in LSASS memory while a
  session is active.
- Abusing Kerberos tickets (pass-the-ticket and forged-ticket concepts)
  to show why tiered administration and credential hygiene matter.
- Demonstrating why modern mitigations exist: Credential Guard, LSA
  protection (RunAsPPL), and disabling WDigest plaintext caching.

Run the tool only to generate telemetry for the detections below, then
revert the VM snapshot. Never run it against systems you do not own.

## Detect

Mimikatz is high-signal and should be caught at several layers.

- **LSASS access (primary):** Sysmon Event ID 10 (ProcessAccess) where
  the target is `lsass.exe` and `GrantedAccess` includes rights such as
  `0x1010`/`0x1410` from an unusual process. This is the classic signal.
- **LSA protection:** with RunAsPPL enabled, access attempts fail and are
  logged, which is itself suspicious.
- **Sensitive handle access:** Security Event ID 4656/4663 against LSASS
  or the SAM; Event ID 4672/4703 privilege anomalies.
- **On-disk/behaviour:** many AV/EDR tools flag the default binary and
  its signature strings (e.g. `sekurlsa`, `gentilkiwi`); defenders also
  watch for its driver (`mimidrv`) loading.

```yaml
title: LSASS Memory Access (Possible Credential Dumping)
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
  filter:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\wininit.exe'
  condition: selection and not filter
level: high
```

Tuning note: baseline the legitimate processes that open LSASS (AV, EDR,
backup agents) and alert on everything else; pair with LSA protection so
real attempts fail and are logged.

## References

- Project page: https://github.com/gentilkiwi/mimikatz
- Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
- MITRE ATT&CK: T1003.001 LSASS Memory; T1550.003 Pass the Ticket

---

**Author:** Danny Stanfield
**License:** MIT
