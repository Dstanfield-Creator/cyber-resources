# Privilege Escalation

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Privilege escalation is how an attacker moves from limited access to higher permissions (local admin, root, SYSTEM, or domain admin). It is the ATT&CK tactic **TA0004**, realised through techniques including Exploitation for Privilege Escalation (**T1068**), Abuse Elevation Control Mechanism (**T1548**: UAC bypass .002, sudo/setuid .001 and .003), Access Token Manipulation (**T1134**), Process Injection (**T1055**), and Valid Accounts (**T1078**).

## How It Works

Escalation exploits a gap between the privilege a user has and the privilege some code or configuration grants.

- **Vulnerable software/kernel:** exploiting a flaw in a privileged driver, service, or the kernel.
- **Misconfiguration:** writable service binaries, unquoted service paths, weak file or registry ACLs, overly broad sudo rules, SUID binaries, and world-writable cron jobs.
- **Token / UAC abuse:** stealing or impersonating a higher-privilege token, or bypassing User Account Control.
- **Credential theft:** dumping secrets (LSASS, SAM, keytabs) to reuse a privileged identity.

Many paths rely on configuration errors rather than exploits, which is why hardening and enumeration-of-your-own-weaknesses matter.

## Detect

Watch for privileged tokens appearing where they should not, and for known escalation tooling and sequences.

| Source | Signal |
| --- | --- |
| Windows Security | 4672 (special privileges assigned), 4673/4674 (privileged service/operation), 4688 with elevated token |
| Sysmon | EID 10 access to lsass.exe; EID 8 CreateRemoteThread (injection); EID 1 odd parent-child (service to cmd as SYSTEM) |
| Linux auditd | `execve` of setuid binaries, `sudo` to root by unusual users, changes to `/etc/sudoers`, new SUID files |
| EDR | token manipulation, UAC-bypass patterns, LSASS read by non-system tools |

```yaml
title: LSASS Access by Non-System Process
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
  filter:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\wininit.exe'
  condition: selection and not filter
fields:
  - SourceImage
  - GrantedAccess
falsepositives:
  - EDR and AV agents, legitimate diagnostics
level: high
```

Alert when a standard user process suddenly runs with SYSTEM/root, and on new SUID binaries or sudoers edits outside change control.

## Mitigate

- Patch promptly, especially kernels, drivers, and privileged services (T1068 closes with patching).
- Least privilege: minimal sudo rules, no unnecessary SUID bits, correct service and file ACLs, no unquoted service paths.
- Credential Guard / LSASS protection to resist secret dumping; enforce UAC at the highest practical level.
- Application control and allow-listing to block known escalation tools.
- Regular configuration auditing (e.g. with a benign privilege-audit script) to find writable services and weak permissions before an attacker does.

## Lab

- On an isolated VM (192.0.2.0/24) with logging to your SIEM, deliberately introduce a misconfiguration (a world-writable service binary or an over-broad sudo rule) on a disposable host.
- As a low-privilege test user at example.com, confirm your audit tooling flags the weakness and that 4672 / auditd setuid events capture elevation.
- Enable Credential Guard and tighten ACLs, then re-run to confirm the path closes. Snapshot and revert afterward.

## References

- MITRE ATT&CK TA0004 Privilege Escalation: https://attack.mitre.org/tactics/TA0004/
- MITRE ATT&CK T1068 Exploitation for Privilege Escalation: https://attack.mitre.org/techniques/T1068/
- MITRE ATT&CK T1548 Abuse Elevation Control Mechanism: https://attack.mitre.org/techniques/T1548/
- Microsoft Credential Guard documentation: https://learn.microsoft.com/windows/security/identity-protection/credential-guard/

---

**Author:** Danny Stanfield
**License:** MIT
