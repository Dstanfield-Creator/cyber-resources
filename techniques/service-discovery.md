# Service Discovery

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Service discovery is the step after a port is found open: identifying which
service, product and version is listening, and what it exposes. Attackers use it
to select exploits; defenders watch for it as a sign that reconnaissance has
moved from "what is reachable" to "what is attackable".

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1046 | Network Service Discovery |
| T1007 | System Service Discovery |
| T1518 | Software Discovery |

## How It Works

Discovery usually combines:

- **Banner grabbing** - reading the greeting a service returns on connect
  (SSH, SMTP, FTP, HTTP Server headers).
- **Version / probe scanning** - sending protocol-specific probes and matching
  responses against a fingerprint database.
- **Service-level enumeration** - listing SMB shares, SNMP OIDs, RPC endpoints,
  or NSE-style scripted checks.
- **Local enumeration** - on a compromised host, querying running services via
  `systemctl`, `sc query`, or service-control APIs (T1007).

The telltale is deliberate, varied interaction with a service beyond a simple
open/closed check.

## Detect

Log sources and signals:

| Source | Signal |
| --- | --- |
| Zeek (ssh.log, http.log, smb) | Connections that negotiate then drop early |
| Service application logs | Malformed probes, unusual User-Agent, version pokes |
| Windows Security 4688 / Sysmon 1 | `sc.exe query`, `tasklist /svc`, net view |
| Auth logs | Repeated connect-without-auth to SSH/SMTP/FTP |

```yaml
title: Local Service Enumeration Commands
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\sc.exe'
            - '\tasklist.exe'
            - '\net.exe'
        CommandLine|contains:
            - 'query'
            - '/svc'
            - 'view'
    condition: selection
falsepositives:
    - Administrators and inventory agents
level: low
```

Network-side, correlate many distinct service fingerprinting attempts from one
source across several hosts within a short window.

## Mitigate

- Suppress or genericise service banners where the software allows it.
- Keep services patched so version disclosure yields nothing exploitable.
- Restrict management services (SMB, SNMP, RPC, WinRM) to admin networks.
- Disable or scope unauthenticated enumeration (e.g. SMB null sessions,
  default SNMP community strings).
- Baseline normal admin tooling so enumeration commands stand out.

## Lab

Isolated lab on 192.0.2.0/24:

1. Stand up a host running SSH, HTTP and SMB.
2. Fingerprint it from an attacker VM and capture Zeek + application logs.
3. Verify each service records the probe; confirm your process-creation rule
   fires for local enumeration run on the target.
4. Harden banners / null-session settings and re-test what the attacker still
   learns.

## References

- MITRE ATT&CK T1046 - https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1518 - https://attack.mitre.org/techniques/T1518/
- Zeek log reference - https://docs.zeek.org/
- NIST SP 800-115 - https://csrc.nist.gov/

---

**Author:** Danny Stanfield
**License:** MIT
