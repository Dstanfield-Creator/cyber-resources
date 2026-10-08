# Reverse Shells

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

A reverse shell is an interactive command channel in which the compromised host
initiates an outbound connection back to an attacker-controlled listener, giving
the actor command execution. Outbound initiation is chosen specifically to evade
inbound firewall rules, so detection focuses on anomalous egress and process
lineage.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1059 | Command and Scripting Interpreter |
| T1571 | Non-Standard Port |
| T1095 | Non-Application Layer Protocol |

## How It Works

After code execution, a short stub makes an outbound TCP (or UDP/ICMP/DNS)
connection to the attacker and wires a shell's input/output over that socket.
Common hallmarks:

- A shell or interpreter owning an outbound network socket.
- Connections to unusual ports or external IPs with no business purpose.
- Interactive, low-volume, long-lived flows (keystroke-paced traffic).
- Server processes (web/app workers) suddenly making outbound connections.

## Detect

Log sources and signals:

| Source | Signal |
| --- | --- |
| Sysmon 3 (network) | Shell/interpreter with an outbound connection |
| Sysmon 1 / auditd | Suspicious parent-child before the connection |
| Zeek conn.log | Long-lived, low-byte flows to rare external hosts |
| Firewall / proxy | Egress to non-standard ports, unknown destinations |

```yaml
title: Interpreter Making Outbound Network Connection
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
        Initiated: 'true'
    filter:
        DestinationIp|cidr: '192.0.2.0/24'   # known internal management range
    condition: selection and not filter
falsepositives:
    - Admin scripts that legitimately call internal services
level: high
```

On Linux, the equivalent is a `/bin/bash` or `python` process owning an outbound
socket (visible via auditd/Sysmon-for-Linux). Correlate with the preceding
process tree to confirm.

## Mitigate

- Default-deny egress; allow outbound only to known destinations/ports via proxy.
- Application-aware filtering to block raw shells over non-standard ports.
- EDR rules on interpreters creating network connections.
- Network segmentation so a foothold cannot freely reach the internet.
- Harden servers so initial code execution (the precursor) is hard to achieve.

## Lab

Isolated lab (two VMs, host-only 192.0.2.0/24, no internet):

1. Establish a benign callback between two lab hosts you own and capture Sysmon
   network + process events plus Zeek conn.log.
2. Confirm the interpreter-with-socket pattern triggers your Sigma rule.
3. Enforce egress filtering on the target and verify the callback is blocked.

## References

- MITRE ATT&CK T1059 - https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK T1571 - https://attack.mitre.org/techniques/T1571/
- MITRE ATT&CK T1095 - https://attack.mitre.org/techniques/T1095/
- Zeek conn.log reference - https://docs.zeek.org/

---

**Author:** Danny Stanfield
**License:** MIT
