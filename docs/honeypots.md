# Honeypots and Deception

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

A honeypot is a decoy system or artefact with no legitimate business use, deployed so that any interaction with it is inherently suspicious. Deception flips the economics of detection: instead of sifting huge volumes of normal traffic for a weak signal, the defender plants something that only an adversary (or a serious misconfiguration) would touch, producing very high-fidelity, low-volume alerts. It is a complement to, not a replacement for, mainstream detection.

## Types

| Type | Interaction | Use | Risk |
| --- | --- | --- | --- |
| Honeytoken | None (bait data) | Fake creds, API keys, canary files, decoy records | Very low |
| Low-interaction | Emulated service | Breadth, scan and credential-spray detection | Low |
| High-interaction | Real OS/app | Study TTPs in depth | Higher; must be contained |

- **Honeytokens** are the cheapest win: a fake AWS key, a decoy document, a database row, or a DNS/web canary that beacons when opened.
- **Low-interaction** honeypots (for example Cowrie SSH/Telnet, OpenCanary) emulate services and log attempts without exposing a real system.
- **High-interaction** honeypots run real software and yield rich intelligence but need strong isolation so they cannot be used as a pivot.

## Placement

- Internal decoys catch lateral movement and insider misuse; a honeypot on 192.0.2.0/24 that no user should ever reach is a clean tripwire.
- Seed honeytokens where an adversary looks: credential stores, config files, shares, and directory objects.
- Keep high-interaction systems in a tightly controlled segment with egress filtering and heavy monitoring.

## Detect

The detection logic is simple by design: any connection or credential use is the alert. The engineering effort goes into collecting the interaction and routing it to the SOC with context.

```yaml
title: Interaction With Decoy Host or Honeytoken
logsource:
  category: network_connection
detection:
  decoy_touch:
    destination.ip: '192.0.2.50'   # decoy with no business purpose
  token_use:
    user.name: 'svc-decoy-backup'  # honeytoken account, never used legitimately
  condition: decoy_touch or token_use
fields:
  - source.ip
  - user.name
  - destination.port
level: high
```

Telemetry sources: honeypot application logs (Cowrie session logs, OpenCanary events), firewall allow/deny to the decoy, Zeek `conn.log`, and directory or cloud audit logs for honeytoken account use. Because false positives are near zero, these alerts can be high severity and page directly.

## Harden and Operate Safely

- Isolate decoys; prevent them from initiating connections to production (strict egress rules).
- Make decoys believable but clearly fenced, and never store real data or real credentials on them.
- Monitor the honeypot itself for compromise and resource abuse; treat a high-interaction host as hostile.

## Lab

Deploy a low-interaction honeypot (T-Pot, Cowrie, or OpenCanary) in an isolated segment, plant a honeytoken file and a decoy account, then interact with them from a separate lab host on 192.0.2.x and confirm the alert reaches your SIEM. Verify the decoy cannot reach anything real. Keep everything inside the lab and use example.com for any synthetic identities.

## References

- MITRE Engage (adversary engagement and deception): https://engage.mitre.org/
- MITRE ATT&CK: https://attack.mitre.org/
- Cowrie: https://github.com/cowrie/cowrie
- OpenCanary / Canarytokens: https://github.com/thinkst/opencanary

---

**Author:** Danny Stanfield
**License:** MIT
