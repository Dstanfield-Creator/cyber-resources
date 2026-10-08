# Network Segmentation

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Network segmentation divides a network into zones with controlled paths between them, so a foothold in one area does not grant free movement across the estate. For a SOC it does two things: it limits the blast radius of a compromise by constraining lateral movement, and it creates choke points where east-west traffic can be inspected and detected. Flat networks let an adversary pivot silently; segmented networks force them across boundaries you are watching.

## Key Concepts

| Approach | Boundary | Typical use |
| --- | --- | --- |
| VLAN / subnet | Layer 2/3 zones | Separate user, server, OT, guest, management |
| Firewall zones | Policy between segments | Enforce allowed flows, log crossings |
| Microsegmentation | Per-workload policy | Stop east-west in data centre and cloud |
| Zero trust | Identity-aware per-session | No implicit trust by network location |

- Group assets by sensitivity and function; keep management interfaces on a dedicated, tightly controlled segment.
- Default-deny between zones, then allow only required flows (for example user VLAN to app on 443, app to database on its port).
- Treat the path between segments as a monitored choke point, not just a gate.

## Detect (Telemetry)

Segmentation is only as good as the monitoring at its boundaries. Collect:

- **Firewall/zone logs:** allow and deny between segments, with source, destination, port, and rule.
- **Flow data:** NetFlow/IPFIX for who-talked-to-whom across zones.
- **Zeek `conn.log`:** east-west connection records for protocol and volume context.
- **Identity:** authentication crossing trust boundaries (for example Security 4624 type 3 to servers from a user subnet).

Signals that segmentation is being probed or bypassed:

| Signal | Possible meaning | ATT&CK |
| --- | --- | --- |
| Host in user VLAN talking to many server-VLAN hosts | Lateral movement / scanning | T1021, T1046 |
| Cross-zone SMB/RDP from a workstation that never does | Pivoting | T1021 |
| Traffic from a segment to management VLAN | Policy violation or compromise | T1078 |

```yaml
title: Unexpected Cross-Segment Administrative Access
logsource:
  category: network_connection
detection:
  cross_zone:
    source.network: 'user_vlan_192.0.2.0_24'
    destination.port:
      - 3389   # RDP
      - 445    # SMB
    destination.network: 'server_vlan'
  condition: cross_zone
fields:
  - source.ip
  - destination.ip
  - destination.port
level: high
```

## Harden

- Enforce segmentation at firewalls and switch ACLs, not just by addressing; validate that the policy actually blocks disallowed paths.
- Isolate crown-jewel systems and OT/IoT into their own zones with minimal, inspected ingress and egress.
- Apply microsegmentation east-west in data centre and cloud so workloads cannot reach peers they do not need.
- Re-test segmentation after every change; drift reopens paths you thought were closed.

## Lab

Build three VLANs in an isolated range (user, server, management) on 192.0.2.x with default-deny firewall policy between them. Enable flow logging and Zeek at the boundary, then attempt allowed and disallowed cross-zone connections and confirm both the enforcement (blocked) and the detection (alert) behave as designed. Keep all addressing in 192.0.2.0/24 and any names under example.com.

## References

- MITRE ATT&CK: https://attack.mitre.org/
- NIST SP 800-207 Zero Trust Architecture
- NIST SP 800-125B (segmentation and workload isolation guidance)
- CIS Controls v8 (network infrastructure and segmentation)

---

**Author:** Danny Stanfield
**License:** MIT
