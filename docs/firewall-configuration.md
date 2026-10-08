# Firewall Configuration

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

A firewall enforces which traffic is allowed between zones. For a SOC, a firewall is both a control and a sensor: a well-built default-deny policy shrinks the attack surface, and its logs are a rich source of detection data. The two ideas that make firewalls effective are default-deny (allow only what is explicitly needed) and egress filtering (control what leaves, not just what enters), because most command-and-control and exfiltration happens outbound.

## Key Principles

- **Default deny** inbound and outbound; add explicit, documented allow rules.
- **Least privilege:** scope rules to specific source, destination, port, and protocol rather than any/any.
- **Stateful inspection:** allow established and related return traffic rather than opening wide ranges.
- **Egress filtering:** permit only required outbound services; block direct outbound DNS, SMB, and arbitrary high ports from user segments.
- **Log everything meaningful,** especially denies and new outbound connections.

## Example Ruleset

Illustrative stateful policy for a server in a DMZ (concept, not production tuned):

```text
# nftables-style intent, default deny
chain input  { policy drop;  ct state established,related accept;
               ip saddr 192.0.2.0/24 tcp dport 443 accept;  # app traffic
               tcp dport 22 ip saddr 192.0.2.10 accept;     # admin jump host only
               log prefix "INPUT-DROP " drop; }
chain output { policy drop;  ct state established,related accept;
               tcp dport { 443 } ip daddr 192.0.2.0/24 accept;
               log prefix "OUTPUT-DROP " drop; }
```

Every allow rule should trace to a documented requirement; rules without an owner are removed during review.

## Detect (Telemetry)

Firewall logs feed detection. Useful fields: timestamp, action (allow/deny), source and destination IP and port, protocol, bytes, and rule name. Signals worth alerting on:

| Signal | Possible meaning | ATT&CK |
| --- | --- | --- |
| Spike in denied outbound to one host | Blocked C2 or beaconing | T1071 |
| Outbound on unusual port from a user VLAN | Tunnelling or exfiltration | T1048 |
| Many denies across sequential ports from one source | Internal port scan | T1046 |
| New allow then large data transfer off-net | Possible exfiltration | T1041 |

```yaml
title: Repeated Denied Outbound to Single External Host
logsource:
  product: firewall
detection:
  denies:
    action: 'deny'
    direction: 'outbound'
  condition: denies | count() by destination.ip > 50
fields:
  - source.ip
  - destination.ip
  - destination.port
level: medium
```

## Harden

- Review rules on a schedule; remove stale and overly broad entries and any-any rules.
- Separate management traffic onto an out-of-band path; restrict admin access to a jump host.
- Protect the firewall config and change process (arm a change-safety control before remote edits so a bad rule cannot lock you out).
- Forward logs off-box to the SIEM so an attacker who reaches the device cannot erase evidence.

## Lab

In an isolated range, build a default-deny host firewall with nftables or pf, add least-privilege allow rules between 192.0.2.x VLANs, enable deny logging, and forward logs to a SIEM. Generate benign blocked traffic and confirm the denied-connection detection fires. Test a change-safety rollback so you can practise recovering from a lockout.

## References

- MITRE ATT&CK: https://attack.mitre.org/
- NIST SP 800-41r1 Guidelines on Firewalls and Firewall Policy
- nftables wiki: https://wiki.nftables.org/
- CIS Benchmarks (network devices): https://www.cisecurity.org/cis-benchmarks

---

**Author:** Danny Stanfield
**License:** MIT
