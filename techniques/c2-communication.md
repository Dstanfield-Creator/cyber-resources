# C2 Communication

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Command and control (C2) is the channel an implant uses to receive instructions
and return results to an operator. Modern C2 blends into normal traffic (HTTPS,
DNS, cloud services), so defenders rely on behavioural analysis - beaconing
rhythm, destination reputation and protocol anomalies - rather than payload
inspection alone.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1071 | Application Layer Protocol |
| T1071.004 | DNS |
| T1573 | Encrypted Channel |
| T1008 | Fallback Channels |
| T1571 | Non-Standard Port |

## How It Works

An implant periodically contacts its controller to poll for tasks. Defining
characteristics:

- **Beaconing** - regular check-ins at a fixed interval, often with jitter.
- **Blending** - HTTP(S), DNS or legitimate web services as the carrier.
- **Low-and-slow** - small, repetitive requests to keep volume down.
- **Resilience** - domain rotation, fallback channels and encrypted payloads.

The regularity and repetition of connections, more than their content, is what
distinguishes C2 from human-driven traffic.

## Detect

Log sources and signals:

| Source | Signal |
| --- | --- |
| Zeek conn.log / NetFlow | Periodic same-size flows to one destination |
| Proxy / DNS logs | High-frequency requests to rare/newly-seen domains |
| TLS metadata (JA3/JA3S) | Anomalous or known-bad client fingerprints |
| Threat intel | Matches to known C2 infrastructure |

```yaml
title: Periodic Beaconing To Single Destination
logsource:
    category: proxy
detection:
    selection:
        dst_host: '*'
    timeframe: 1h
    condition: selection | count() by src_ip, dst_host > 50 and low_variance(interval)
falsepositives:
    - Software update checks, telemetry and monitoring agents
level: medium
```

Practical detection measures inter-arrival time variance per source-destination
pair: tight, repetitive intervals with consistent payload size are the beacon
signature. Enrich with domain age and reputation.

## Mitigate

- Force egress through authenticated proxies with TLS inspection where lawful.
- Block/alert on newly-registered and low-reputation domains.
- Restrict outbound DNS to approved resolvers; inspect for tunnelling.
- Deny direct-to-IP and non-standard-port egress by default.
- Feed threat intel into blocklists and continuously hunt for beacon patterns.

## Lab

Isolated lab (host-only 192.0.2.0/24, no internet):

1. Run a benign beaconing simulator between two VMs you own at a fixed interval.
2. Confirm the periodicity is visible in Zeek conn.log and triggers your
   beacon-detection logic.
3. Add jitter and re-test detection resilience; tune the variance threshold.

## References

- MITRE ATT&CK T1071 - https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1573 - https://attack.mitre.org/techniques/T1573/
- MITRE ATT&CK T1008 - https://attack.mitre.org/techniques/T1008/
- Zeek documentation - https://docs.zeek.org/

---

**Author:** Danny Stanfield
**License:** MIT
