# Distributed Denial of Service (DDoS) Attacks

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

A Distributed Denial of Service attack floods a target from many sources at once, overwhelming bandwidth, infrastructure, or application capacity. MITRE ATT&CK tracks it as **T1498 Network Denial of Service**, with sub-techniques for direct network flood (T1498.001) and reflection amplification (T1498.002). The distribution across many sources is what separates DDoS from single-source DoS and defeats simple source-blocking.

## How It Works

Traffic originates from a botnet, compromised servers, or abusable open services:

- **Volumetric floods:** UDP, ICMP, or raw packet floods that saturate the link (measured in Gbps/Mpps).
- **Reflection and amplification:** spoof the victim's source IP in requests to open services (DNS, NTP, memcached, SSDP, CLDAP) so large responses are reflected to the victim. A small request yields a large reply, multiplying attacker bandwidth.
- **Protocol floods:** SYN, ACK, or fragmentation floods that exhaust state on firewalls, load balancers, and servers.
- **Application-layer (L7):** HTTP(S) request floods that look like real users but target expensive endpoints.

Source IP spoofing is common in L3/L4 floods, so individual addresses are unreliable indicators; shape and volume matter more.

## Detect

Edge and provider telemetry lead, since on-host logs may never arrive once the link is saturated.

| Source | Signal |
| --- | --- |
| Netflow / sFlow | Sudden bits-per-second and packets-per-second spikes, abnormal protocol mix (high UDP) |
| Border / ISP | Inbound saturation, traffic from many ASNs and geographies at once |
| DNS/NTP logs | Large responses to spoofed sources; your resolver used as a reflector |
| Load balancer | Connection-table exhaustion, SYN backlog growth |
| CDN / WAF | L7 request-rate spike to one path, low cache-hit ratio, uniform user-agents |

```yaml
title: Possible Volumetric DDoS - Inbound Traffic Spike
logsource:
  category: netflow
detection:
  baseline:
    direction: inbound
  condition: baseline | bytes_per_sec > 5x rolling_avg(15m) and distinct(src_asn) > 50
fields:
  - dst_ip
  - protocol
  - src_asn
  - bytes_per_sec
falsepositives:
  - Flash crowds, software update waves, legitimate campaigns
level: high
```

Alert on the ratio of distinct source ASNs to a single destination, and on protocol anomalies (e.g. a spike in inbound UDP/123 or /53 responses you did not request).

## Mitigate

- Subscribe to upstream or cloud DDoS scrubbing with always-on or on-demand diversion (BGP or DNS redirect).
- Front public services with a CDN/WAF that absorbs L7 floods and provides anycast capacity.
- Deploy anti-spoofing at the network edge (BCP 38 / uRPF) and disable or restrict open reflectors (DNS recursion, NTP monlist).
- Rate limiting, SYN cookies, and connection caps at the edge; drop malformed and fragmented floods early.
- Over-provision and use anycast so volumetric load is distributed.
- Maintain a runbook: detection thresholds, who to call at the ISP/scrubber, and failover steps.

## Lab

- Keep all generation inside an isolated range (192.0.2.0/24); never direct traffic at third-party or internet hosts.
- Model reflection safely by configuring a lab resolver and observing amplification factors with controlled queries you own.
- Replay captured (sanitised) traffic-shape data into your SIEM to validate the ASN-spread and pps-spike rules.
- Rehearse the runbook: trigger an alert, practise the scrubbing-diversion decision, and measure time to mitigate.

## References

- MITRE ATT&CK T1498 Network Denial of Service: https://attack.mitre.org/techniques/T1498/
- CISA DDoS Guidance for Federal Agencies: https://www.cisa.gov/resources-tools/resources/understanding-and-responding-distributed-denial-service-attacks
- OWASP Denial of Service Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- BCP 38 Network Ingress Filtering (RFC 2827): https://www.rfc-editor.org/info/bcp38

---

**Author:** Danny Stanfield
**License:** MIT
