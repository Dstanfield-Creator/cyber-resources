# Denial of Service (DoS) Attacks

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

A Denial of Service attack makes a service unavailable to legitimate users by exhausting a finite resource. MITRE ATT&CK tracks the endpoint variant as **T1499 Endpoint Denial of Service**, with sub-techniques for OS exhaustion flood (T1499.001), service exhaustion flood (T1499.002), application exhaustion flood (T1499.003), and application or system exploitation (T1499.004). This page covers single-source and resource-exhaustion DoS; distributed floods are covered in ddos-attacks.md.

## How It Works

DoS targets whichever resource runs out first: CPU, memory, file descriptors, worker threads, connection-table slots, or application back-end capacity.

- **Volumetric / flood:** more requests or packets than the host can service.
- **Protocol / state exhaustion:** half-open TCP (SYN flood), slow-read or slow-header attacks (Slowloris-style) that tie up connection slots with minimal bandwidth.
- **Application-layer:** expensive endpoints (search, report generation, auth, regex) hit repeatedly so a small request count causes large back-end work.
- **Algorithmic:** inputs crafted to trigger worst-case behaviour, such as hash-collision or catastrophic regex backtracking (ReDoS).

The attacker's goal is availability impact, sometimes as cover (distraction) for a parallel intrusion.

## Detect

Correlate performance telemetry with traffic shape. A flood shows as volume; an application DoS shows as latency and error-rate spikes without matching traffic volume.

| Source | Signal |
| --- | --- |
| Web / LB logs | Surge in requests to one path, rising 5xx, growing response time, concurrent-connection ceiling |
| Netflow / firewall | SYN-to-ACK ratio skew, many half-open connections, single source or small source set |
| Host metrics | CPU/memory saturation, exhausted worker pool, file-descriptor limits, swap pressure |
| Linux | `dmesg` SYN-cookie messages, conntrack table full, auditd on service restarts |
| APM / traces | One endpoint dominating latency and back-end time |

```yaml
title: Possible Application-Layer DoS - Error and Latency Spike
logsource:
  category: webserver
detection:
  selection:
    status: 503
  timeframe: 5m
  condition: selection | count() by clientip > 500
fields:
  - clientip
  - uri_path
  - response_time
falsepositives:
  - Legitimate traffic spikes, load tests, marketing events
level: medium
```

Baseline normal request rate and tail latency per endpoint so anomalies stand out.

## Mitigate

- Rate limiting and connection limits per client at the edge or reverse proxy.
- Timeouts for slow clients, request-header and body size caps to defeat slow-read attacks.
- Autoscaling and load shedding with graceful degradation and queue limits.
- Caching and CDN offload for static and cacheable responses.
- Input validation and safe regex (bounded backtracking) to prevent algorithmic DoS.
- SYN cookies and tuned connection-tracking limits at the OS and firewall.
- Upstream provider or ISP scrubbing for volumetric events.

## Lab

- On an isolated segment (192.0.2.0/24), deploy a small web app behind a reverse proxy and ship logs and metrics to your SIEM.
- Use a load-testing tool you control to drive concurrency and slow-connection scenarios against your own host only.
- Confirm the proxy enforces your rate limits and timeouts, and that your latency/error-rate alert fires.
- Add a deliberately expensive endpoint, then verify a per-endpoint cost control blunts the impact.

## References

- MITRE ATT&CK T1499 Endpoint Denial of Service: https://attack.mitre.org/techniques/T1499/
- OWASP Denial of Service Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
- CISA Understanding Denial-of-Service Attacks: https://www.cisa.gov/news-events/news/understanding-denial-service-attacks
- NIST SP 800-61r2 Computer Security Incident Handling Guide: https://csrc.nist.gov/pubs/sp/800/61/r2/final

---

**Author:** Danny Stanfield
**License:** MIT
