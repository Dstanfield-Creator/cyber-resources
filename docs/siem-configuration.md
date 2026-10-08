# SIEM Configuration

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

A SIEM (Security Information and Event Management) platform centralises logs, normalises them to a common schema, and runs detection logic across the combined data. Its value to a SOC depends less on the engine and more on disciplined onboarding: the right sources, parsed correctly, time-synced, retained long enough, and covered by tested detections. A badly configured SIEM produces confident dashboards over blind spots.

## Pipeline

```text
sources -> collection (agent/forwarder) -> parse/normalise -> enrich -> index/store -> detect -> alert
```

- **Collection:** agents (for example Elastic Agent, Splunk UF) or syslog over TLS. Prefer encrypted transport and buffering so bursts are not dropped.
- **Normalise:** map fields to a common schema such as Elastic Common Schema (ECS) so a query works across vendors (`source.ip`, `user.name`, `process.command_line`).
- **Enrich:** add asset role, owner, geo, and threat-intel context at ingest to speed triage.

## Onboarding Checklist

| Item | Why it matters |
| --- | --- |
| Time sync (NTP, UTC) | Correlation and timelines break with skewed clocks |
| Field normalisation | One detection covers many sources |
| Source health monitoring | Silent log loss creates blind spots |
| Retention tiers | Hunts and IR need weeks to months of history |
| Index/field budget | Control cost without dropping security-relevant fields |

## Telemetry to Prioritise

- **Windows:** Security 4624/4625/4688/4672/4720, Sysmon 1/3/11/13 via a vetted config.
- **Linux:** auditd execve and network, journald, sshd auth.
- **Network and edge:** firewall allow/deny, Zeek, proxy, DNS, VPN, load balancer.
- **Identity and cloud:** SSO, MFA, directory changes, cloud control-plane audit logs.

## Detect

Correlation is where a SIEM earns its place: join events that are benign alone but suspicious together. Example: many failed logons followed by a success from one source (possible password spray or brute force, T1110).

```yaml
title: Successful Logon After Many Failures (same source)
logsource:
  product: windows
  service: security
detection:
  failures:
    EventID: 4625
  success:
    EventID: 4624
  timeframe: 10m
  condition: failures | count() by SourceAddress > 15 and success
fields:
  - SourceAddress
  - TargetUserName
level: high
```

Keep detections in version control, map each to ATT&CK, and attach runbooks so alerts are actionable.

## Validate

- Send a known test event and confirm it parses to the expected fields; broken parsers are a leading cause of missed alerts.
- Use source-health rules that fire when a feed goes quiet for longer than expected.
- Replay sample attack logs to confirm correlation rules fire, and review noisy rules weekly to tune thresholds.

## Lab

Deploy a free-tier SIEM in an isolated range, onboard one Windows and one Linux host, and verify end to end: generate a logon failure burst, confirm ingestion, parsing, and alert. Practise writing and tuning a correlation rule. Use 192.0.2.x addresses and example.com domains for all test data.

## References

- Elastic Common Schema: https://www.elastic.co/guide/en/ecs/current/index.html
- NIST SP 800-92 Guide to Computer Security Log Management
- MITRE ATT&CK: https://attack.mitre.org/
- Sysmon configuration reference (Sysinternals)

---

**Author:** Danny Stanfield
**License:** MIT
