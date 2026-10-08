# Threat Hunting

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Threat hunting is the proactive, hypothesis-driven search for adversary activity that automated detections missed. It assumes a breach may already exist and looks for evidence rather than waiting for an alert. Hunts produce three outputs: findings (something to escalate to incident response), new detections (codify what you found), and coverage insight (data or visibility gaps). A hunt that finds nothing is still valuable if it hardens assumptions or creates a durable detection.

## Methodology

- **Hypothesis-driven:** start from a testable statement, for example "an adversary is using scheduled tasks for persistence (T1053.005) on servers in the 192.0.2.0/24 segment."
- **PEAK / TaHiTI loops:** Prepare (scope, data, hypothesis), Execute (search and analyse), Act (document, hand off, build detection).
- **Pyramid of Pain:** hunt at the TTP layer where possible; behaviour is harder for an adversary to change than an IP or hash.
- **Crown jewels first:** prioritise hunts around high-value assets and identities.

## Telemetry

| Hunt theme | Primary signals | ATT&CK |
| --- | --- | --- |
| Persistence | Sysmon 1, Security 4698 task created, run keys (Sysmon 13) | T1053, T1547 |
| Credential access | Security 4624 type 9, LSASS access (Sysmon 10) | T1003 |
| C2 / beaconing | Zeek conn.log, dns.log, tls.log, proxy logs | T1071 |
| Living-off-the-land | 4688 / Sysmon 1 command lines for certutil, bitsadmin, mshta | T1105, T1218 |
| Lateral movement | 4624 type 3, 4648, Sysmon 3 to SMB/RDP | T1021 |

## Detect

Example hunt for beaconing: adversaries using HTTP(S) C2 often produce regular connections with low jitter to a single destination. Aggregate Zeek `conn.log` by source and destination, compute the interval between connections, and surface pairs with low variance and consistent byte counts.

```sql
-- conceptual: group connections and look for regular intervals
SELECT id_orig_h, id_resp_h, COUNT(*) AS n,
       STDDEV(interval_seconds) AS jitter,
       AVG(orig_bytes) AS avg_up
FROM zeek_conn
WHERE ts > now() - interval '24 hours'
GROUP BY id_orig_h, id_resp_h
HAVING n > 50 AND jitter < 5
ORDER BY n DESC;
```

Pair the result with newly registered or rare destination domains from `dns.log`, and with user-agent anomalies from proxy logs, to separate C2 from noisy but benign automation.

## From Hunt to Detection

Anything found twice should become a detection. Convert the hunt query into a scheduled rule, map it to the technique, add tuning filters for the benign cases you identified, and document the false positives so the SOC trusts the alert.

## Lab

Replay public breach datasets (for example Mordor/Security Datasets or EVTX samples) into a SIEM and practise the loop: form a hypothesis, query, triage, and write a detection. Use a Jupyter notebook against the data to prototype statistical hunts like beaconing or rare-process analysis. Keep all activity in an isolated lab; use 192.0.2.x and example.com for any synthetic indicators.

## References

- MITRE ATT&CK: https://attack.mitre.org/
- PEAK Threat Hunting Framework (SURGe)
- Mordor / Security Datasets: https://github.com/OTRF/Security-Datasets
- NIST SP 800-61r2 Computer Security Incident Handling Guide

---

**Author:** Danny Stanfield
**License:** MIT
