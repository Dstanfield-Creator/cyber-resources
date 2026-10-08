# sqlmap

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

sqlmap is an open-source tool that automates the detection and
exploitation of SQL injection flaws. It fingerprints the backend
database, enumerates schemas, and can extract data when a parameter is
injectable. In a lab it is used against deliberately vulnerable apps to
learn how injection manifests and, more usefully here, what the attempts
look like in logs. Usage below stays lab-scoped and non-weaponised.

## Install

| Method | Source |
| --- | --- |
| Kali package | `sudo apt install sqlmap` |
| Git | `git clone https://github.com/sqlmapproject/sqlmap` |
| Run | `python sqlmap.py` (Python 3.7+) |

## Common Usage

Target only a lab app you own, for example a test instance at
`http://192.0.2.20` or `app.example.com`.

```bash
# Test a single GET parameter at low level/risk
sqlmap -u "http://192.0.2.20/item?id=1" --batch --level=1 --risk=1

# Identify the backend DBMS and current user only
sqlmap -u "http://192.0.2.20/item?id=1" --banner --current-user

# Enumerate database names (no data extraction)
sqlmap -u "http://192.0.2.20/item?id=1" --dbs
```

Keep `--level`/`--risk` low in a lab; high values send aggressive,
easily logged payloads. Do not run data-exfiltration flags against
anything you do not own.

## Detect

sqlmap is noisy and well-known on the defensive side.

- **User-Agent:** the default UA contains `sqlmap/<version>
  (https://sqlmap.org)`. Operators randomise it, so treat its absence as
  neutral but its presence as near-certain.
- **Payload patterns:** repeated requests to one parameter with boolean,
  UNION, time-based (`SLEEP`/`WAITFOR DELAY`), and error-based probes;
  bursts of near-identical requests that differ only in the injected
  value; spikes of HTTP 500 responses.
- **WAF/web logs:** encoded quotes, `AND 1=1`, `ORDER BY`, and comment
  sequences in parameters; time-based tests show measurable latency.

```yaml
title: sqlmap Default User-Agent
logsource:
  category: webserver
detection:
  selection:
    c-useragent|contains: 'sqlmap'
  condition: selection
level: high
```

Tuning note: time-based blind injection is best caught by correlating
response latency with repeated single-parameter requests, since the
payloads themselves may be encoded.

## References

- Official site: https://sqlmap.org/
- Usage wiki: https://github.com/sqlmapproject/sqlmap/wiki
- MITRE ATT&CK: T1190 Exploit Public-Facing Application

---

**Author:** Danny Stanfield
**License:** MIT
