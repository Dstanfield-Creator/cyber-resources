# Nikto

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Nikto is an open-source web server scanner. It checks a target for
thousands of potentially dangerous files, outdated server components, and
common misconfigurations, then reports findings with references. It is
fast and deliberately not stealthy, which makes it a good lab tool both
for baseline web checks and for generating detection samples. Usage here
is lab-scoped against servers you own.

## Install

| Method | Source |
| --- | --- |
| Kali package | `sudo apt install nikto` |
| Git | `git clone https://github.com/sullo/nikto` |
| Run | `perl nikto.pl` or `nikto` |

## Common Usage

Scan only lab hosts, for example `192.0.2.20` or `app.example.com`.

```bash
# Basic scan of a lab web server
nikto -h http://192.0.2.20

# Scan a specific port with TLS
nikto -h https://192.0.2.20:8443

# Save output as HTML for review
nikto -h http://192.0.2.20 -o nikto-lab.html -Format htm
```

| Option | Purpose |
| --- | --- |
| `-h` | Target host or URL |
| `-p` | Port(s) to scan |
| `-ssl` | Force TLS |
| `-Tuning` | Limit test categories |
| `-o` / `-Format` | Output file and format |

## Detect

Nikto is one of the easiest scanners to spot in web logs.

- **User-Agent:** the default UA contains `Nikto/<version>`. It is sent on
  nearly every request unless explicitly changed.
- **Request volume:** thousands of requests in a short window from one
  source, probing paths like `/admin`, `/cgi-bin/`, backup files, and
  known CGIs, producing a flood of 404/403 responses.
- **WAF:** its probe strings match many default WAF signatures, so a scan
  typically triggers a burst of WAF blocks from one IP.

```yaml
title: Nikto Web Scanner Activity
logsource:
  category: webserver
detection:
  selection_ua:
    c-useragent|contains: 'Nikto'
  selection_rate:
    sc-status: 404
  timeframe: 1m
  condition: selection_ua or (selection_rate | count() by c-ip > 200)
level: medium
```

Tuning note: alert on the UA and on high 404 rates separately, so a
UA-spoofed scan is still caught by request volume.

## References

- Project page: https://github.com/sullo/nikto
- Wiki: https://github.com/sullo/nikto/wiki
- MITRE ATT&CK: T1595.002 Active Scanning: Vulnerability Scanning

---

**Author:** Danny Stanfield
**License:** MIT
