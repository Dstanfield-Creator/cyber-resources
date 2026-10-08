# Web Application Enumeration

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Web application enumeration is the mapping of an application's attack surface:
directories, files, parameters, virtual hosts, technologies and hidden
endpoints. It almost always precedes exploitation, so detecting it buys lead
time. Defenders observe it primarily through web server and WAF logs.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1595.003 | Active Scanning: Wordlist Scanning |
| T1595.002 | Active Scanning: Vulnerability Scanning |
| T1083 | File and Directory Discovery |

Maps to OWASP WSTG reconnaissance and OWASP Top 10 A05 (Security Misconfiguration).

## How It Works

Typical activities:

- **Content discovery** - brute forcing paths and filenames from a wordlist,
  producing many 404/403 responses.
- **Virtual host discovery** - varying the Host header against one IP.
- **Technology fingerprinting** - reading headers, cookies, error pages and
  framework-specific paths.
- **Parameter / endpoint mining** - probing API routes, backup files
  (`.bak`, `.old`), and exposed admin panels.
- **Crawling / spidering** - automated link traversal at machine speed.

The defining signal is volume and breadth: far more unique URLs per client than
a human would request.

## Detect

Log sources and signals:

| Source | Signal |
| --- | --- |
| Web server access logs | Burst of 404/403, many unique paths, one source |
| WAF / reverse proxy | Known scanner User-Agents, directory-brute signatures |
| CDN logs | High request rate, low cache-hit ratio from one IP |
| App logs | Requests for nonexistent routes, backup-file extensions |

```yaml
title: Web Content Brute Force (Directory Enumeration)
logsource:
    category: webserver
detection:
    selection:
        sc_status:
            - 404
            - 403
    timeframe: 1m
    condition: selection | count(cs_uri_stem) by src_ip > 100
falsepositives:
    - Search engine crawlers
    - Broken internal links and link checkers
level: medium
```

Enrich with User-Agent analysis and request-rate baselining; genuine users
rarely generate hundreds of distinct 404s per minute.

## Mitigate

- Return consistent, generic error pages; avoid verbose stack traces.
- Remove backup/temporary files and directory listing from production.
- Deploy a WAF with rate limiting and bot management.
- Require authentication on admin and management endpoints.
- Strip or genericise technology-revealing headers (Server, X-Powered-By).

## Lab

Isolated lab (app served at http://example.com in a host-only network):

1. Run a content-discovery tool against your lab app and capture access logs.
2. Confirm the 404/403 burst triggers the Sigma rule in your SIEM.
3. Add rate limiting at the proxy and re-measure how far enumeration gets.
4. Plant a deliberate backup file and verify your detection catches the request.

## References

- MITRE ATT&CK T1595.003 - https://attack.mitre.org/techniques/T1595/003/
- OWASP Web Security Testing Guide - https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10 - https://owasp.org/Top10/
- MITRE ATT&CK T1083 - https://attack.mitre.org/techniques/T1083/

---

**Author:** Danny Stanfield
**License:** MIT
