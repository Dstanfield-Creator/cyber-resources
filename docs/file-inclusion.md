# File Inclusion (LFI / RFI)

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

File inclusion flaws let an attacker make a web application load a file it should not. Local File Inclusion (LFI) reads files already on the server; Remote File Inclusion (RFI) loads a file from an external location. These map to **CWE-98** (RFI) and **CWE-22** (path traversal), fall under OWASP **A03:2021 Injection** and A01 Broken Access Control, and enable **T1190 Exploit Public-Facing Application**. Impact ranges from sensitive-file disclosure to remote code execution.

## How It Works

The app builds a file path or include target from user input without validation.

- **LFI:** a parameter like `?page=` is concatenated into a filesystem path; traversal sequences (`../`) walk out of the intended directory to read config files, credentials, or logs.
- **Path traversal:** the same root cause applied to download or read endpoints.
- **RFI:** the include target accepts a URL, so the server fetches and may execute attacker-hosted content (most dangerous where remote includes are enabled).
- **Log poisoning / wrapper abuse:** combining LFI with controllable server content to reach code execution.

The root cause is trusting input to name a file, rather than mapping a request to a known, safe resource.

## Detect

Web server and WAF logs carry the traversal and URL signatures; host and app logs confirm the read.

| Source | Signal |
| --- | --- |
| Web / WAF | `../` sequences and encodings (`%2e%2e%2f`, `..%5c`), references to `/etc/passwd`, `web.config`, `wp-config.php` |
| Web / WAF | `php://`, `data://`, `file://` wrappers; an `http(s)://` value in an include parameter (RFI) |
| App logs | File-not-found or permission errors for paths outside the web root |
| Host / FIM | Web process reading sensitive files it never normally touches |
| Netflow | Web server making outbound fetches triggered by a request parameter (RFI) |

```yaml
title: Path Traversal and Remote Include Indicators
logsource:
  category: webserver
detection:
  traversal:
    uri_query|contains:
      - '../'
      - '%2e%2e%2f'
      - 'php://'
      - 'etc/passwd'
  remote:
    uri_query|re: '=(https?|ftp)://'
  condition: traversal or remote
fields:
  - clientip
  - uri_path
  - uri_query
falsepositives:
  - Scanners, legitimate URLs passed as parameters
level: high
```

Alert on reads of sensitive files by the web user and on web-triggered outbound connections (RFI).

## Mitigate

- Do not pass user input into file paths or include statements; map requests to an allow-listed set of known resources (an index or enum).
- Canonicalise and validate paths; reject traversal sequences and absolute paths; confine access with a base directory and `realpath` checks.
- Disable remote includes (for example PHP `allow_url_include=Off`, `allow_url_fopen=Off`) and dangerous wrappers.
- Run the web process least-privileged; restrict filesystem permissions so sensitive files are unreadable to it.
- WAF rules and egress filtering as defence in depth; patch frameworks and plugins.

## Lab

- Deploy a deliberately vulnerable app (DVWA has an LFI/RFI module) on an isolated segment (192.0.2.0/24), not reachable from outside the lab.
- Against your own instance, send traversal and wrapper requests and confirm the WAF/web-log rule fires and FIM shows the file read.
- Apply allow-listing and disable remote includes, then re-test to confirm the inclusion fails. Only ever test assets you own.

## References

- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- OWASP Testing for Local/Remote File Inclusion (WSTG): https://owasp.org/www-project-web-security-testing-guide/
- CWE-98 PHP Remote File Inclusion: https://cwe.mitre.org/data/definitions/98.html
- CWE-22 Improper Limitation of a Pathname to a Restricted Directory: https://cwe.mitre.org/data/definitions/22.html

---

**Author:** Danny Stanfield
**License:** MIT
