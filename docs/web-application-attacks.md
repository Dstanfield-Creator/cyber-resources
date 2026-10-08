# Web Application Attacks

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Web application attacks target the logic, data access, and trust boundaries of internet-facing apps. In ATT&CK this is **T1190 Exploit Public-Facing Application**; the taxonomy of flaws is the **OWASP Top 10**, covering injection (SQLi, command injection), broken access control, authentication failures, SSRF, insecure deserialization, and misconfiguration. XSS and file inclusion are covered in their own pages (cross-site-scripting.md, file-inclusion.md).

## How It Works

Most web attacks abuse untrusted input that reaches a sensitive sink without proper validation, encoding, or authorisation.

- **Injection:** attacker-controlled input alters a backend query or command (SQL, OS, LDAP, NoSQL).
- **Broken access control:** missing object-level or function-level authorisation (IDOR, forced browsing, privilege bypass).
- **SSRF:** the server is coerced into making requests to internal resources or cloud metadata endpoints.
- **Authentication / session flaws:** weak tokens, fixation, or missing checks allow account takeover.
- **Misconfiguration and known-CVE exploitation:** default credentials, exposed admin panels, or unpatched components.

Public-facing apps are high value because exploitation often yields direct initial access.

## Detect

Web server, application, and WAF logs are primary; correlate with database and backend telemetry.

| Source | Signal |
| --- | --- |
| Web / WAF | SQL meta-characters and keywords in parameters, encoded payloads, 500s following crafted input |
| Web access | Sequential ID enumeration (IDOR), bursts of 403s (forced browsing), unusual methods |
| App logs | Stack traces, deserialization errors, auth-bypass anomalies |
| Netflow / proxy | Outbound from the app to internal ranges or `169.254.169.254` (SSRF to metadata) |
| DB logs | Query errors, unexpected `UNION`/`OR 1=1` patterns, long-running queries |

```yaml
title: SQL Injection Indicators in Query String
logsource:
  category: webserver
detection:
  selection:
    uri_query|contains:
      - 'union select'
      - "' or 1=1"
      - 'sleep('
      - 'information_schema'
  condition: selection
fields:
  - clientip
  - uri_path
  - uri_query
  - status
falsepositives:
  - Security scanners, legitimate search terms, false matches
level: high
```

Tune on your own parameter names; pair signature hits with response-code and timing anomalies to reduce noise.

## Mitigate

- Parameterised queries / prepared statements and ORMs to stop SQL injection; avoid shelling out to prevent command injection.
- Enforce server-side authorisation on every object and function (deny by default); never trust client-side checks.
- Validate and allow-list input; encode output for the correct context.
- Block SSRF with egress filtering, metadata-endpoint protection, and allow-listed outbound destinations.
- Deploy a tuned WAF in blocking mode as defence in depth, plus security headers and patched components (track an SBOM).
- Secure defaults, remove sample/admin interfaces, and run SAST/DAST in CI.

## Lab

- Deploy an intentionally vulnerable training app (such as OWASP Juice Shop or DVWA) on an isolated segment (192.0.2.0/24), reachable only inside the lab.
- Send crafted requests to your own instance, confirm WAF and web-log detections fire, and capture the DB-error and timing signals.
- Apply parameterised queries and access-control fixes, then re-test to confirm the finding closes. Never test against systems you do not own.

## References

- MITRE ATT&CK T1190 Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

---

**Author:** Danny Stanfield
**License:** MIT
