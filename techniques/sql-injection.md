# SQL Injection

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

SQL injection (SQLi) occurs when untrusted input is concatenated into a database
query, letting an actor alter the query's logic to read, modify or exfiltrate
data. It remains one of the highest-impact web flaws. Defenders detect it through
web, WAF and database telemetry and prevent it with parameterised queries.

Relevant MITRE ATT&CK technique:

| ID | Name |
| --- | --- |
| T1190 | Exploit Public-Facing Application |

Maps to OWASP Top 10 A03 (Injection) and OWASP WSTG injection tests.

## How It Works

Conceptually, input that should be data is interpreted as query syntax. Variants:

- **In-band** - results returned directly (error-based or UNION-based).
- **Blind** - no direct output; the attacker infers data from boolean responses
  or time delays.
- **Out-of-band** - the database is coerced into making an external request
  carrying data.

The observable signatures are SQL metacharacters and keywords in parameters,
database errors surfacing to users, and anomalous query patterns.

## Detect

Log sources and signals:

| Source | Signal |
| --- | --- |
| WAF | Injection signatures in parameters and headers |
| Web access logs | SQL keywords/metacharacters in query strings |
| App logs | Database error messages, stack traces |
| DB audit logs | Unusual UNION/OR-based queries, bulk reads, schema access |

```yaml
title: SQL Injection Pattern In Web Request
logsource:
    category: webserver
detection:
    selection:
        cs_uri_query|contains:
            - 'UNION SELECT'
            - ' OR 1=1'
            - 'information_schema'
            - 'SLEEP('
    condition: selection
falsepositives:
    - Legitimate search or reporting queries containing SQL keywords
level: high
```

Pair request-side detection with database audit logs: a single web session that
suddenly reads `information_schema` or dumps a large row count is high fidelity.

## Mitigate

- Use parameterised queries / prepared statements everywhere; never concatenate
  input into SQL.
- Apply input validation and context-aware output handling as defence in depth.
- Enforce least-privilege database accounts (no DDL/admin rights for the app).
- Disable verbose database errors in production.
- Deploy a tuned WAF and alert on database audit anomalies.

## Lab

Isolated lab (deliberately vulnerable app + database, host-only 192.0.2.0/24):

1. Exercise a benign injection against your own lab app and confirm WAF and DB
   audit logs capture it and trigger the Sigma rule.
2. Convert the query to a parameterised statement and verify the injection no
   longer alters behaviour.
3. Lower the app's DB privileges and confirm the blast radius shrinks.

## References

- MITRE ATT&CK T1190 - https://attack.mitre.org/techniques/T1190/
- OWASP SQL Injection - https://owasp.org/www-community/attacks/SQL_Injection
- OWASP SQLi Prevention Cheat Sheet - https://cheatsheetseries.owasp.org/
- OWASP Top 10 A03 - https://owasp.org/Top10/

---

**Author:** Danny Stanfield
**License:** MIT
