# Authentication Bypass

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Authentication bypass is any technique that lets an actor reach protected
functionality without presenting valid credentials, or while presenting
credentials the system should have rejected. It spans logic flaws, token
mishandling and access-control gaps. Detection relies on application and
identity-provider logs rather than network sensors.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1556 | Modify Authentication Process |
| T1212 | Exploitation for Credential Access |
| T1078 | Valid Accounts |

Maps to OWASP Top 10 A07 (Identification and Authentication Failures) and A01
(Broken Access Control).

## How It Works

Representative classes (conceptual, not weaponised):

- **Broken access control** - forced browsing to authenticated pages, or IDOR
  where an identifier is changed to reach another user's object.
- **Token / session flaws** - predictable, non-expiring or improperly validated
  session tokens and JWTs.
- **Logic flaws** - skippable multi-step flows, password-reset abuse, response
  manipulation.
- **Default and residual credentials** - unchanged vendor defaults or test
  accounts left enabled.

The common thread is a successful authenticated action with no legitimate
preceding authentication event.

## Detect

Log sources and signals:

| Source | Signal |
| --- | --- |
| App / auth logs | Access to protected routes without a matching login event |
| IdP / SSO logs | Token use from impossible locations, reused session IDs |
| WAF | Sequential ID iteration, tampered cookies/JWT, forced browsing |
| Audit logs | Privileged action by an account that never authenticated |

```yaml
title: Protected Resource Access Without Authentication Event
logsource:
    category: application
detection:
    selection:
        url_path|startswith: '/admin/'
        http_status: 200
    filter:
        event: successful_login
    condition: selection and not filter
falsepositives:
    - Long-lived valid sessions that predate the log window
level: high
```

Correlate authenticated access against recent login events per session/user;
gaps are the signal. Watch for sequential object-ID access from one session.

## Mitigate

- Enforce server-side authorisation on every request; never trust client state.
- Use strong, random, expiring session tokens; validate JWT signature, audience
  and expiry.
- Remove default/test accounts and change vendor defaults.
- Require MFA on sensitive and administrative functions.
- Add object-level access checks (prevent IDOR) and deny-by-default routing.

## Lab

Isolated lab (deliberately vulnerable app at http://example.com, host-only):

1. Reproduce a forced-browsing bypass against your own lab app; confirm the
   access-without-login pattern appears in logs and triggers the Sigma rule.
2. Add server-side authorisation and re-test that the bypass now fails.
3. Iterate an object ID to demonstrate IDOR, then add ownership checks and verify
   detection and prevention.

## References

- MITRE ATT&CK T1556 - https://attack.mitre.org/techniques/T1556/
- OWASP Top 10 A01/A07 - https://owasp.org/Top10/
- OWASP Authentication Cheat Sheet - https://cheatsheetseries.owasp.org/
- NIST SP 800-63B - https://pages.nist.gov/800-63-3/

---

**Author:** Danny Stanfield
**License:** MIT
