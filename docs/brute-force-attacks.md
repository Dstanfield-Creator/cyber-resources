# Brute Force Attacks

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Brute force covers any authentication attack that tries many credentials until one works. MITRE ATT&CK tracks it as **T1110**, with sub-techniques for password guessing (T1110.001), password cracking against captured hashes (T1110.002), password spraying (T1110.003), and credential stuffing (T1110.004). From a defender's view the common thread is high-volume or low-and-slow authentication attempts that eventually land a valid session.

## How It Works

An attacker submits credentials to any surface that validates them: web login forms, VPN or RDP gateways, SSH, SMTP AUTH, Kerberos pre-authentication, or cloud identity providers.

- **Vertical (password guessing):** many passwords against one account. Noisy and prone to lockout.
- **Horizontal (password spraying):** one or two common passwords against many accounts, pacing attempts to stay under per-account lockout thresholds.
- **Credential stuffing:** reusing username and password pairs leaked from other breaches, betting on password reuse.
- **Offline cracking:** once a hash store (NTDS.dit, /etc/shadow, a database dump) is stolen, guessing happens offline with no authentication logs to catch it.

The economics favour the attacker where accounts lack MFA, passwords are weak or reused, and failed logins are not correlated across accounts and source IPs.

## Detect

Authentication logs are the primary signal. Correlate failures by account, by source, and across the estate rather than per host.

| Source | Signal |
| --- | --- |
| Windows Security | 4625 (failed logon), 4624 (success), 4771 (Kerberos pre-auth failure), 4740 (account lockout) |
| Windows Security | Spraying pattern: many 4625 across distinct accounts from one source, then a 4624 |
| Linux auditd / journald | `pam_unix` auth failures, sshd `Failed password`, `authpriv` facility |
| Web / WAF | Bursts of HTTP 401/403 or repeated 200 POSTs to a login path from one IP or ASN |
| Netflow / proxy | Many short-lived connections to 22/389/443/3389 from a single source |
| Cloud IdP | Repeated sign-in failures, impossible-travel, new-ASN sign-ins |

```yaml
title: Password Spraying - Many Accounts One Source
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 10m
  condition: selection | count(TargetUserName) by IpAddress > 10
fields:
  - IpAddress
  - TargetUserName
  - WorkstationName
falsepositives:
  - Shared service accounts, misconfigured clients, NAT egress
level: high
```

Watch for a single success (4624) immediately following a run of failures from the same source, and for a success from a source or geo that never authenticated before.

## Mitigate

- Enforce phishing-resistant MFA on every external and privileged surface (NIST SP 800-63B).
- Use account lockout or progressive throttling, plus per-source rate limiting to blunt spraying.
- Ban breached and common passwords; screen against known-exposed credential lists.
- Alert on and disable unused or default accounts; restrict legacy protocols that bypass MFA (basic auth, NTLM, IMAP/POP).
- Protect credential stores: strong hashing (bcrypt/argon2), restricted access to NTDS.dit and SAM, and monitoring of hash-dump activity.
- Prefer SSH keys or certificate auth over passwords; disable password auth where feasible.

## Lab

Reproduce in an isolated lab to validate detections, never against third-party systems.

- Stand up a domain controller and a Linux host on an isolated segment (192.0.2.0/24).
- Create disposable test accounts (`testuser01`..`testuser20` at example.com) and ship logs to your SIEM.
- Generate failed and successful logons with a controlled, rate-limited script you own, then confirm 4625/4740 and auditd failures land and your spraying rule fires.
- Tune thresholds against a noisy-but-benign baseline (a misconfigured mail client) to measure false positives.

## References

- MITRE ATT&CK T1110 Brute Force: https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1110.003 Password Spraying: https://attack.mitre.org/techniques/T1110/003/
- OWASP Credential Stuffing Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
- NIST SP 800-63B Digital Identity Guidelines: https://pages.nist.gov/800-63-3/sp800-63b.html

---

**Author:** Danny Stanfield
**License:** MIT
