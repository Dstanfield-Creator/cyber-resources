# Social Engineering

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Social engineering manipulates people into taking actions or revealing information that weaken security, bypassing technical controls by targeting human trust. It underpins several ATT&CK techniques rather than being a single ID: phishing (**T1566**), phishing for information (**T1598**), impersonation (**T1656**), and internal spearphishing (**T1534**). Common forms include pretexting, baiting, vishing (voice), smishing (SMS), tailgating, and help-desk or MFA-reset fraud.

## How It Works

The attacker builds a plausible pretext and exploits cognitive shortcuts: authority, urgency, familiarity, reciprocity, and fear.

- **Pretexting:** a fabricated scenario (new starter, auditor, vendor) to justify a request.
- **Vishing / help-desk fraud:** calling support to reset a password or MFA factor by impersonating an employee.
- **MFA fatigue / prompt bombing:** repeated push prompts until the target approves one.
- **Baiting:** a lure such as a dropped USB device or a "free" download.
- **Tailgating / impersonation:** physical entry by following staff or posing as a contractor.

The weakness is process, not software: unverified identity at a human decision point.

## Detect

Signals are indirect. Correlate identity, help-desk, and physical-access records with later account behaviour.

| Source | Signal |
| --- | --- |
| Identity / IdP | MFA factor reset or added, then sign-in from new device/ASN; repeated push denials then an approval |
| Help-desk / ITSM | Password or MFA resets lacking strong identity proofing; out-of-process urgency |
| Mail / phone | Caller or sender claiming authority, requests to bypass procedure |
| Badge / PACS | Entry without a corresponding badge event, after-hours access anomalies |
| Finance | Payment or bank-detail change requests arriving by message only |

```yaml
title: MFA Factor Added Then New-Device Sign-In
logsource:
  category: authentication
detection:
  factor_change:
    action: 'mfa_method_registered'
  new_device_login:
    action: 'user_login'
    device_is_new: true
  timeframe: 1h
  condition: factor_change followed by new_device_login by user
fields:
  - user
  - source_ip
  - device_id
falsepositives:
  - Genuine device upgrades, legitimate re-enrolment
level: high
```

Treat a cluster of help-desk resets, factor changes, and new-device logins for the same user as a likely account-takeover.

## Mitigate

- Strong identity proofing at the help desk: callback to a known number, manager verification, or a knowledge challenge the caller cannot source externally.
- Number matching and limits on MFA push prompts to defeat fatigue; prefer FIDO2.
- Out-of-band dual approval for payments and banking changes.
- Least privilege so a single tricked user cannot authorise high-impact actions alone.
- Physical controls: visitor escort, anti-tailgating, badge enforcement, and USB device-control policy.
- Regular awareness training with realistic scenarios and a blameless reporting culture.

## Lab

- Run authorised tabletop exercises and sanctioned simulations only, scoped to your own staff at example.com with management approval.
- Script a help-desk reset drill and verify the proofing steps are followed and logged.
- In the IdP lab, register and remove MFA factors on test accounts to confirm the factor-change-then-login rule fires.
- Review physical-access logs from a mock tailgating drill; keep all activity internal and consented, never targeting third parties.

## References

- MITRE ATT&CK T1656 Impersonation: https://attack.mitre.org/techniques/T1656/
- MITRE ATT&CK T1534 Internal Spearphishing: https://attack.mitre.org/techniques/T1534/
- CISA Avoiding Social Engineering and Phishing Attacks: https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks
- NIST SP 800-63B (authenticator and verifier requirements): https://pages.nist.gov/800-63-3/sp800-63b.html

---

**Author:** Danny Stanfield
**License:** MIT
