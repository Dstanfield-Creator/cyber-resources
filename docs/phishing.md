# Phishing

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Phishing is the delivery of deceptive messages that trick a recipient into opening a malicious attachment, clicking a hostile link, or disclosing credentials. MITRE ATT&CK tracks delivery as **T1566 Phishing** (spearphishing attachment T1566.001, link T1566.002, via service T1566.003) and information-gathering as **T1598 Phishing for Information**. Internal spearphishing from a compromised account is **T1534**. It remains a leading initial-access vector.

## How It Works

An attacker crafts a message that impersonates a trusted sender (a brand, a colleague, or a service) and creates urgency or routine plausibility.

- **Attachment:** a document or archive carrying a macro, script, or exploit that runs on open.
- **Link:** a URL to a credential-harvesting page that mimics a real login, or to a malware payload. Links often pass through redirectors and newly registered look-alike domains.
- **Via service:** delivery over SMS (smishing), chat, or social platforms to bypass email controls.
- **Business Email Compromise (BEC):** text-only messages that request payments or data, with no payload to scan.

Success depends on a convincing lure, a delivery path that evades filtering, and a victim action that the environment does not constrain.

## Detect

Blend mail-gateway telemetry, endpoint behaviour after the click, and identity signals.

| Source | Signal |
| --- | --- |
| Mail gateway | SPF/DKIM/DMARC failures, newly registered sender domains, lookalike display names, known-bad URLs |
| Email auth | DMARC `p=reject` failures, header From vs envelope From mismatch |
| Endpoint / Sysmon | Office spawning a shell (EID 1 with winword/excel as parent of cmd/powershell/wscript) |
| Proxy / DNS | First-contact to a young domain, credential POST to an external lookalike host |
| Identity | Sign-in from new ASN right after a mail click; MFA fatigue prompts |

```yaml
title: Office Application Spawning Script Interpreter
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\outlook.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\wscript.exe'
  condition: selection
fields:
  - ParentImage
  - Image
  - CommandLine
falsepositives:
  - Signed enterprise macros, add-ins
level: high
```

Correlate reported-phish mailbox submissions with proxy and endpoint hits to find who else received the same lure.

## Mitigate

- Enforce SPF, DKIM, and DMARC (`p=reject`) and apply inbound anti-spoofing and lookalike-domain detection.
- Phishing-resistant MFA (FIDO2) so stolen passwords alone do not grant access.
- Attachment sandboxing, macro blocking from the internet, and safe-link URL rewriting/detonation.
- An easy report-phish button that feeds triage and auto-pulls matching mail from other inboxes.
- Recurring user awareness training and a clear out-of-band verification process for payment or data requests (BEC).
- Browser isolation or warning interstitials for newly seen or uncategorised domains.

## Lab

- Run authorised internal simulations only, with management sign-off, scoped to your own users and your own example.com infrastructure.
- Stand up a lab mail flow and a benign landing page on an isolated segment (192.0.2.0/24) to validate URL rewriting and reporting workflows.
- Detonate a benign macro-bearing document in a sandbox VM to confirm the Office-spawns-shell rule fires.
- Measure report rate and mean-time-to-pull for simulated lures; never target third parties.

## References

- MITRE ATT&CK T1566 Phishing: https://attack.mitre.org/techniques/T1566/
- MITRE ATT&CK T1598 Phishing for Information: https://attack.mitre.org/techniques/T1598/
- CISA Phishing Guidance - Stopping the Attack Cycle: https://www.cisa.gov/resources-tools/resources/phishing-guidance-stopping-attack-cycle-phase-one
- NIST SP 800-177 Trustworthy Email: https://csrc.nist.gov/pubs/sp/800/177/r1/final

---

**Author:** Danny Stanfield
**License:** MIT
