# Cross-Site Scripting (XSS)

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Cross-Site Scripting (XSS) injects attacker-controlled script into a web page so it executes in another user's browser in the context of the trusted site. It is **CWE-79** and sits under OWASP **A03:2021 Injection**; in ATT&CK it enables browser-based initial access and script execution (related to T1059.007 JavaScript and drive-by techniques). Impact ranges from session theft to full account takeover.

## How It Works

The app reflects or stores user input into HTML, JavaScript, or attribute context without proper encoding, and the browser executes it.

- **Reflected:** payload in a request (query parameter, form) is echoed straight back in the response; delivered via a crafted link.
- **Stored (persistent):** payload is saved server-side (comment, profile, message) and served to every viewer.
- **DOM-based:** client-side JavaScript writes untrusted input into a dangerous sink (`innerHTML`, `document.write`) without the server being involved.

Because script runs as the site, it can read cookies and tokens, make authenticated requests, and rewrite the page.

## Detect

Server logs see the delivery; client-side telemetry and CSP reports see execution.

| Source | Signal |
| --- | --- |
| Web / WAF | Script-like metacharacters in parameters (`<script`, `onerror=`, `javascript:`, encoded variants) |
| CSP reports | `report-uri`/`report-to` violations indicating blocked inline or external script |
| App logs | Stored fields containing HTML/script markup; unusual content in user-generated fields |
| Client RUM | Unexpected outbound requests to attacker domains from within a session |
| Proxy | Victim browsers beaconing cookies/tokens to an external host |

```yaml
title: Reflected XSS Payload Indicators
logsource:
  category: webserver
detection:
  selection:
    uri_query|contains:
      - '<script'
      - 'onerror='
      - 'javascript:'
      - 'onload='
  condition: selection
fields:
  - clientip
  - uri_path
  - uri_query
falsepositives:
  - WYSIWYG editors, security scanners, legitimate markup in fields
level: medium
```

CSP violation reports are a strong, lower-noise detection for execution attempts; forward them to the SIEM.

## Mitigate

- Context-aware output encoding (HTML, attribute, JavaScript, URL) on all untrusted data; use a framework that auto-escapes.
- Content Security Policy with nonces/hashes and no `unsafe-inline` to neutralise injected script.
- Prefer safe DOM APIs (`textContent`) over `innerHTML`; use a vetted sanitiser (such as DOMPurify) when HTML must be rendered.
- `HttpOnly` and `Secure` cookies so script cannot read session tokens; `SameSite` to limit cross-site use.
- Input validation and allow-listing as defence in depth; WAF in blocking mode as a backstop.
- Trusted Types in supporting browsers to prevent DOM-sink misuse.

## Lab

- Deploy a deliberately vulnerable app (DVWA or OWASP Juice Shop) on an isolated segment (192.0.2.0/24).
- Trigger reflected, stored, and DOM cases against your own instance with benign proof payloads (for example an `alert(document.domain)` marker), and confirm web-log and CSP-report detections fire.
- Add output encoding and a strict CSP, then re-test to confirm the injection no longer executes. Keep all testing to assets you own.

## References

- OWASP Cross Site Scripting (XSS): https://owasp.org/www-community/attacks/xss/
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- CWE-79 Improper Neutralization of Input During Web Page Generation: https://cwe.mitre.org/data/definitions/79.html
- MDN Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

---

**Author:** Danny Stanfield
**License:** MIT
