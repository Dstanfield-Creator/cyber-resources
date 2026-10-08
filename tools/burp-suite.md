# Burp Suite

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Burp Suite is an integrated platform for web application security testing
from PortSwigger. It works as an intercepting HTTP/S proxy that sits
between a browser and a target web app, letting an analyst inspect,
modify, and replay requests. The Community Edition covers manual testing
(Proxy, Repeater, Decoder); the Professional edition adds the automated
scanner and an unthrottled Intruder. In a lab it fits the web-app testing
stage after reconnaissance, against targets you own.

## Install

| Method | Source |
| --- | --- |
| Kali package | `sudo apt install burpsuite` |
| Installer | https://portswigger.net/burp/releases |
| JAR | Requires a Java 17+ runtime |

On first run, install Burp's CA certificate in the browser so HTTPS
traffic can be intercepted without warnings.

## Common Usage

Point the browser proxy at `127.0.0.1:8080`, then work against a lab app
at `http://192.0.2.20` or `app.example.com` in your own lab.

- **Proxy:** intercept a request, review headers and body, forward or
  drop it. The HTTP history tab records all traffic.
- **Repeater:** resend a captured request with small edits to study how
  the app responds. This is the core manual-testing loop.
- **Decoder/Comparer:** decode Base64/URL/hex values and diff responses.
- **Intruder:** iterate a parameter over a wordlist (run gently in the
  Community edition, which is rate-limited).

```http
POST /login HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

username=analyst&password=lab-test
```

Keep all testing inside the lab and only against applications you are
authorised to assess.

## Detect

Burp's traffic looks like a browser, but automated use and its defaults
leave fingerprints in web server and WAF logs.

- **Collaborator:** out-of-band testing uses Burp Collaborator domains.
  Unexpected DNS or HTTP lookups to `*.oastify.com` (or a private
  Collaborator server) are a strong indicator of active testing.
- **Scanner patterns:** the scanner issues many parameter permutations
  and probe strings in a short window from one source IP, producing
  bursts of 4xx/5xx and anomalous parameter values in access logs.
- **Headers:** probe payloads can appear in parameters and headers; tuned
  WAF rules flag these signatures.

```yaml
title: Burp Collaborator Interaction
logsource:
  category: dns
detection:
  selection:
    query|endswith: '.oastify.com'
  condition: selection
level: high
```

Tuning note: a private Collaborator server changes the domain, so also
alert on scanner-rate bursts of error responses from a single client.

## References

- Official docs: https://portswigger.net/burp/documentation
- Web Security Academy: https://portswigger.net/web-security
- MITRE ATT&CK: T1190 Exploit Public-Facing Application

---

**Author:** Danny Stanfield
**License:** MIT
