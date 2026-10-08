# DNS Enumeration

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

DNS enumeration is the collection of hostnames, subdomains and record data for a
target domain. It is largely passive and often invisible to the victim, which is
why defenders rely on authoritative-server logs, resolver telemetry and external
monitoring rather than host alerts.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1590.002 | Gather Victim Network Information: DNS |
| T1596.001 | Search Open Technical Databases: DNS/Passive DNS |
| T1018 | Remote System Discovery |

## How It Works

Common enumeration behaviours:

- **Zone transfer (AXFR)** - requesting a full copy of a zone from a
  misconfigured authoritative server.
- **Record harvesting** - querying A, AAAA, MX, TXT, NS, SRV and CNAME records.
- **Subdomain brute force** - resolving many candidate names from a wordlist.
- **Passive DNS / OSINT** - reading third-party datasets so the target never
  sees the query.
- **Reverse lookups** - PTR sweeps across an owned IP block.

High query volume for nonexistent names (NXDOMAIN) is the classic brute-force
signature.

## Detect

Primary telemetry:

- **Authoritative DNS logs** - AXFR/IXFR requests from unexpected sources.
- **Resolver / DNS firewall logs** - spikes in NXDOMAIN, high unique-subdomain
  counts per client.
- **Passive DNS and attack-surface monitoring** - new records appearing for your
  domains.

```yaml
title: Unauthorized DNS Zone Transfer Attempt
logsource:
    product: dns
    category: dns_query
detection:
    selection:
        query_type: AXFR
    filter:
        src_ip:
            - '192.0.2.0/24'   # authorised secondary nameservers
    condition: selection and not filter
falsepositives:
    - New or re-IP'd secondary nameservers
level: high
```

For brute force, alert when one client produces a high ratio of NXDOMAIN
responses or resolves many distinct labels under one parent domain in a short
window.

## Mitigate

- Restrict AXFR/IXFR to named secondary servers only; deny by default.
- Split-horizon DNS so internal names are not served to the internet.
- Rate-limit resolvers and enable DNS firewalling / response policy zones.
- Minimise record hygiene leaks (stale A records, internal hosts in public zones).
- Monitor certificate transparency and passive DNS for your own domains to catch
  what adversaries can see.

## Lab

Isolated lab (example.com served by a lab authoritative server):

1. Deliberately allow AXFR, attempt a transfer, confirm it appears in the server
   log and triggers the Sigma rule.
2. Lock AXFR to the secondary only and re-test the denial.
3. Run a subdomain brute force against the lab zone and confirm the NXDOMAIN
   spike is visible in resolver logs.

## References

- MITRE ATT&CK T1590.002 - https://attack.mitre.org/techniques/T1590/002/
- MITRE ATT&CK T1596.001 - https://attack.mitre.org/techniques/T1596/001/
- RFC 5936 (DNS Zone Transfer Protocol AXFR) - https://www.rfc-editor.org/
- NIST SP 800-81 (Secure DNS Deployment) - https://csrc.nist.gov/

---

**Author:** Danny Stanfield
**License:** MIT
