# Log Analysis

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Log analysis is the defensive practice of reviewing system, application and
security logs to detect, confirm and reconstruct malicious activity. It is the
backbone of SOC triage and incident response: alerts point you at a time and a
host, and the logs tell you what actually happened. This page is a practical
analyst how-to for working against lab or incident log data.

It underpins investigation of virtually every ATT&CK technique rather than being
an attack method itself.

## How It Works

Logs are time-stamped records emitted by hosts, services and controls. Effective
analysis combines:

- **Normalisation** - get disparate formats into a common, queryable shape
  (JSON is ideal).
- **Correlation** - line up events across sources by time, host and user.
- **Baselining** - know what normal looks like so deviations stand out.
- **Pivoting** - follow an indicator (IP, user, process) across all sources.

Work from copies of log files in a dedicated analysis directory and keep an
incident timeline as you go.

## Analyse

Structured (JSON) logs with `jq` - example against a lab file `events.json`:

```bash
# Count event types to orient quickly
jq -r '.event_type' events.json | sort | uniq -c | sort -n -r

# Failed logins grouped by source IP
jq -r 'select(.action=="login" and .result=="fail") | .src_ip' events.json \
  | sort | uniq -c | sort -n -r | head

# Timeline for one user of interest
jq -r 'select(.user=="testuser") | "\(.timestamp) \(.action) \(.src_ip)"' \
  events.json | sort
```

Line-oriented logs with `grep`, `awk` and friends:

```bash
# Auth failures in a Linux auth log
grep -i 'failed password' auth.log | awk '{print $(NF-3)}' | sort | uniq -c

# Spot a brute force window, then the success that followed
grep -E 'Failed|Accepted' auth.log | tail -n 50

# Web access log: top 404-generating clients (enumeration)
awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -n -r | head
```

Triage checklist:

| Question | Technique |
| --- | --- |
| What stands out by volume? | `uniq -c | sort` over the key field |
| Any auth brute force? | failed-login counts per source, then success |
| Enumeration? | 404/403 bursts per client in web logs |
| What did one indicator touch? | pivot the IP/user across all sources |
| What is the sequence? | build a merged, time-sorted timeline |

Preserve originals, record hashes of source files, and note query provenance so
findings are reproducible.

## Lab

Isolated lab (host-only 192.0.2.0/24):

1. Generate benign and simulated-malicious activity you control (failed logins, a
   content-discovery run) and collect the resulting logs.
2. Reproduce each command above to find the activity you created.
3. Practise building a timeline that merges auth, web and process logs for one
   source IP.

## References

- jq manual - https://jqlang.github.io/jq/manual/
- NIST SP 800-92 (Log Management) - https://csrc.nist.gov/
- MITRE ATT&CK (technique context) - https://attack.mitre.org/
- Sigma project (detection rules) - https://github.com/SigmaHQ/sigma

---

**Author:** Danny Stanfield
**License:** MIT
