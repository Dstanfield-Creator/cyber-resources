# Digital Forensics

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Digital forensics is the sound collection, preservation, and analysis of digital evidence to reconstruct what happened on a system. In a SOC it underpins incident response: it answers how an adversary got in, what they did, and what was taken, in a way that holds up to scrutiny. The two guiding principles are preserving evidence integrity (work on copies, hash everything) and respecting the order of volatility (collect the most perishable data first).

## Order of Volatility

Collect from most to least volatile:

1. CPU registers, cache, running process memory
2. Network connections, ARP cache, routing tables
3. Running processes and open files
4. Disk (filesystem, slack, unallocated)
5. Remote and archival logs
6. Physical configuration and backups

## Key Artefacts

| Platform | Artefact | Tells you |
| --- | --- | --- |
| Windows | Security event logs (4624/4688/4672) | Logons, execution, privilege use |
| Windows | Prefetch, Amcache, Shimcache | Programs that ran and when |
| Windows | $MFT, USN journal, registry hives | File activity, persistence, config |
| Linux | auditd, journald, /var/log/auth.log | Execution and authentication |
| Linux | shell history, cron, systemd units | User actions, persistence |
| Both | Memory image | Injected code, secrets, live network state |

## Process and Chain of Custody

Document who collected what, when, from where, and with which tool. Hash every acquired image (for example SHA-256) at collection and verify the hash after transfer. Keep a working copy and an untouched master. Record each handling step. A clean chain of custody is what separates evidence from an anecdote.

## Detect and Analyse

Build a super-timeline by merging artefacts on time. Example signals that place an intrusion:

- Execution: Amcache/Prefetch entry for an unexpected binary aligned with Security 4688 and Sysmon 1.
- Persistence: a new service (7045) or run-key write (Sysmon 13) near initial access.
- Credential theft: process access to LSASS (Sysmon 10, T1003).
- Exfiltration: large outbound flows in Zeek `conn.log` to a rare destination.

```bash
# Build a filesystem and artefact timeline from a mounted image copy (read-only)
log2timeline.py --storage-file case.plaso /evidence/image_copy
psort.py -o l2tcsv -w timeline.csv case.plaso
# Then pivot in a SIEM or spreadsheet around the suspected intrusion window
```

Memory analysis with Volatility 3 surfaces hidden processes, injected regions, and network artefacts not present on disk.

## Harden for Forensic Readiness

- Enable and centralise command-line auditing (4688 with command line, Sysmon, auditd) before an incident.
- Extend log retention so evidence still exists when you go looking.
- Ensure time sync (UTC, NTP) across the estate so timelines line up.

## Lab

Acquire a disk image and a memory capture from a snapshot of an isolated lab VM, hash them, and analyse read-only copies with Autopsy, Volatility 3, and plaso. Practise building a timeline and writing a short findings note. Use only lab systems and 192.0.2.x / example.com data; never analyse data you are not authorised to hold.

## References

- MITRE ATT&CK: https://attack.mitre.org/
- NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response
- Volatility 3: https://volatility3.readthedocs.io/
- Autopsy / The Sleuth Kit: https://www.sleuthkit.org/

---

**Author:** Danny Stanfield
**License:** MIT
