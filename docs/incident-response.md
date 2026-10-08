# Incident Response

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Incident response (IR) is the structured process a SOC follows to detect, contain, and recover from a security event while preserving evidence and learning from it. A repeatable process reduces dwell time, limits damage, and keeps decisions defensible. This page frames IR around the NIST SP 800-61 lifecycle and the telemetry a responder relies on at each phase.

## Lifecycle (NIST SP 800-61)

| Phase | Goal | Key activities |
| --- | --- | --- |
| Preparation | Be ready before an incident | Playbooks, logging coverage, IR tooling, contacts, tabletop drills |
| Detection and Analysis | Confirm and scope | Triage alert, validate, build timeline, assign severity |
| Containment, Eradication, Recovery | Stop spread, remove, restore | Isolate hosts, revoke credentials, remove persistence, rebuild, monitor |
| Post-Incident Activity | Learn | Root cause, lessons learned, detection and control improvements |

## Telemetry

Fast triage depends on these sources being present and time-synced before the incident:

- **Windows:** Security 4624/4625 (logon), 4688 (process), 4672 (special privileges), 4720/4728 (account and group changes), 7045 (service install); Sysmon 1, 3, 11, 13.
- **Linux:** auditd execve and connect records, journald/`/var/log/auth.log` for authentication, shell history, and cron.
- **Network:** Zeek conn/dns/http/tls logs, firewall allow and deny logs, proxy and VPN logs.
- **Identity and cloud:** SSO sign-in logs, MFA events, API audit logs, mailbox rule changes.

## Detect and Triage

Early analysis answers: what fired, on which asset and identity, when did it start, and what did it touch. Build a timeline by pivoting across sources on shared keys (host, user, process GUID, source IP). Example triage questions for a suspected compromise:

- Logon anomaly: 4625 failures followed by a 4624 success from the same source, then privileged logon (4672).
- Execution: 4688/Sysmon 1 showing a scripting interpreter spawned from a document handler (T1566, T1059).
- Persistence: new service (7045) or scheduled task (4698) created near the time of initial access.

```yaml
title: New Service Installed After Interactive Logon
logsource:
  product: windows
  service: system
detection:
  svc_install:
    EventID: 7045
  condition: svc_install
fields:
  - ServiceName
  - ImagePath
  - AccountName
level: medium
```

## Contain, Eradicate, Recover

- **Contain:** isolate the host at the network layer, disable affected accounts, block known C2 destinations. Capture volatile data before pulling the plug.
- **Eradicate:** remove persistence (services, tasks, run keys), rotate credentials and secrets, patch the exploited weakness.
- **Recover:** rebuild from known-good images, restore validated backups, and watch the asset closely for reinfection before returning to production.

## Lab

Run a tabletop with a written scenario and decision points, then a technical exercise: trigger a benign technique in an isolated range, work the alert end to end, and collect artefacts with a live-response tool such as Velociraptor or GRR. Rehearse evidence handling and chain of custody. Use 192.0.2.x hosts and example.com identities so nothing real is exposed.

## References

- NIST SP 800-61r2 Computer Security Incident Handling Guide
- SANS Incident Handler's Handbook
- MITRE ATT&CK: https://attack.mitre.org/
- Velociraptor: https://docs.velociraptor.app/

---

**Author:** Danny Stanfield
**License:** MIT
