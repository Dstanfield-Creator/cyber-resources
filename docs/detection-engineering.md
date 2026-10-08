# Detection Engineering

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Detection engineering is the discipline of building, testing, and maintaining the logic a SOC uses to spot malicious activity. It treats detections as a product: each rule has an owner, a hypothesis, a data source, a test, and a lifecycle. The goal is high-fidelity alerts mapped to adversary behaviour rather than ad hoc signatures that decay silently. A detection engineer closes the gap between threat intelligence (what adversaries do) and the SIEM/EDR content that actually fires.

## Key Concepts

- **Detection-as-code:** rules live in version control, are peer reviewed, and deploy through CI. Changes are auditable and revertible.
- **ATT&CK mapping:** every detection references a technique (for example T1059 Command and Scripting Interpreter) so coverage gaps are visible.
- **Pyramid of Pain:** prefer detections on TTPs and tool behaviour over hashes and IPs, which adversaries rotate cheaply.
- **Fidelity vs coverage:** broad detections find more but cost analyst time. Tune for signal, track both false positives and false negatives.
- **Detection lifecycle:** idea -> hypothesis -> data check -> author -> test -> deploy -> tune -> retire.

## Data Sources

| Source | Example telemetry | Covers |
| --- | --- | --- |
| Windows Security log | 4688 process creation, 4624/4625 logon, 4720 user created | Execution, access, persistence |
| Sysmon | 1 process, 3 network, 7 image load, 11 file create, 8 remote thread | Fine-grained endpoint behaviour |
| Linux auditd / journald | execve, connect, file writes | Execution, lateral movement |
| EDR | process tree, API telemetry | Behavioural chains |
| Zeek / Suricata | conn, dns, http, tls, alerts | Network context |

## Detect

Good detections describe behaviour, not a single artefact. Example hypothesis: an attacker uses `rundll32.exe` to proxy execution of a DLL with no standard arguments (T1218.011). The signal is a process-creation event where the parent is unusual and the command line lacks a typical `,ExportName` pattern.

A Sigma-style sketch (translate to your SIEM at deploy time):

```yaml
title: Rundll32 Without Expected Arguments
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\rundll32.exe'
  filter_normal:
    CommandLine|contains: '.dll'
  condition: selection and not filter_normal
fields:
  - ParentImage
  - CommandLine
falsepositives:
  - Legacy installers invoking rundll32 directly
level: medium
```

Enrich alerts with parent process, user, host role, and ATT&CK ID so a triager has context without pivoting.

## Validate

- **Atomic Red Team** runs small, reversible tests for a specific technique so you can confirm a rule fires end to end.
- **Detection unit tests:** replay known-bad and known-good logs and assert the expected outcome.
- Track metrics per rule: true positives, false positives, mean time to detect, and last-fired date. A rule that never fires may be broken or may lack data.
- Run purple-team exercises so red emulates a technique while blue confirms the detection and refines it.

## Lab

Stand up a small isolated range: a SIEM (Elastic or Splunk free tier), a Windows VM with Sysmon using a vetted config, and a Linux VM with auditd. Forward logs, then execute Atomic tests inside the range (never against production or example.com) and iterate on rules until they fire cleanly. Snapshot VMs so each test starts from a known state.

## References

- MITRE ATT&CK: https://attack.mitre.org/
- Sigma rules project: https://github.com/SigmaHQ/sigma
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- NIST SP 800-92 Guide to Computer Security Log Management

---

**Author:** Danny Stanfield
**License:** MIT
