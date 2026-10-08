# Persistence

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Persistence is how an attacker keeps access across reboots, credential changes, and interruptions. It is the ATT&CK tactic **TA0003**, realised through techniques such as Scheduled Task/Job (**T1053**), Boot or Logon Autostart Execution (**T1547**), Create or Modify System Process / Services (**T1543**), Create Account (**T1136**), Valid Accounts (**T1078**), and Server Software Component: Web Shell (**T1505.003**).

## How It Works

The attacker plants a mechanism that re-executes their code or re-grants their access automatically.

- **Autostart:** run keys, startup folders, logon scripts, and `/etc/profile.d` entries that fire at boot or logon.
- **Scheduled execution:** Windows Scheduled Tasks or Linux cron/systemd timers that run a payload on a schedule.
- **Services and daemons:** a new or hijacked Windows service or systemd unit that starts with the host.
- **Accounts:** a new local or domain account, or a new SSH authorized key, to walk back in through the front door.
- **Web shell:** a script left on a web server for recurring remote command execution.

Good persistence looks like legitimate administration, so baselines of "what normally autostarts" are the defender's advantage.

## Detect

Focus on creation and modification of autostart points, services, tasks, and accounts.

| Source | Signal |
| --- | --- |
| Windows Security | 4697 (service installed), 4698/4702 (scheduled task created/updated), 4720 (user created), 4732 (added to admin group) |
| Sysmon | EID 13 Run-key registry writes; EID 11 writes to Startup; EID 1 schtasks.exe/sc.exe |
| Linux auditd | writes to crontab, `/etc/cron.*`, systemd unit files, `~/.ssh/authorized_keys`, `/etc/passwd` |
| Web server | new or modified script files in web root; unusual POSTs to a single rarely accessed page |
| EDR | new autoruns entries not matching a change ticket |

```yaml
title: New Scheduled Task Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
fields:
  - SubjectUserName
  - TaskName
  - TaskContent
falsepositives:
  - Software installers, legitimate admin automation
level: medium
```

Diff current autoruns, services, tasks, and `authorized_keys` against a known-good baseline and alert on additions.

## Mitigate

- Application control (WDAC/AppLocker) and script controls to stop unauthorised autostart binaries.
- Least privilege so standard users cannot install services or system-wide tasks.
- File-integrity monitoring on web roots, startup locations, cron, and systemd unit directories.
- Alert and require change-ticket correlation for new accounts, admin-group additions, and new SSH keys.
- Immutable or signed infrastructure and golden images that are rebuilt rather than patched in place.

## Lab

- On an isolated host (192.0.2.0/24) with logging to your SIEM, create test autostart entries, a scheduled task, a benign systemd timer, and a test account (`svc_test` at example.com).
- Confirm 4697/4698/4720, Sysmon registry/file events, and auditd rules capture each.
- Run a baseline-diff script before and after to verify your detection catches the additions, then remove them.

## References

- MITRE ATT&CK TA0003 Persistence: https://attack.mitre.org/tactics/TA0003/
- MITRE ATT&CK T1053 Scheduled Task/Job: https://attack.mitre.org/techniques/T1053/
- MITRE ATT&CK T1547 Boot or Logon Autostart Execution: https://attack.mitre.org/techniques/T1547/
- NIST SP 800-53 SI-7 Software, Firmware, and Information Integrity: https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search

---

**Author:** Danny Stanfield
**License:** MIT
