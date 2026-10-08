# Lateral Movement

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Lateral movement is how an attacker pivots from an initial foothold to other hosts, moving toward objectives such as domain dominance or sensitive data. It is the ATT&CK tactic **TA0008**, realised through techniques including Remote Services (**T1021**: RDP .001, SMB/admin shares .002, SSH .004, WinRM .006), Use Alternate Authentication Material (**T1550**: pass-the-hash .002, pass-the-ticket .003), and Lateral Tool Transfer (**T1570**).

## How It Works

After gaining credentials or tokens, the attacker reuses them to authenticate to additional systems using legitimate remote-access protocols, so activity blends with normal administration.

- **Credential reuse:** valid accounts via RDP, SMB (`ADMIN$`/`C$`), WinRM, or SSH.
- **Pass-the-hash / pass-the-ticket:** authenticating with stolen NTLM hashes or Kerberos tickets without the plaintext password.
- **Remote execution:** service creation, scheduled tasks, WMI, or PsExec-style tooling to run code on a target.
- **Tool transfer:** staging binaries or scripts to the next host over SMB or HTTP.

The tradecraft favours "living off the land" (built-in admin tools) to avoid dropping obvious malware.

## Detect

The richest signals are authentication and remote-execution events seen from the destination host and the domain controller.

| Source | Signal |
| --- | --- |
| Windows Security | 4624 type 3 (network) and type 10 (RDP); 4672 (admin logon); 4768/4769 (Kerberos TGT/TGS) |
| Windows Security | 5140/5145 (share access to ADMIN$/C$); 4697 (service installed); 7045 |
| Sysmon | EID 1 for psexec/wmic/winrs; EID 3 network connections to 445/3389/5985; EID 11 remote file writes |
| Linux auditd | sshd accepted logins from internal peers, unusual `sudo` chains, new cron |
| Netflow | East-west connections to 445/3389/5985/22 between hosts that never normally talk |

```yaml
title: Remote Service Execution via Admin Share
logsource:
  product: windows
  service: security
detection:
  share:
    EventID: 5145
    ShareName|contains: 'ADMIN$'
  service:
    EventID: 7045
  timeframe: 10m
  condition: share and service
fields:
  - SubjectUserName
  - IpAddress
  - ShareName
falsepositives:
  - Legitimate software deployment and remote admin tools
level: high
```

Hunt for one account authenticating to many hosts in a short window, and for NTLM use where Kerberos is expected (a pass-the-hash indicator).

## Mitigate

- Network segmentation and host firewalls to block unnecessary east-west SMB/RDP/WinRM.
- Deny lateral admin logons with the protected-users group, LAPS for unique local admin passwords, and blocking local accounts from network logon.
- Tiered administration so workstation admins cannot log on to servers or domain controllers.
- Phishing-resistant MFA on remote-access paths; disable NTLM where feasible.
- Just-in-time and just-enough admin; monitor and restrict PsExec/WMI/WinRM to jump hosts.

## Lab

- Build a small AD domain with two workstations and a server on an isolated segment (192.0.2.0/24), forwarding logs to your SIEM.
- Using test admin accounts at example.com, perform sanctioned remote execution between your own hosts and confirm 4624 type 3/10, 5145, and 7045 appear.
- Validate the admin-share-plus-service rule, then apply LAPS and segmentation and re-test to confirm the path is blocked.

## References

- MITRE ATT&CK TA0008 Lateral Movement: https://attack.mitre.org/tactics/TA0008/
- MITRE ATT&CK T1021 Remote Services: https://attack.mitre.org/techniques/T1021/
- MITRE ATT&CK T1550 Use Alternate Authentication Material: https://attack.mitre.org/techniques/T1550/
- Microsoft LAPS documentation: https://learn.microsoft.com/windows-server/identity/laps/laps-overview

---

**Author:** Danny Stanfield
**License:** MIT
