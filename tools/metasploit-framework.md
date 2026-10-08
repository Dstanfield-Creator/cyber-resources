# Metasploit Framework

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

The Metasploit Framework is an open-source exploitation and
post-exploitation platform maintained by Rapid7. It provides a catalogue
of modules (exploits, payloads, auxiliary scanners, post modules) behind
a common console, `msfconsole`. In a lab it is used to validate that a
known-vulnerable target is actually exploitable and to study payload and
C2 behaviour end to end. This reference stays lab-scoped and
non-weaponised and focuses on how its activity looks to defenders.

## Install

| Platform | Command |
| --- | --- |
| Kali | `sudo apt install metasploit-framework` |
| Installer | https://docs.metasploit.com/ (nightly installers) |
| First run | `msfconsole` then `db_status` to confirm the database |

## Common Usage

Use only against deliberately vulnerable lab targets (for example a local
Metasploitable VM at `192.0.2.30`).

```bash
# Start the console quietly
msfconsole -q

# Select an auxiliary scanner module and run it
search type:auxiliary smb
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.0.2.30
run
```

Workflow at a glance:

| Phase | Module type |
| --- | --- |
| Discovery | `auxiliary/scanner/*` |
| Exploitation | `exploit/*` with a matched `payload` |
| Session handling | Meterpreter or a shell session |
| Post | `post/*` modules for enumeration |

Keep payload listeners bound to lab interfaces and tear down sessions
when finished.

## Detect

Metasploit is heavily signatured; default modules and payloads are a
primary detection target.

- **Meterpreter traffic:** default TLS staging has recognisable
  certificate and handshake patterns; many IDS rulesets (Suricata/Snort)
  ship signatures for the default stager and reverse shells.
- **Service exploits:** auxiliary scanners generate the same multi-port,
  multi-probe noise as any scanner in flow and firewall logs.
- **Host side:** payload execution shows up as anomalous child processes,
  injected threads, and `rundll32`/`regsvr32` abuse (Sysmon Event ID 1
  process create, Event ID 8 CreateRemoteThread, Event ID 10 process
  access to LSASS when post modules harvest credentials).

```yaml
title: Possible Meterpreter Named Pipe
logsource:
  product: windows
  category: pipe_created
detection:
  selection:
    PipeName|startswith: '\msf-pipe'
  condition: selection
level: high
```

Default module strings and self-signed certs are the easiest wins;
operators change them, so pair signatures with behavioural detection.

## References

- Official docs: https://docs.metasploit.com/
- Module reference: https://www.rapid7.com/db/
- MITRE ATT&CK: T1059 Command and Scripting Interpreter; T1055 Process Injection

---

**Author:** Danny Stanfield
**License:** MIT
