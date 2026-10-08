# Nmap

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Nmap (Network Mapper) is an open-source network discovery and security
auditing tool. It maps live hosts, open ports, running services, and
operating systems by crafting and interpreting raw packets. In a lab
workflow it sits at the reconnaissance stage: you use it to inventory an
isolated subnet before any deeper testing, and defenders use the same
artefacts it produces to understand what an attacker would see.

## Install

| Platform | Command |
| --- | --- |
| Debian/Kali | `sudo apt install nmap` |
| RHEL/Fedora | `sudo dnf install nmap` |
| macOS | `brew install nmap` |
| Source | https://nmap.org/download.html |

The Windows build ships with the Npcap driver and the Zenmap GUI.

## Common Usage

All targets below are RFC 5737 documentation addresses on an isolated lab.

```bash
# Host discovery only (no port scan) across a lab /24
nmap -sn 192.0.2.0/24

# Default SYN scan of the top 1000 ports
sudo nmap -sS 192.0.2.10

# Service and version detection with default scripts
sudo nmap -sV -sC 192.0.2.10

# Full TCP port range, service detection, OS guess
sudo nmap -p- -sV -O 192.0.2.10

# UDP scan of a few common services
sudo nmap -sU -p 53,123,161 192.0.2.10

# Save output in all formats for later review
nmap -sV -oA lab-scan 192.0.2.10
```

Keep scans inside the lab subnet. The `-T4`/`-T5` timing templates are
noisy and are useful mainly for seeing how loud a scan looks to a defender.

## Detect

Port scans are high-signal events. A SYN scan leaves many half-open
connections: a burst of SYN packets to many ports from one source, few
completing the handshake. Defenders surface this from several angles.

- **Flow/IDS:** Zeek `conn.log` shows one source touching many ports with
  `S0` (no reply) states; Suricata and Snort ship scan rules (e.g. the
  Snort sfPortscan preprocessor) that fire on connection-rate thresholds.
- **Firewall logs:** many `DROP`/`REJECT` entries to sequential or
  scattered ports from a single IP in a short window.
- **Host logs:** short-lived connections across many ports; version
  detection (`-sV`) sends real payloads that appear in application logs.

```yaml
# Sigma-style: horizontal port scan from one source
title: Possible Nmap Port Scan
logsource:
  category: firewall
detection:
  selection:
    action:
      - drop
      - reject
  timeframe: 1m
  condition: selection | count(dst_port) by src_ip > 100
level: medium
```

Tuning note: whitelist authorised scanners and vulnerability-management
hosts so their scheduled scans do not drown out real reconnaissance.

## References

- Official docs: https://nmap.org/book/
- NSE scripts: https://nmap.org/nsedoc/
- MITRE ATT&CK: T1046 Network Service Discovery; T1595 Active Scanning

---

**Author:** Danny Stanfield
**License:** MIT
