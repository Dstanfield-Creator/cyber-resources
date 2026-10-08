# Kali Linux

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Kali Linux is a Debian-based distribution maintained by OffSec and built
for penetration testing and security research. It ships a large curated
set of offensive and analysis tools (many referenced elsewhere in this
folder) preinstalled and configured. In a home lab it is a convenient,
disposable analyst workstation: snapshot a VM, run an exercise against
isolated targets, and revert. This page covers the platform itself and
how its default tooling looks to a defender.

## Install

| Method | Source |
| --- | --- |
| ISO / VM images | https://www.kali.org/get-kali/ |
| WSL | `kali-linux` from the Microsoft Store |
| Docker | `docker pull kalilinux/kali-rolling` |

Verify the SHA256 and GPG signature of any image before use. Kali is a
rolling release; run `sudo apt update && sudo apt full-upgrade` to patch.

## Common Usage

Keep the lab VM on an isolated host-only or internal network so traffic
never leaves the lab.

```bash
# Update the system and tool metadata
sudo apt update && sudo apt full-upgrade -y

# Install a metapackage of tools on demand
sudo apt install kali-tools-web

# Confirm the interface is on an isolated subnet before testing
ip addr show
```

Typical lab flow: snapshot the VM, run an exercise against targets like
`192.0.2.0/24` or `app.example.com` in the lab, capture telemetry, then
revert to the clean snapshot.

## Detect

Kali itself is just an OS; the defensive interest is that a Kali host on a
managed network is almost always an analyst or an intruder, and its
default tools are individually signatured (see the other pages here).

- **Host fingerprint:** default hostname `kali`, a distinctive DHCP
  fingerprint, and User-Agent strings from bundled tools can hint at a
  Kali host via passive fingerprinting (e.g. p0f) or DHCP logs.
- **Tool telemetry:** the real signals are the activities the tools
  produce - scans, brute force, web probes - covered per-tool here.
- **Asset management:** an unknown Debian/Kali host appearing in DHCP,
  NAC, or switch MAC tables on a managed network is the first alert.

```yaml
title: Possible Kali Host via Default Hostname
logsource:
  category: dhcp
detection:
  selection:
    hostname|contains: 'kali'
  condition: selection
level: low
```

Tuning note: hostname and fingerprint checks are weak on their own and
easily changed; treat them as enrichment and lean on the per-tool
behavioural detections.

## References

- Official site: https://www.kali.org/
- Documentation: https://www.kali.org/docs/
- Tool listing: https://www.kali.org/tools/

---

**Author:** Danny Stanfield
**License:** MIT
