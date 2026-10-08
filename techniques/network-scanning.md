# Network Scanning

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Network scanning is the reconnaissance activity of probing an address range to
discover live hosts, reachable ports and network topology. From the defender's
seat it is early-stage adversary behaviour and a strong leading indicator of an
intrusion in progress.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1595 | Active Scanning |
| T1595.001 | Scanning IP Blocks |
| T1046 | Network Service Discovery |
| T1018 | Remote System Discovery |

## How It Works

An actor sweeps a subnet to map what is reachable, then narrows to interesting
hosts. Common patterns:

- **Host discovery** - ICMP echo, TCP/UDP pings and ARP sweeps to find live IPs.
- **Port sweeps** - the same port tested across many hosts (horizontal scan).
- **Port scans** - many ports tested on one host (vertical scan).
- **Stealth variants** - SYN-only, FIN, NULL or slow-rate scans to evade naive
  thresholds.

Internal scans (from an already-compromised host) matter most; they signal
lateral discovery rather than background internet noise.

## Detect

Primary telemetry:

- **Firewall / NGFW logs** - denied connections, fan-out from a single source.
- **NetFlow / IPFIX / Zeek conn.log** - many short-lived flows, high unique-port
  or unique-destination counts per source.
- **IDS/IPS** (Suricata, Snort) - scan preprocessors and portsweep signatures.
- **Endpoint** - unexpected scanning binaries or raw socket use.

Key signals: one source touching many destinations or ports in a short window,
high ratio of SYN to SYN-ACK, bursts of connection resets.

```yaml
title: Horizontal Port Sweep From Single Source
logsource:
    category: firewall
detection:
    selection:
        action: denied
    timeframe: 1m
    condition: selection | count(dst_ip) by src_ip > 50
falsepositives:
    - Vulnerability scanners
    - Monitoring and asset-discovery tools
level: medium
```

Tune by excluding sanctioned scanners (e.g. an asset-inventory host at
192.0.2.10) and by alerting on internal-to-internal sweeps more aggressively
than inbound internet noise.

## Mitigate

- Segment the network so a foothold cannot reach the whole estate (limits
  blast radius of T1046/T1018).
- Default-deny east-west traffic between workstation VLANs.
- Deploy honeypots / deception hosts; any connection to them is high-fidelity.
- Rate-limit and drop unsolicited scans at the perimeter.
- Maintain an authorised-scanner allowlist so legitimate scans are distinguishable.

## Lab

In an isolated lab (two VMs on a host-only network, 192.0.2.0/24):

1. Run a scanner against a target you own and capture firewall + Zeek logs.
2. Confirm the sweep appears as a fan-out in `conn.log` and triggers your Sigma
   rule in the SIEM.
3. Re-run a slow / randomised scan and measure detection gaps; adjust thresholds.

## References

- MITRE ATT&CK T1595 - https://attack.mitre.org/techniques/T1595/
- MITRE ATT&CK T1046 - https://attack.mitre.org/techniques/T1046/
- Zeek conn.log docs - https://docs.zeek.org/
- NIST SP 800-115 (Technical Guide to Security Testing) - https://csrc.nist.gov/

---

**Author:** Danny Stanfield
**License:** MIT
