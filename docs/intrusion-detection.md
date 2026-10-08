# Intrusion Detection

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

An Intrusion Detection System (IDS) inspects activity for signs of attack and raises alerts; an Intrusion Prevention System (IPS) can also block inline. Detection happens on the network (NIDS) or on the host (HIDS/EDR). A SOC uses both: the network sees traffic the host cannot, and the host sees execution the network cannot. This page covers where sensors sit, what they detect, and how to tune them so analysts are not buried in noise.

## Key Concepts

| Dimension | Options | Trade-off |
| --- | --- | --- |
| Location | Network (NIDS) vs host (HIDS/EDR) | Breadth vs depth of visibility |
| Method | Signature vs anomaly/behaviour | Known-bad precision vs novel coverage |
| Mode | Detect (IDS) vs inline block (IPS) | Safety vs latency and false-positive risk |
| Placement | SPAN/mirror port vs inline TAP | Visibility vs failure impact |

- **Signature detection** matches known patterns; precise but blind to novel activity.
- **Anomaly detection** flags deviation from a baseline; catches the unknown but needs tuning to control false positives.
- Place network sensors at choke points: internet egress, the DMZ, and between segments so east-west traffic is visible, not just north-south.

## Detect

Network sensors (Suricata, Snort, Zeek) generate both rule alerts and protocol logs. A rule describes a known-bad condition; the protocol logs give the context to confirm it. Example Suricata rule structure (detection logic only, benign test traffic):

```text
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"Suspicious short user-agent to rare host"; \
  flow:established,to_server; \
  http.user_agent; content:"curl"; \
  threshold: type limit, track by_src, count 1, seconds 300; \
  classtype:policy-violation; sid:1000001; rev:1; )
```

Host telemetry complements this. Map signals to ATT&CK:

- **Windows:** Sysmon 1 (process), 3 (network), 8 (remote thread), 10 (process access to LSASS, T1003), 11 (file create); Security 4688.
- **Linux:** auditd execve and connect, journald, OSSEC/Wazuh file-integrity events.
- **Zeek:** `conn.log`, `dns.log`, `ssl.log`, and `notice.log` for protocol anomalies and long-lived or beaconing flows.

A practical anomaly detection: alert on a host in 192.0.2.0/24 that suddenly initiates outbound connections to many new external destinations in a short window (possible scanning or C2 fan-out).

## Harden and Tune

- Baseline normal first; suppress known-good talkers (update servers, scanners, monitoring) with documented filters.
- Rank rules by fidelity and disable noisy, low-value signatures rather than letting analysts ignore the console.
- Keep signature sets current (for example Emerging Threats) and review suppressions on a schedule.
- Protect the sensor itself: out-of-band management, read-only capture interfaces, restricted access.

## Lab

Build an isolated range with Security Onion (Suricata plus Zeek plus a SIEM) watching a mirror port. Generate benign and clearly-malicious-pattern test traffic between lab VMs on 192.0.2.x, confirm alerts and protocol logs, then practise writing one signature and one anomaly rule and tuning out a false positive. Never point sensors or test traffic at systems you do not own.

## References

- MITRE ATT&CK: https://attack.mitre.org/
- Suricata documentation: https://docs.suricata.io/
- Zeek documentation: https://docs.zeek.org/
- NIST SP 800-94 Guide to Intrusion Detection and Prevention Systems

---

**Author:** Danny Stanfield
**License:** MIT
