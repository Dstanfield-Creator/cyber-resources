# Protocol Analysis

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Protocol analysis is the defensive practice of inspecting captured network
traffic to understand what happened on the wire: which hosts talked, over which
protocols, and whether the behaviour is benign or malicious. It is the analyst's
core technique for validating alerts, scoping incidents and hunting. This page is
a practical how-to for working against lab or incident PCAPs, not an attack
method.

It supports investigation of many ATT&CK techniques (C2, lateral movement,
exfiltration) but is itself a blue-team analysis workflow.

## How It Works

A capture (PCAP) records frames that tools reassemble into flows and
application-layer transactions. Two complementary approaches:

- **Packet-level** (Wireshark / tshark) - exact fields, handshakes, payloads.
- **Flow / log-level** (Zeek) - summarised connection and protocol logs that
  scale to large captures and feed a SIEM.

A good workflow starts broad (who talked to whom) and narrows to specific flows.

## Analyse

Work from a copy of the capture in a dedicated analysis directory. Example
commands against a lab file `lab.pcap` (hosts on 192.0.2.0/24):

```bash
# Top talkers and conversations
tshark -r lab.pcap -q -z conv,ip

# Protocol hierarchy - what is actually in the capture
tshark -r lab.pcap -q -z io,phs

# Extract DNS queries (spot tunnelling by length/entropy)
tshark -r lab.pcap -Y dns.flags.response==0 -T fields -e dns.qry.name

# HTTP requests: method, host, URI, user-agent
tshark -r lab.pcap -Y http.request \
  -T fields -e ip.dst -e http.host -e http.request.uri -e http.user_agent
```

Generate Zeek logs for a structured, greppable view:

```bash
zeek -r lab.pcap

# Long-lived low-byte flows (possible beaconing)
cat conn.log | zeek-cut id.orig_h id.resp_h duration orig_bytes \
  | sort -k3 -n -r | head

# Rare destinations by connection count
cat conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -n | head
```

Checklist while analysing:

| Question | Where to look |
| --- | --- |
| Who are the top talkers? | `tshark -z conv,ip`, Zeek conn.log |
| What protocols are present? | `tshark -z io,phs` |
| Any beaconing rhythm? | conn.log duration + inter-arrival times |
| DNS/ICMP tunnelling? | query length, entropy, volume |
| Cleartext credentials? | http/ftp streams (lab only) |

## Lab

Isolated lab (host-only 192.0.2.0/24):

1. Capture traffic you generate between VMs you own (a web request, a DNS
   lookup, a simulated beacon).
2. Reproduce each command above and confirm you can identify the flow you
   created.
3. Build a short "normal vs anomalous" reference from your own captures to speed
   future triage.

## References

- Wireshark / tshark documentation - https://www.wireshark.org/docs/
- Zeek documentation - https://docs.zeek.org/
- MITRE ATT&CK (technique context) - https://attack.mitre.org/
- NIST SP 800-86 (Forensic Techniques) - https://csrc.nist.gov/

---

**Author:** Danny Stanfield
**License:** MIT
