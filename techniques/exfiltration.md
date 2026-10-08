# Exfiltration

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Exfiltration is the theft of data out of a victim environment. It is often the
objective of an intrusion and the last chance to intervene before damage is
done. Defenders detect it through egress volume anomalies, destination analysis
and data-aware controls (DLP), focusing on where large or sensitive data leaves.

Relevant MITRE ATT&CK techniques:

| ID | Name |
| --- | --- |
| T1041 | Exfiltration Over C2 Channel |
| T1048 | Exfiltration Over Alternative Protocol |
| T1567 | Exfiltration Over Web Service |
| T1030 | Data Transfer Size Limits |

## How It Works

After collecting and often staging/compressing data, the actor moves it out via:

- **The existing C2 channel** (T1041) - blends with command traffic.
- **Alternative protocols** (T1048) - DNS, ICMP, FTP, SMTP tunnelling.
- **Web services** (T1567) - cloud storage, paste sites, code repositories.
- **Chunking** (T1030) - splitting transfers to stay under alerting thresholds.

Signals include outbound volume spikes, large uploads to unusual destinations,
and encoded data inside DNS or ICMP.

## Detect

Log sources and signals:

| Source | Signal |
| --- | --- |
| NetFlow / Zeek conn.log | Outbound byte spikes, asymmetric upload volume |
| Proxy / cloud access logs | Large uploads to personal or unknown storage |
| DNS logs | Oversized / high-entropy TXT or subdomain queries |
| DLP / CASB | Sensitive-data patterns leaving the boundary |

```yaml
title: Large Outbound Transfer To Rare Destination
logsource:
    category: firewall
detection:
    selection:
        direction: outbound
    timeframe: 10m
    condition: selection | sum(bytes_out) by src_ip, dst_ip > 500000000
falsepositives:
    - Backups, software distribution and sanctioned cloud sync
level: medium
```

For DNS/ICMP tunnelling, alert on abnormal query length, high subdomain entropy,
and sustained request rates to one domain. Baseline normal egress per host.

## Mitigate

- Deploy DLP/CASB to inspect and control sensitive-data egress.
- Allowlist sanctioned cloud destinations; block personal file-sharing.
- Constrain outbound DNS and ICMP; inspect for tunnelling.
- Egress filtering and proxy enforcement for all outbound traffic.
- Encrypt and tightly access-control data at rest to reduce what can be collected.

## Lab

Isolated lab (host-only 192.0.2.0/24, no internet):

1. Transfer a benign marker dataset between two VMs you own over HTTP and over a
   DNS-style channel.
2. Confirm the volume spike and the DNS anomaly are both visible in your logs and
   trigger the relevant detections.
3. Apply egress filtering and re-test which channels are now blocked.

## References

- MITRE ATT&CK Exfiltration (TA0010) - https://attack.mitre.org/tactics/TA0010/
- MITRE ATT&CK T1048 - https://attack.mitre.org/techniques/T1048/
- MITRE ATT&CK T1567 - https://attack.mitre.org/techniques/T1567/
- NIST SP 800-137 (Continuous Monitoring) - https://csrc.nist.gov/

---

**Author:** Danny Stanfield
**License:** MIT
