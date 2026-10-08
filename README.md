# Cyber Resources

> The Security Operations department of my GitHub: detection-as-code, the monitoring that feeds it, a 48-page technique and tool reference written from the defender's side, and the lab ranges it is all practised in.

**Status:** Active · **Updated:** 2026-10-08

## Structure

```
├── detections/          # Sigma rule library, mapped to MITRE ATT&CK, validated in CI
│   ├── rules/           #   windows, linux, network, web, cloud
│   └── docs/            #   testing workflow, Windows AD logging baseline
├── monitoring/          # Prometheus / Grafana stacks, node_exporter, MyDashboard design
│   ├── compose/         #   reference stack and the lab stack
│   ├── docs/            #   node_exporter setup
│   └── mydashboard/     #   lab health dashboard: data sources, panels, alert rules
├── docs/                # Defensive operations and attack write-ups
├── techniques/          # Attack techniques and how to detect them
├── tools/               # Tool guides
├── labs/                # Ludus AD cyber range, HackTheBox tracker
├── CONTRIBUTING.md      # Sanitisation rules
└── LICENSE
```

## Detections

**[detections/](./detections/)** - a version-controlled Sigma library for a home SOC lab. Every rule is a plain-text file reviewed in a pull request and structurally validated in CI before it ships to the SIEM.

- [Rules](./detections/rules/) - Windows (6), Linux (3), web (2), network (1), cloud (1)
- [How rules are tested](./detections/docs/testing.md) - from Ludus range to Sigma to SIEM
- [Windows AD logging baseline for detection](./detections/docs/windows-ad-logging-baseline-for-detection.md) - Advanced Audit Policy, Sysmon, forwarding, attack-to-event map

## Monitoring & Observability

**[monitoring/](./monitoring/)** - Prometheus, Grafana and alerts derived from real incidents.

- [MyDashboard](./monitoring/mydashboard/) - lab health dashboard design: data sources, panels, alert rules
- [Monitoring stack (Compose)](./monitoring/compose/monitoring-stack/) - Prometheus, Alertmanager, Grafana, node_exporter, cAdvisor, blackbox probes, starter alerts · [Lab monitoring (Compose)](./monitoring/compose/lab-monitoring/) - the stack deployed in the lab
- [Prometheus node_exporter setup](./monitoring/docs/prometheus-node-exporter-setup.md) - sandboxed unit, textfile collector, scrape config, PromQL

## Reference

- **Defensive operations** ([docs/](./docs/)): [Detection Engineering](./docs/detection-engineering.md) · [Threat Hunting](./docs/threat-hunting.md) · [Incident Response](./docs/incident-response.md) · [SIEM Configuration](./docs/siem-configuration.md) · [Intrusion Detection](./docs/intrusion-detection.md) · [Forensics](./docs/forensics.md) · [Honeypots](./docs/honeypots.md) · [Firewall Configuration](./docs/firewall-configuration.md) · [Network Segmentation](./docs/network-segmentation.md)
- **Attack write-ups** ([docs/](./docs/)): [Brute Force](./docs/brute-force-attacks.md) · [DoS](./docs/dos-attacks.md) · [DDoS](./docs/ddos-attacks.md) · [Phishing](./docs/phishing.md) · [Social Engineering](./docs/social-engineering.md) · [Lateral Movement](./docs/lateral-movement.md) · [Persistence](./docs/persistence.md) · [Privilege Escalation](./docs/privilege-escalation.md) · [Web Application Attacks](./docs/web-application-attacks.md) · [Cross-Site Scripting](./docs/cross-site-scripting.md) · [File Inclusion](./docs/file-inclusion.md) · [Network Protocol Attacks](./docs/network-protocol-attacks.md)
- **Techniques** ([techniques/](./techniques/)): [Enumeration](./techniques/enumeration.md) · [Port Scanning](./techniques/port-scanning.md) · [Network Scanning](./techniques/network-scanning.md) · [Service Discovery](./techniques/service-discovery.md) · [DNS Enumeration](./techniques/dns-enumeration.md) · [Web App Enumeration](./techniques/web-application-enumeration.md) · [Vulnerability Scanning](./techniques/vulnerability-scanning.md) · [OSINT](./techniques/osint.md) · [Online Password Attacks](./techniques/password-attacks-online.md) · [Password Cracking](./techniques/password-cracking.md) · [Authentication Bypass](./techniques/authentication-bypass.md) · [SQL Injection](./techniques/sql-injection.md) · [Command Injection](./techniques/command-injection.md) · [Reverse Shells](./techniques/reverse-shells.md) · [Post-Exploitation](./techniques/post-exploitation.md) · [C2 Communication](./techniques/c2-communication.md) · [Exfiltration](./techniques/exfiltration.md) · [Protocol Analysis](./techniques/protocol-analysis.md) · [Log Analysis](./techniques/log-analysis.md) · [Social Engineering](./techniques/social-engineering.md)
- **Tools** ([tools/](./tools/)): [Nmap](./tools/nmap.md) · [Wireshark](./tools/wireshark.md) · [Burp Suite](./tools/burp-suite.md) · [Metasploit](./tools/metasploit-framework.md) · [sqlmap](./tools/sqlmap.md) · [Nikto](./tools/nikto.md) · [Hydra](./tools/hydra.md) · [Hashcat](./tools/hashcat.md) · [John the Ripper](./tools/john-the-ripper.md) · [Mimikatz](./tools/mimikatz.md) · [Aircrack-ng](./tools/aircrack-ng.md) · [Kali Linux](./tools/kali-linux.md)

## Labs

- [Ludus Cyber Range](./labs/ludus-cyber-range/) - reproducible AD attack / detection range on Proxmox: router, Server 2022 DC, Win 11 workstation, Kali
- [HackTheBox tracker](./labs/htb/README.md) · [write-up template](./labs/htb/_template.md)

## Conventions

Real IPs, MACs, usernames, tailnet names and secrets are replaced with documentation placeholders (RFC 5737 `192.0.2.0/24`, `example.ts.net`). HTB flags are never published. See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

**Author:** Danny Stanfield · Perth, WA  
**License:** MIT
