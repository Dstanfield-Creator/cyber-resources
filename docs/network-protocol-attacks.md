# Network Protocol Attacks

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Network protocol attacks abuse the trust and lack of authentication in core LAN protocols to intercept, redirect, or tamper with traffic. In ATT&CK these are **T1557 Adversary-in-the-Middle** (LLMNR/NBT-NS poisoning .001, ARP cache poisoning .002, DHCP spoofing .003), with **T1040 Network Sniffing** and **T1565 Data Manipulation** often following. The common theme is a local attacker positioning between hosts to capture credentials or alter data in transit.

## How It Works

Many Layer 2 and name-resolution protocols trust whatever answers first.

- **ARP cache poisoning:** forged ARP replies map the gateway's IP to the attacker's MAC, so traffic flows through them.
- **LLMNR/NBT-NS/mDNS poisoning:** when DNS fails, Windows falls back to these broadcast protocols; the attacker answers and collects NTLM authentication material.
- **DHCP spoofing:** a rogue DHCP server hands out the attacker's address as the default gateway or DNS.
- **DNS spoofing:** forged responses redirect names to attacker-controlled hosts.
- **Rogue router advertisements (IPv6):** unsolicited RAs insert the attacker into IPv6 routing.

Once positioned, the attacker sniffs credentials, relays authentication, or manipulates responses.

## Detect

Network and host telemetry both help; many of these are broadcast events visible to a sensor on the segment.

| Source | Signal |
| --- | --- |
| IDS / sensor | Multiple IPs claiming one MAC or multiple MACs for the gateway IP (ARP anomaly); gratuitous ARP bursts |
| Switch logs | Dynamic ARP Inspection and DHCP snooping violations; MAC flapping |
| DNS/name svc | LLMNR/NBT-NS (UDP 5355/137) responses on segments where they should be disabled |
| DHCP | DHCP OFFER from an unauthorised server MAC/IP |
| Host / Sysmon | New listener on 445 with inbound NTLM; unexpected gateway MAC change |

```yaml
title: Rogue DHCP Server - Unexpected OFFER Source
logsource:
  category: dhcp
detection:
  selection:
    message_type: 'DHCPOFFER'
  filter:
    server_ip:
      - '192.0.2.1'   # sanctioned DHCP server
  condition: selection and not filter
fields:
  - server_ip
  - server_mac
  - client_mac
falsepositives:
  - New sanctioned DHCP server not yet allow-listed
level: high
```

Alert on gateway MAC changes and on LLMNR/NBT-NS traffic where policy says it should be off.

## Mitigate

- Enable switch protections: Dynamic ARP Inspection, DHCP snooping, and port security to pin MAC/IP bindings.
- Disable LLMNR, NBT-NS, and mDNS where not required; prefer authenticated DNS.
- Use 802.1X / NAC to authenticate devices onto the network and block rogue ports.
- Enforce SMB signing and LDAP channel binding/signing to defeat NTLM relay; move to Kerberos and disable NTLM where feasible.
- RA Guard and DHCPv6 Guard for IPv6; segment and isolate sensitive subnets.
- Encrypt in transit (TLS, IPsec) so interception yields little.

## Lab

- Build an isolated switched segment (192.0.2.0/24) with a monitoring sensor and ship logs to your SIEM; keep it air-gapped from production.
- Using lab hosts you own, generate ARP-anomaly, rogue-DHCP, and LLMNR-response conditions and confirm your sensor and DHCP-snooping alerts fire.
- Enable DAI, DHCP snooping, SMB signing, and disable LLMNR, then re-test to confirm the attacks are blocked. Never run these on a network you do not control.

## References

- MITRE ATT&CK T1557 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
- MITRE ATT&CK T1040 Network Sniffing: https://attack.mitre.org/techniques/T1040/
- CISA Securing Network Infrastructure Devices: https://www.cisa.gov/news-events/news/securing-network-infrastructure-devices
- Microsoft - Mitigating NTLM Relay (SMB signing / channel binding): https://learn.microsoft.com/windows-server/security/

---

**Author:** Danny Stanfield
**License:** MIT
