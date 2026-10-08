# Wireshark

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Wireshark is an open-source network protocol analyser. It captures frames
off an interface and decodes them across hundreds of protocols, letting
an analyst inspect traffic packet by packet. In a lab it is the primary
tool for understanding what other tools put on the wire: you run a scan
or an attack in one window and watch the exact packets in Wireshark in
another. For defenders it is a core investigation tool for reconstructing
sessions from a packet capture.

## Install

| Platform | Command |
| --- | --- |
| Debian/Kali | `sudo apt install wireshark` |
| RHEL/Fedora | `sudo dnf install wireshark` |
| macOS | `brew install --cask wireshark` |
| Source | https://www.wireshark.org/download.html |

On Linux, add your user to the `wireshark` group so dumpcap can capture
without root. `tshark` is the command-line sibling and ships in the same
package.

## Common Usage

```bash
# List capture interfaces
tshark -D

# Capture on eth0, write to a file
sudo tshark -i eth0 -w lab.pcapng

# Read a capture and filter to one lab host
tshark -r lab.pcapng -Y "ip.addr == 192.0.2.10"

# Show only DNS queries
tshark -r lab.pcapng -Y "dns.flags.response == 0"

# Follow a TCP stream by index
tshark -r lab.pcapng -z follow,tcp,ascii,0
```

Common display filters in the GUI:

| Filter | Shows |
| --- | --- |
| `http.request` | Outbound HTTP requests |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN packets (scan hunting) |
| `tls.handshake.type == 1` | TLS client hellos |
| `ip.addr == 192.0.2.10 && tcp.port == 445` | SMB to one host |

## Detect

Wireshark is a passive capture tool, so on a switched network it normally
generates no traffic of its own and is not detectable on the wire the way
an active scanner is. The defensive angle is different.

- **Promiscuous/monitor mode:** an interface in promiscuous mode may be
  flagged by host monitoring; some legacy ARP-based techniques probe for
  sniffers, but these are unreliable on modern switches.
- **Capture infrastructure:** legitimate capture relies on a SPAN/mirror
  port or a TAP. Unexpected use of these, or an unknown host suddenly
  receiving mirrored traffic, is the real signal.
- **Host artefacts:** presence of `dumpcap`/`tshark` processes, new
  `.pcap`/`.pcapng` files, and Npcap driver installs on Windows (Sysmon
  Event ID 1 process create, Event ID 11 file create).

```yaml
title: Packet Capture Tool Execution
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\dumpcap.exe'
      - '\tshark.exe'
      - '\Wireshark.exe'
  condition: selection
level: low
```

## References

- Official docs: https://www.wireshark.org/docs/
- Display filter reference: https://www.wireshark.org/docs/dfref/
- MITRE ATT&CK: T1040 Network Sniffing

---

**Author:** Danny Stanfield
**License:** MIT
