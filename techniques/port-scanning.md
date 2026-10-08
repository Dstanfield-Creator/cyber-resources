# Host and Port Scanning

> **Status:** Reference
> **Updated:** 2026-01-30

## Overview

Understanding port scanning is essential for reconnaissance. This guide covers TCP/UDP port scanning techniques, interpreting scan results, and identifying service states.

## Port States

| **State** | **Description** |
| --- | --- |
| `open` | Connection established (TCP, UDP, SCTP) |
| `closed` | Port responds with RST flag |
| `filtered` | Cannot determine if open/closed |
| `unfiltered` | Port accessible, state unknown |
| `open\|filtered` | No response received |
| `closed\|filtered` | Cannot determine state |

## Discovering Open TCP Ports

### Scanning Top 10 TCP Ports

```bash
sudo nmap 10.129.2.28 --top-ports=10
```

## Port States and Responses

- **Open:** SYN-ACK response
- **Closed:** RST response
- **Filtered:** No response or ICMP error

## Common Nmap Options

| **Option** | **Description** |
| --- | --- |
| `-p <port>` | Specify ports |
| `--top-ports=<n>` | Scan top N ports |
| `-sT` | TCP Connect scan |
| `-sS` | TCP SYN scan |
| `-sU` | UDP scan |
| `-sV` | Service version detection |

---

**Author:** Danny Stanfield | **License:** MIT
