# Aircrack-ng

> **Status:** Reference
> **Updated:** 2026-10-08

## Overview

Aircrack-ng is an open-source suite for assessing Wi-Fi network security.
It covers monitoring (capturing 802.11 frames), attacking (deauth and
replay), testing adapter capabilities, and cracking WEP/WPA-PSK keys from
captured handshakes. In a lab with your own access point it is used to
understand wireless weaknesses and, for this reference, the telemetry a
wireless defender watches. Usage stays lab-scoped against hardware you
own.

## Install

| Method | Source |
| --- | --- |
| Kali package | `sudo apt install aircrack-ng` |
| Source | https://www.aircrack-ng.org/ |
| Needs | An adapter that supports monitor mode and injection |

## Common Usage

Only ever test your own lab access point. The core suite components:

```bash
# Put the adapter into monitor mode
sudo airmon-ng start wlan0

# Survey nearby networks (your own lab AP)
sudo airodump-ng wlan0mon

# Capture frames for one lab BSSID/channel to a file
sudo airodump-ng -c 6 --bssid 02:00:5E:10:00:01 -w lab wlan0mon

# Crack a captured WPA handshake with a lab wordlist
aircrack-ng -w lab-words.txt lab-01.cap
```

| Tool | Role |
| --- | --- |
| `airmon-ng` | Enable/disable monitor mode |
| `airodump-ng` | Capture and survey |
| `aireplay-ng` | Inject/replay (e.g. deauth) |
| `aircrack-ng` | Offline key cracking |

## Detect

Wireless attacks are visible to anyone monitoring the RF environment and
to a wireless IDS (WIDS).

- **Deauthentication floods:** `aireplay-ng` deauth sends many 802.11
  deauth/disassoc management frames; a WIDS (or a controller such as
  those from Aruba, Meraki, or Ubiquiti) flags bursts of deauth from one
  source as a classic attack signature.
- **Monitor mode / rogue capture:** adapters in monitor mode do not
  associate; unexpected probe patterns and unassociated capture are noted
  by managed WLAN infrastructure.
- **Handshake harvesting:** forced client reconnects (deauth then
  re-auth) appear as repeated association churn in AP logs.

```yaml
title: 802.11 Deauthentication Flood
logsource:
  product: wids
  category: wireless
detection:
  selection:
    frame.type: management
    frame.subtype: deauthentication
  timeframe: 10s
  condition: selection | count() by src_mac > 30
level: medium
```

Tuning note: a few deauths are normal; alert on sustained floods and on
deauths that spoof the AP's own BSSID.

## References

- Official site: https://www.aircrack-ng.org/
- Documentation: https://www.aircrack-ng.org/documentation.html
- MITRE ATT&CK: T1557 Adversary-in-the-Middle; T1040 Network Sniffing

---

**Author:** Danny Stanfield
**License:** MIT
