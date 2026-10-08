# <Machine Name>

> **Status:** Not Started
> **Updated:** YYYY-MM-DD

## Info

- **Platform:** HackTheBox
- **OS:** Linux / Windows
- **Difficulty:** Easy / Medium / Hard / Insane
- **IP:** 10.10.11.x
- **Started:** YYYY-MM-DD
- **Completed:** YYYY-MM-DD

## Summary

One or two sentence recap of the box and the overall attack chain.

## Recon

### Port Scan

```bash
nmap -sC -sV -oA ~/htb/boxes/<machine>/scans/initial <ip>
```

| Port | Service | Version | Notes |
| --- | --- | --- | --- |
|  |  |  |  |

### Service Enumeration

One subsection per service (web dirs/vhosts, SMB shares, etc.).

## Foothold

Vulnerability / exploit / credentials used to get initial access, with the exact commands.

## User Flag

```
***REDACTED***
```

## Privilege Escalation

Enumeration path to root/SYSTEM, findings, exploitation steps.

## Root Flag

```
***REDACTED***
```

## Lessons Learned

-
-

## Commands Reference

Cheat-sheet of commands used on this box (cross-link `/tools/*.md` where relevant, e.g. [nmap.md](../../tools/nmap.md)).

## References

- [HackTheBox Academy](https://academy.hackthebox.com)

---

**Author:** Danny Stanfield
**License:** MIT
