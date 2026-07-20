# Open-Source Intelligence (OSINT)

> **Source:** Confluence Page 492152
> **Updated:** 2026-01-30

## Overview

OSINT finds publicly available information to reveal events, dependencies, connections, and sensitive data.

## Critical Security Gaps

Attackers find:
- Passwords (hardcoded in code)
- Hashes (from breached databases)
- SSH/API Keys (in public repos)
- Tokens (in documentation)
- Credentials (GitHub, StackOverflow)

## Common Sources

- GitHub, GitLab, Bitbucket
- StackOverflow (code with credentials)
- SearchCode (public code search)
- WHOIS, DNS records
- Certificate transparency logs

## SSH Keys Risk

Private SSH keys found in:
- Public GitHub repos
- Backup files
- Docker images
- Config files

**If exposed, revoke immediately.**

## Defense

- Scan repos for secrets
- Use secret scanning tools
- Implement .gitignore properly
- Train developers on security
- Rotate exposed credentials
- Remove commits with secrets
- Use environment variables

---

**Author:** Danny Stanfield | **License:** MIT
