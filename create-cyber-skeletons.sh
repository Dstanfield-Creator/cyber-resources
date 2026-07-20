#!/bin/bash

# Create skeleton files for Cyber Department topics
# Run this in your cyber-resources repo to generate markdown stubs

set -e

CYBER_TOPICS=(
  "Port Scanning"
  "Enumeration"
  "OSINT"
  "Service Discovery"
  "DNS Enumeration"
  "Web Application Enumeration"
  "Network Scanning"
  "Vulnerability Scanning"
  "Password Cracking"
  "Brute Force Attacks"
  "Social Engineering"
  "Phishing"
  "DDoS Attacks"
  "DoS Attacks"
  "Network Protocol Attacks"
  "Web Application Attacks"
  "SQL Injection"
  "Cross-Site Scripting"
  "Command Injection"
  "File Inclusion"
  "Authentication Bypass"
  "Privilege Escalation"
  "Lateral Movement"
  "Persistence"
  "Exfiltration"
  "C2 Communication"
  "Post-Exploitation"
  "Metasploit Framework"
  "Burp Suite"
  "Kali Linux"
  "Nmap"
  "Wireshark"
  "Hashcat"
  "John the Ripper"
  "Nikto"
  "SQLmap"
  "Hydra"
  "Aircrack-ng"
  "Mimikatz"
  "Reverse Shells"
  "Protocol Analysis"
  "Network Segmentation"
  "Firewall Configuration"
  "Intrusion Detection"
  "Log Analysis"
  "SIEM Configuration"
  "Incident Response"
  "Forensics"
  "Detection Engineering"
  "Honeypots"
  "Threat Hunting"
)

DOCS_DIR="./docs"
TECHNIQUES_DIR="./techniques"
TOOLS_DIR="./tools"
LABS_DIR="./labs"

# Create directories
mkdir -p "$DOCS_DIR" "$TECHNIQUES_DIR" "$TOOLS_DIR" "$LABS_DIR"

echo "📝 Creating skeleton files for Cyber Department topics..."
echo ""

for topic in "${CYBER_TOPICS[@]}"; do
  # Sanitize filename
  filename=$(echo "$topic" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/-+/-/g')
  
  # Choose directory based on topic
  if [[ "$topic" =~ (Metasploit|Burp|Kali|Nmap|Wireshark|Hashcat|John|Nikto|SQLmap|Hydra|Aircrack|Mimikatz|Framework) ]]; then
    DIR="$TOOLS_DIR"
  elif [[ "$topic" =~ (Scanning|Enumeration|OSINT|Discovery|Analysis|Cracking|Injection|Bypass|Exploitation|Exfiltration|Communication|Post-Exploitation|Shells) ]]; then
    DIR="$TECHNIQUES_DIR"
  else
    DIR="$DOCS_DIR"
  fi
  
  filepath="$DIR/${filename}.md"
  
  # Skip if file exists
  if [ -f "$filepath" ]; then
    echo "⏭️  Skip: $filename (already exists)"
    continue
  fi
  
  # Create skeleton
  cat > "$filepath" << EOF
# $topic

> **Status:** Skeleton — Content to be added from Confluence
> **Updated:** $(date +%Y-%m-%d)

## Overview

Add topic overview here.

## Prerequisites

- Item 1
- Item 2

## Key Concepts

- Concept 1
- Concept 2
- Concept 3

## Step-by-Step Guide

### Step 1: Setup
Description here

\`\`\`bash
# Commands here
\`\`\`

### Step 2: Execution
Description here

\`\`\`bash
# Commands here
\`\`\`

## Tools & Resources

- Tool 1: Description
- Tool 2: Description

## Lab Exercises

### Exercise 1: Basic
Hands-on practice scenario

### Exercise 2: Intermediate
More advanced practice

## Common Pitfalls

- Pitfall 1
- Pitfall 2

## References

- [OWASP](https://owasp.org)
- [HackTheBox Academy](https://academy.hackthebox.com)

---

**Author:** Danny Stanfield
**License:** MIT
EOF

  echo "✓ Created: $filename"
done

echo ""
echo "✅ Skeleton files created!"
echo ""
echo "Next steps:"
echo "  1. Review files in docs/, techniques/, tools/, labs/"
echo "  2. Copy content from your Confluence pages into these files"
echo "  3. Commit: git add . && git commit -m 'Add cyber topic skeletons'"
echo "  4. Push: git push"
echo ""
