#!/usr/bin/env python3
"""
Pull Cyber Department pages from Confluence and format for cyber-resources repo.

Usage:
    python3 pull-cyber-pages.py <page_id> [page_id] ...
    python3 pull-cyber-pages.py 557801 491972 590402

Requires:
    - requests library (pip install requests)
    - Access to your Confluence wiki
    - Page IDs from the Cyber Department index
"""

import sys
import os
import json
import re
import requests
from datetime import datetime

# Configuration
CONFLUENCE_CLOUD_ID = "nxdh.atlassian.net"
CONFLUENCE_URL = f"https://{CONFLUENCE_CLOUD_ID}/wiki"
API_ENDPOINT = f"{CONFLUENCE_URL}/rest/api/content"

# Note: You may need to add authentication here if your Confluence is private
# See: https://confluence.atlassian.com/doc/confluence-rest-api-examples-285217648.html

def sanitize_filename(title):
    """Convert title to valid markdown filename"""
    name = title.lower()
    name = re.sub(r'[^a-z0-9]+', '-', name)
    name = re.sub(r'-+', '-', name)
    name = name.strip('-')
    return name

def fetch_page(page_id):
    """Fetch a page from Confluence"""
    try:
        url = f"{API_ENDPOINT}/{page_id}"
        params = {
            'expand': 'body.storage,history',
        }
        
        print(f"  📡 Fetching page {page_id}...", end=' ', flush=True)
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        title = data.get('title', f'Page-{page_id}')
        body = data.get('body', {}).get('storage', {}).get('value', '')
        created = data.get('history', {}).get('createdDate', datetime.now().isoformat())
        
        print("✓")
        return {
            'id': page_id,
            'title': title,
            'body': body,
            'created': created,
            'url': f"{CONFLUENCE_URL}/pages/viewpage.action?pageId={page_id}"
        }
    except requests.exceptions.RequestException as e:
        print(f"✗ Error: {e}")
        return None

def create_markdown(page_data):
    """Convert Confluence page to Markdown"""
    title = page_data['title']
    page_id = page_data['id']
    url = page_data['url']
    
    # Create markdown skeleton
    md = f"""# {title}

> **Source:** [Confluence Page {page_id}]({url})
> **Created:** {page_data['created'][:10]}

## Overview

Add overview of this topic from the Confluence page.

## Key Concepts

- Concept 1
- Concept 2
- Concept 3

## Step-by-Step Guide

### Step 1
Description and commands

### Step 2
Description and commands

## Tools & Commands

```bash
# Common commands and tools
```

## Lab Exercises

### Exercise 1
Hands-on practice

## References

- Original Confluence page: {url}

---

**Author:** Danny Stanfield
**License:** MIT
**Last Updated:** {datetime.now().strftime('%Y-%m-%d')}
"""
    return md

def main():
    if len(sys.argv) < 2:
        print("Pull Cyber Department pages from Confluence")
        print("")
        print("Usage:")
        print("  python3 pull-cyber-pages.py <page_id> [page_id] ...")
        print("")
        print("Example:")
        print("  python3 pull-cyber-pages.py 557801 491972 590402")
        print("")
        print("Common Cyber Department Page IDs:")
        print("  557801  - Port Scanning")
        print("  491972  - Enumeration")
        print("  590402  - Cyber Tool (Networking)")
        print("  623567  - Exfiltration")
        print("  557764  - (Unnamed)")
        print("  491954  - Password Cracking")
        print("")
        print("Tip: Run without arguments to see this help.")
        sys.exit(0)
    
    page_ids = sys.argv[1:]
    output_dir = os.path.expanduser("~/repos/cyber-resources/docs")
    
    # Create output directory if needed
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\n🔄 Pulling {len(page_ids)} page(s) from Confluence...\n")
    
    created_files = []
    
    for page_id in page_ids:
        page_data = fetch_page(page_id)
        
        if page_data:
            markdown = create_markdown(page_data)
            filename = sanitize_filename(page_data['title'])
            filepath = os.path.join(output_dir, f"{filename}.md")
            
            # Avoid overwriting existing files
            if os.path.exists(filepath):
                base, ext = os.path.splitext(filepath)
                filepath = f"{base}_{page_id}{ext}"
            
            with open(filepath, 'w') as f:
                f.write(markdown)
            
            created_files.append(filepath)
            print(f"    ✓ Saved: {filename}.md")
    
    print(f"\n✅ Complete!")
    print(f"   Created {len(created_files)} file(s)")
    print(f"   Location: {output_dir}\n")
    print("Next steps:")
    print("  1. Review the created .md files")
    print("  2. Copy actual content from your Confluence wiki and paste into each file")
    print("  3. Run: cd ~/repos/cyber-resources && git add docs/ && git commit -m 'Add cyber topics'")
    print("  4. Push: git push\n")

if __name__ == '__main__':
    main()
