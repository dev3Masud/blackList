#!/usr/bin/env python3
import os
import re
import sys
import json
import yaml
from datetime import datetime, timezone

# Regex patterns for domains and IP validation
DOMAIN_REGEX = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$',
    re.IGNORECASE
)
IP_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

def load_config(config_path="config.yaml"):
    """Loads config.yaml safely."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[-] Error loading configuration: {e}")
        sys.exit(1)

def load_whitelist(whitelist_path="whitelist.txt"):
    """Loads whitelist.txt, ignoring comments and empty lines."""
    whitelist = set()
    if not os.path.exists(whitelist_path):
        print(f"[!] Whitelist file {whitelist_path} not found. Proceeding with empty whitelist.")
        return whitelist

    with open(whitelist_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            whitelist.add(line.lower())
    print(f"[+] Loaded {len(whitelist)} whitelisted domains/rules.")
    return whitelist

def is_whitelisted(domain, whitelist):
    """Checks if a domain or its parent domains are whitelisted."""
    domain_lower = domain.lower()
    # Direct match
    if domain_lower in whitelist:
        return True
    
    # Subdomain check (e.g. if google.com is whitelisted, match api.google.com)
    parts = domain_lower.split('.')
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        if parent in whitelist:
            return True
            
    return False

def minimize_domains(domains):
    """
    Removes redundant subdomains if their parent domain is already in the list.
    E.g. if 'example.com' is in the list, 'sub.example.com' is removed.
    """
    # Convert to tuples of reversed parts
    tuples = [tuple(reversed(d.split('.'))) for d in domains]
    tuples.sort()
    
    minimized = []
    last_kept = None
    for t in tuples:
        if last_kept and len(t) > len(last_kept) and t[:len(last_kept)] == last_kept:
            # This is a subdomain of last_kept, skip it
            continue
        minimized.append('.'.join(reversed(t)))
        last_kept = t
    return minimized

def save_variant(variant_name, categories_list, category_domains, category_uncapped_counts, base_path="variants"):
    """Combines specified categories and saves them under base_path/variant_name/."""
    variant_domains = set()
    for cat in categories_list:
        if cat in category_domains:
            variant_domains.update(category_domains[cat])
            
    domains_list = sorted(list(variant_domains))
        
    variant_dir = os.path.join(base_path, variant_name)
    os.makedirs(variant_dir, exist_ok=True)
    
    # 1. Write domains.txt
    with open(os.path.join(variant_dir, "domains.txt"), "w") as f:
        f.write(f"# Compiled Blacklist Variant - {variant_name.upper()}\n")
        f.write(f"# Total Domains: {len(domains_list)}\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write("\n".join(domains_list))
        
    # 2. Write hosts.txt
    with open(os.path.join(variant_dir, "hosts.txt"), "w") as f:
        f.write(f"# Compiled Blacklist Variant (Hosts format) - {variant_name.upper()}\n")
        f.write(f"# Total Domains: {len(domains_list)}\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        for d in domains_list:
            f.write(f"0.0.0.0 {d}\n")
            
    # 3. Write adblock.txt
    with open(os.path.join(variant_dir, "adblock.txt"), "w") as f:
        f.write(f"! Compiled Blacklist Variant (Adblock format) - {variant_name.upper()}\n")
        f.write(f"! Total Domains: {len(domains_list)}\n")
        f.write(f"! Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        for d in domains_list:
            f.write(f"||{d}^\n")
            
    write_variant_readme(variant_name, len(domains_list), categories_list, category_domains, category_uncapped_counts, base_path)
    write_variant_html(variant_name, len(domains_list), categories_list, category_domains, category_uncapped_counts, base_path)
    print(f"[+] Saved {base_path} variant '{variant_name}' ({len(domains_list)} domains) to {variant_dir}")

category_details = {
    "cryptomining": ("Cryptomining", "Cryptojacking scripts, browser miners, and pool connection endpoints."),
    "malware": ("Malware Sites", "Command & control servers, distribution endpoints, ransomware, and spyware platforms."),
    "phishing": ("Phishing Pages", "Fraudulent login pages, credential harvesting forms, and identity spoofing sites."),
    "ads": ("Advertising Domains", "Ad delivery networks, promotional servers, and banner scripting endpoints."),
    "tracking": ("Tracking & Telemetry", "Analytics scripts, user profiling telemetry, and commercial data harvesting domains."),
    "spam": ("Spam & Scam Domains", "Malicious email redirectors, lottery scam landing pages, and deceptive bulk sites."),
    "dating": ("Dating Portals", "Matchmaking platforms, hookup sites, and related relationship portals."),
    "social": ("Social Tracking", "Social networking trackers, widgets, and domain collectors that profile user browsing."),
    "gambling": ("Gambling & Casinos", "Online betting sites, slot machines, lottery portals, and digital casinos."),
    "torrent": ("Torrent & P2P", "BitTorrent trackers, magnet index sites, piracy portals, and peer communication networks."),
    "crawled": ("Scrapers & Crawlers", "Suspicious automated scraper bots, web scanner networks, and scraping systems."),
    "nsfw": ("NSFW (Adult) Content", "Pornography, adult video portals, online dating platforms, and age-restricted domains.")
}

variant_categories = {
    "lite": ["malware", "phishing", "cryptomining"],
    "medium": ["malware", "phishing", "cryptomining", "ads", "tracking", "spam"],
    "high": ["malware", "phishing", "cryptomining", "ads", "tracking", "spam", "dating", "social", "gambling", "torrent", "crawled"],
    "nsfw": ["nsfw"],
    "adblock": ["malware", "phishing", "cryptomining", "ads", "tracking", "spam", "dating", "social", "gambling", "torrent", "crawled", "nsfw"]
}

def write_variant_readme(variant_name, count, categories_list, category_domains, category_uncapped_counts, base_path="variants"):
    """Writes a beautiful README.md for the specific variant/alternate folder detailing categories."""
    descriptions = {
        "lite": "Designed for maximum speed and stability. Targets high-severity security threats like malware, phishing, and cryptomining. Near-zero false positives.",
        "medium": "Balanced protection and usability. Blocks security threats, ads, trackers, and spam domains. Recommended for standard home networks.",
        "high": "Maximum security ruleset. Blocks ads, trackers, malware, spam, dating, social tracking, gambling, and torrent networks. May block some web features.",
        "nsfw": "Dedicated blocklist for filtering adult content, pornography, and age-restricted domains. Ideal for parental controls.",
        "adblock": "Optimized ruleset formatted for browser extensions (uBlock Origin, AdGuard). Supports cosmetic and network blocking."
    }
    
    desc = descriptions.get(variant_name, f"Alternate blocklist configuration. Combines the base security blocklist with: {', '.join(categories_list)}.")
    
    cat_rows = ""
    for c in categories_list:
        title, d_desc = category_details.get(c, (c, ""))
        c_count = len(category_domains.get(c, []))
        cat_rows += f"| 🔴 **{title}** | `{c_count:,}` | {d_desc} |\n"

    title_str = f"Alternate: {variant_name}" if base_path == "alternates" else f"{variant_name.capitalize()} Variant"

    readme_content = f"""# 🛡️ blackList - {title_str}

This directory contains the compiled **{variant_name}** blocklist.

*   **Status**: Active
*   **Total blocked domains**: `{count:,}`
*   **Target audience**: {desc}

---

## 📦 Blocked Categories & Domain Types

This configuration contains lists designed to block the following domain categories:

| Category | Blocked Domains | Description |
| -------- | --------------- | ----------- |
{cat_rows}
---

## 🚀 How to Use

Select your preferred format below to load into your adblocker:

| Format | File Link | Description |
| ------ | --------- | ----------- |
| **Domains List** | [domains.txt](domains.txt) | Pure list of domains (best for custom scripts) |
| **Hosts Format** | [hosts.txt](hosts.txt) | Standard hosts file (0.0.0.0 format) |
| **Adblock Syntax** | [adblock.txt](adblock.txt) | Wildcard syntax (`||domain.com^`) |

---

## ⚙️ Setup Instructions

### 1. Pi-hole (DNS Resolver)
1. Copy the raw link to the **`domains.txt`** file above.
2. Go to your Pi-hole admin panel.
3. Navigate to **Group Management** -> **Adlists**.
4. Paste the URL and click **Add**.

### 2. AdGuard Home
1. Copy the raw link to the **`hosts.txt`** file above.
2. Go to AdGuard Home -> **Filters** -> **DNS blocklists**.
3. Click **Add blocklist** -> **Add custom list**.
4. Paste the URL and save.

### 3. Browser Adblockers (uBlock Origin / AdGuard Extension)
1. Copy the raw link to the **`adblock.txt`** file above.
2. Open your extension settings page.
3. Go to the **Filter Lists** tab.
4. Scroll to the bottom, check **Import**, paste the URL, and click **Apply changes**.

---
*Maintained and auto-updated daily by the [blackList pipeline](https://github.com/dev3Masud/blackList).*
"""
    readme_path = os.path.join(base_path, variant_name, "README.md")
    with open(readme_path, "w") as f:
        f.write(readme_content)

def write_variant_html(variant_name, count, categories_list, category_domains, category_uncapped_counts, base_path="variants"):
    """Writes a beautiful, dark-mode self-contained index.html for each variant folder."""
    descriptions = {
        "lite": "Designed for maximum speed and stability. Targets high-severity security threats like malware, phishing, and cryptomining. Near-zero false positives.",
        "medium": "Balanced protection and usability. Blocks security threats, ads, trackers, and spam domains. Recommended for standard home networks.",
        "high": "Maximum security ruleset. Blocks ads, trackers, malware, spam, dating, social tracking, gambling, and torrent networks. May block some web features.",
        "nsfw": "Dedicated blocklist for filtering adult content, pornography, and age-restricted domains. Ideal for parental controls.",
        "adblock": "Optimized ruleset formatted for browser extensions (uBlock Origin, AdGuard). Supports cosmetic and network blocking."
    }
    
    desc = descriptions.get(variant_name, f"Alternate blocklist configuration. Combines the base security blocklist with: {', '.join(categories_list)}.")
    
    cat_html = ""
    for c in categories_list:
        title, d_desc = category_details.get(c, (c, ""))
        c_count = len(category_domains.get(c, []))
        cat_html += f"""
        <div class="category-item">
          <div style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
            <span class="category-tag">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line></svg>
              {title}
            </span>
            <span style="font-family: var(--font-mono); font-size: 0.85rem; font-weight: 700; background: rgba(244, 63, 94, 0.15); color: var(--danger-color); padding: 0.15rem 0.5rem; border-radius: 6px;">
              {c_count:,}
            </span>
          </div>
          <span class="category-desc">{d_desc}</span>
        </div>"""

    title_str = f"Alternate: {variant_name}" if base_path == "alternates" else f"{variant_name.capitalize()} Variant"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>blackList - {title_str}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
    
    :root {{
      --font-sans: 'Plus Jakarta Sans', sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
      --bg-primary: #08090d;
      --bg-secondary: #0f111a;
      --accent-primary: #4f46e5;
      --accent-secondary: #06b6d4;
      --success-color: #10b981;
      --danger-color: #f43f5e;
      --glass-bg: rgba(15, 17, 26, 0.55);
      --glass-border: rgba(255, 255, 255, 0.06);
      --glass-border-hover: rgba(255, 255, 255, 0.12);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    
    body {{
      background-color: var(--bg-primary);
      color: var(--text-primary);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.6;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 3rem 1.5rem;
      overflow-x: hidden;
    }}

    /* Glowing Backdrop */
    .bg-glow {{
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      z-index: -1;
      overflow: hidden;
      pointer-events: none;
    }}

    .blob {{
      position: absolute;
      width: 500px;
      height: 500px;
      border-radius: 50%;
      filter: blur(130px);
      opacity: 0.1;
    }}

    .blob-1 {{
      top: -10%;
      right: 10%;
      background: var(--accent-primary);
    }}

    .blob-2 {{
      bottom: -10%;
      left: 10%;
      background: var(--accent-secondary);
    }}

    .container {{
      max-width: 800px;
      width: 100%;
    }}

    /* Back link */
    .back-link {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--text-secondary);
      text-decoration: none;
      font-weight: 600;
      font-size: 0.9rem;
      margin-bottom: 1.5rem;
      transition: all 0.2s ease;
    }}

    .back-link:hover {{
      color: var(--text-primary);
      transform: translateX(-4px);
    }}

    /* Glass Card layout */
    .glass-card {{
      background: var(--glass-bg);
      border: 1px solid var(--glass-border);
      border-radius: 20px;
      padding: 2.5rem;
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.35);
      margin-bottom: 2rem;
    }}

    h1 {{
      font-size: 2.25rem;
      font-weight: 800;
      letter-spacing: -0.5px;
      margin-bottom: 0.5rem;
      background: linear-gradient(135deg, var(--text-primary) 30%, var(--accent-secondary) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}

    .meta-list {{
      list-style: none;
      margin: 1.5rem 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }}

    .meta-list li {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--text-secondary);
      font-size: 0.95rem;
    }}

    .meta-list strong {{
      color: var(--text-primary);
    }}

    .badge {{
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.28);
      color: var(--success-color);
      padding: 0.15rem 0.6rem;
      border-radius: 20px;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}

    .desc {{
      color: var(--text-secondary);
      margin-bottom: 2rem;
    }}

    h2 {{
      font-size: 1.4rem;
      font-weight: 700;
      margin: 2.5rem 0 1rem;
      border-bottom: 1px solid var(--glass-border);
      padding-bottom: 0.5rem;
    }}

    /* Category lists */
    .category-list {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 1rem;
      margin: 1.5rem 0;
    }}
    @media (min-width: 600px) {{
      .category-list {{
        grid-template-columns: 1fr 1fr;
      }}
    }}
    .category-item {{
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--glass-border);
      border-radius: 12px;
      padding: 1.1rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      transition: all 0.3s ease;
    }}
    .category-item:hover {{
      background: rgba(255, 255, 255, 0.04);
      border-color: var(--accent-secondary);
    }}
    .category-tag {{
      font-weight: 700;
      color: var(--text-primary);
      font-size: 0.95rem;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }}
    .category-desc {{
      color: var(--text-secondary);
      font-size: 0.85rem;
    }}

    /* Downloads Table */
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 1rem 0;
      border: 1px solid var(--glass-border);
      border-radius: 12px;
      overflow: hidden;
      background: rgba(10, 11, 16, 0.3);
    }}

    th, td {{
      padding: 1rem;
      text-align: left;
      border-bottom: 1px solid var(--glass-border);
    }}

    th {{
      background: rgba(0, 0, 0, 0.2);
      color: var(--text-secondary);
      font-size: 0.8rem;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}

    td {{
      font-size: 0.95rem;
    }}

    .file-name {{
      font-weight: 700;
      font-family: var(--font-mono);
      color: var(--accent-secondary);
    }}

    /* Copy Button & Icons */
    .action-row {{
      display: flex;
      gap: 0.5rem;
    }}

    .btn-icon {{
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--glass-border);
      color: var(--text-secondary);
      width: 34px;
      height: 34px;
      border-radius: 8px;
      cursor: pointer;
      display: inline-flex;
      justify-content: center;
      align-items: center;
      transition: all 0.2s ease;
      text-decoration: none;
    }}

    .btn-icon:hover {{
      background: rgba(255, 255, 255, 0.08);
      border-color: var(--glass-border-hover);
      color: var(--text-primary);
    }}

    .copy-success {{
      background: rgba(16, 185, 129, 0.08) !important;
      color: var(--success-color) !important;
      border-color: var(--success-color) !important;
    }}

    /* Setup/Config Info */
    .setup-desc {{
      color: var(--text-secondary);
      font-size: 0.95rem;
      margin-bottom: 1.5rem;
    }}

    /* Instructions formatting */
    ol {{
      margin: 1rem 0 1.5rem 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }}

    li {{
      font-size: 0.95rem;
      color: var(--text-secondary);
    }}

    code {{
      font-family: var(--font-mono);
      background: rgba(255, 255, 255, 0.05);
      padding: 0.1rem 0.3rem;
      border-radius: 4px;
      font-size: 0.9rem;
      color: var(--text-primary);
    }}

    footer {{
      margin-top: 5rem;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.85rem;
      border-top: 1px solid var(--glass-border);
      padding-top: 2rem;
    }}

    footer a {{
      color: var(--accent-secondary);
      text-decoration: none;
    }}
  </style>
</head>
<body>

  <div class="bg-glow" aria-hidden="true">
    <div class="blob blob-1"></div>
    <div class="blob blob-2"></div>
  </div>

  <div class="container">
    
    <a href="../../" class="back-link">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
      <span>Back to Registry</span>
    </a>

    <main class="glass-card">
      <h1>🛡️ blackList - {title_str}</h1>
      
      <ul class="meta-list">
        <li>Status: <span class="badge">ACTIVE</span></li>
        <li>Blocked Domains: <strong>{count:,}</strong></li>
      </ul>

      <p class="desc">{desc}</p>

      <h2>📦 Blocked Categories & Domain Types</h2>
      <div class="category-list">
        {cat_html}
      </div>

      <h2>🚀 Compile Formats</h2>
      <table>
        <thead>
          <tr>
            <th>Format</th>
            <th>Description</th>
            <th style="width: 100px;">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><span class="file-name">domains.txt</span></td>
            <td style="color: var(--text-secondary);">Plaintext raw domains list</td>
            <td>
              <div class="action-row">
                <button class="btn-icon" onclick="copyText('domains.txt')" title="Copy URL">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
                <a href="domains.txt" class="btn-icon" download title="Download">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                </a>
              </div>
            </td>
          </tr>
          <tr>
            <td><span class="file-name">hosts.txt</span></td>
            <td style="color: var(--text-secondary);">Hosts file mapping (0.0.0.0 target)</td>
            <td>
              <div class="action-row">
                <button class="btn-icon" onclick="copyText('hosts.txt')" title="Copy URL">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
                <a href="hosts.txt" class="btn-icon" download title="Download">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                </a>
              </div>
            </td>
          </tr>
          <tr>
            <td><span class="file-name">adblock.txt</span></td>
            <td style="color: var(--text-secondary);">AdBlock syntax filter rules</td>
            <td>
              <div class="action-row">
                <button class="btn-icon" onclick="copyText('adblock.txt')" title="Copy URL">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
                <a href="adblock.txt" class="btn-icon" download title="Download">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                </a>
              </div>
            </td>
          </tr>
        </tbody>
      </table>

      <h2>⚙️ Setup Instructions</h2>

      <h3>1. Pi-hole (DNS Resolver)</h3>
      <ol>
        <li>Click the copy button next to <code>domains.txt</code> above to copy the absolute link.</li>
        <li>Go to your Pi-hole admin console.</li>
        <li>Navigate to <strong>Group Management</strong> -> <strong>Adlists</strong>.</li>
        <li>Paste the copied URL under Address and click <strong>Add</strong>.</li>
      </ol>

      <h3>2. AdGuard Home</h3>
      <ol>
        <li>Click the copy button next to <code>hosts.txt</code> above.</li>
        <li>Open AdGuard Home dashboard and navigate to <strong>Filters</strong> -> <strong>DNS Blocklists</strong>.</li>
        <li>Click <strong>Add Blocklist</strong> -> <strong>Add a custom list</strong>.</li>
        <li>Paste the copied URL under list URL, give it a name, and save.</li>
      </ol>

      <h3>3. Browser Adblockers (uBlock Origin / AdGuard Extension)</h3>
      <ol>
        <li>Copy the link to <code>adblock.txt</code> above.</li>
        <li>Open the extension settings and go to the <strong>Filter Lists</strong> (or My Filters) tab.</li>
        <li>Scroll down, check <strong>Import</strong> under custom lists, paste the URL, and click <strong>Apply Changes</strong>.</li>
      </ol>

    </main>

    <footer>
      <p>Pipeline compiled and auto-updated daily via GitHub Actions.</p>
      <p style="margin-top: 6px; font-size: 0.8rem; color: var(--text-muted);">
        Maintained by <a href="https://github.com/dev3Masud" target="_blank">dev3Masud</a> &bull; 
        <a href="https://github.com/dev3Masud/blackList" target="_blank">GitHub Repository</a>
      </p>
    </footer>

  </div>

  <script>
    function copyText(subpath) {{
      const absoluteUrl = window.location.origin + window.location.pathname + subpath;
      
      navigator.clipboard.writeText(absoluteUrl).then(() => {{
        const btn = event.currentTarget;
        const originalContent = btn.innerHTML;
        
        btn.innerHTML = `
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
        `;
        btn.classList.add("copy-success");
        
        setTimeout(() => {{
          btn.innerHTML = originalContent;
          btn.classList.remove("copy-success");
        }}, 1500);
      }}).catch(err => {{
        console.error("Could not copy URL:", err);
      }});
    }}
  </script>
</body>
</html>
"""
    html_path = os.path.join(base_path, variant_name, "index.html")
    with open(html_path, "w") as f:
        f.write(html_content)

def main():
    print("=== Step 2: Blacklist Domain Validator Start ===")
    config = load_config()
    whitelist = load_whitelist(config.get("whitelist_file", "whitelist.txt"))

    raw_dir = "raw"
    categories_dir = config.get("outputs", {}).get("categories_dir", "categories")
    master_dir = config.get("outputs", {}).get("master_dir", "master")
    stats_file = config.get("outputs", {}).get("stats_file", "stats.json")

    # Ensure output directories exist
    os.makedirs(categories_dir, exist_ok=True)
    os.makedirs(master_dir, exist_ok=True)

    if not os.path.exists(raw_dir):
        print(f"[-] Raw directory '{raw_dir}' not found! Run the crawler first.")
        sys.exit(1)

    # Dictionary to hold domain sets per category
    category_domains = {}
    category_uncapped_counts = {}
    
    # Read raw files
    raw_files = [f for f in os.listdir(raw_dir) if f.endswith(".txt")]
    print(f"[*] Found {len(raw_files)} raw category files.")

    for f_name in raw_files:
        category = f_name[:-4] # strip '.txt'
        raw_file_path = os.path.join(raw_dir, f_name)
        
        print(f"[*] Validating and filtering category: {category}...")
        domains = set()
        with open(raw_file_path, "r") as f:
            for line in f:
                domain = line.strip().lower()
                
                # Strict structure checks
                if not DOMAIN_REGEX.match(domain) or IP_REGEX.match(domain):
                    continue
                
                # Whitelist checks to prevent false positives (prevent faulse prasive)
                if is_whitelisted(domain, whitelist):
                    continue
                
                # Exclude common media/code formats that slipped through
                if domain.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.json', '.txt', '.xml', '.html', '.pdf')):
                    continue
                    
                domains.add(domain)
        
        # Apply subdomain minimization to reduce file sizes
        minimized_list = minimize_domains(domains)
        category_uncapped_counts[category] = len(minimized_list)
        category_domains[category] = set(minimized_list)

    # Load feed stats generated by crawler
    feed_stats = []
    feed_stats_path = os.path.join(raw_dir, "feed_stats.json")
    if os.path.exists(feed_stats_path):
        with open(feed_stats_path, "r") as f:
            feed_stats = json.load(f)

    # Compile statistics
    summary_stats = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "total_domains": 0,
        "categories": {},
        "feeds": feed_stats
    }

    all_master_domains = set()

    # Save cleaned categories
    for category, domains in category_domains.items():
        final_list = sorted(list(domains))
        
        summary_stats["categories"][category] = len(final_list)
        if category != "social":
            all_master_domains.update(final_list)

        # Write clean category file
        cat_file_path = os.path.join(categories_dir, f"{category}.txt")
        with open(cat_file_path, "w") as f:
            f.write(f"# Category: {category.upper()}\n")
            f.write(f"# Count: {len(final_list)}\n")
            f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write("# Filtered against whitelist to prevent false positives.\n\n")
            f.write("\n".join(final_list))
        print(f"[+] Saved {len(final_list)} clean domains to {cat_file_path}")

    master_domains_list = sorted(minimize_domains(all_master_domains))
    summary_stats["total_domains"] = len(master_domains_list)

    # 1. Write master domains list
    master_domains_path = os.path.join(master_dir, "domains.txt")
    with open(master_domains_path, "w") as f:
        f.write("# Compiled Master Blacklist - Domains Only\n")
        f.write(f"# Total Domains: {len(master_domains_list)}\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write("\n".join(master_domains_list))

    # 2. Write master hosts list
    master_hosts_path = os.path.join(master_dir, "hosts.txt")
    with open(master_hosts_path, "w") as f:
        f.write("# Compiled Master Blacklist - Hosts Format\n")
        f.write(f"# Total Domains: {len(master_domains_list)}\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        for d in master_domains_list:
            f.write(f"0.0.0.0 {d}\n")

    # 3. Write Adblock / DNS wildcard style list
    master_adblock_path = os.path.join(master_dir, "adblock.txt")
    with open(master_adblock_path, "w") as f:
        f.write("! Compiled Master Blacklist - Adblock Filter Format\n")
        f.write(f"! Total Domains: {len(master_domains_list)}\n")
        f.write(f"! Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        for d in master_domains_list:
            f.write(f"||{d}^\n")

    # 4. Compile domain mapping for shard generation (do not write master domains.json to save space)
    domain_map = {}
    for category, domains in category_domains.items():
        for d in domains:
            if d not in domain_map:
                domain_map[d] = []
            domain_map[d].append(category)

    # 4b. Write sharded lookup database (for high-speed client-side check without downloading 150MB)
    print("[*] Compiling sharded lookup database...")
    import hashlib
    shards = {}
    for d, cats in domain_map.items():
        h = hashlib.sha256(d.encode('utf-8')).hexdigest()[:2]
        if h not in shards:
            shards[h] = {}
        shards[h][d] = cats

    lookup_dir = "lookup"
    os.makedirs(lookup_dir, exist_ok=True)
    
    # Clean out any old shards to prevent stale files
    if os.path.exists(lookup_dir):
        for f in os.listdir(lookup_dir):
            if f.endswith(".json"):
                os.remove(os.path.join(lookup_dir, f))
            
    # Write new shards
    for h, data_map in shards.items():
        with open(os.path.join(lookup_dir, f"{h}.json"), "w") as f:
            json.dump(data_map, f, separators=(',', ':'))  # minified
    print(f"[+] Saved {len(shards)} lookup shard files in '{lookup_dir}/'")

    # Compile Variant Blocklists
    print("[*] Compiling variant blocklists...")
    save_variant("lite", ["malware", "phishing", "cryptomining"], category_domains, category_uncapped_counts)
    save_variant("medium", ["malware", "phishing", "cryptomining", "ads", "tracking", "spam"], category_domains, category_uncapped_counts)
    save_variant("high", ["malware", "phishing", "cryptomining", "ads", "tracking", "spam", "dating", "social", "gambling", "torrent", "crawled"], category_domains, category_uncapped_counts)
    save_variant("nsfw", ["nsfw"], category_domains, category_uncapped_counts)
    save_variant("adblock", ["malware", "phishing", "cryptomining", "ads", "tracking", "spam", "dating", "social", "gambling", "torrent", "crawled", "nsfw"], category_domains, category_uncapped_counts)

    # Compile StevenBlack-Style Alternates
    print("[*] Compiling StevenBlack-style alternates...")
    base_cats = ["malware", "phishing", "cryptomining", "ads", "tracking"]
    
    # We will generate combinations of gambling, porn (nsfw), social, fakenews (spam)
    ext_map = {
        "fakenews": ["spam"],
        "gambling": ["gambling"],
        "porn": ["nsfw"],
        "social": ["social"]
    }
    
    ext_keys = list(ext_map.keys())
    import itertools
    for r in range(1, len(ext_keys) + 1):
        for comb in itertools.combinations(ext_keys, r):
            comb_name = "-".join(comb)
            comb_cats = list(base_cats)
            for key in comb:
                comb_cats.extend(ext_map[key])
            
            # Save this alternate combination
            save_variant(comb_name, comb_cats, category_domains, category_uncapped_counts, base_path="alternates")

    # 5. Write stats file
    with open(stats_file, "w") as f:
        json.dump(summary_stats, f, indent=2)

    print(f"[+] Compiled master list contains {len(master_domains_list)} clean distinct domains.")
    print("=== Step 2: Validator Complete ===")

if __name__ == "__main__":
    main()
