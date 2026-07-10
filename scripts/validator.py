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

def save_variant(variant_name, categories_list, category_domains, max_per_cat):
    """Combines specified categories and saves them under variants/variant_name/."""
    variant_domains = set()
    for cat in categories_list:
        if cat in category_domains:
            variant_domains.update(category_domains[cat])
            
    domains_list = sorted(list(variant_domains))
    if len(domains_list) > max_per_cat:
        domains_list = domains_list[:max_per_cat]
        
    variant_dir = os.path.join("variants", variant_name)
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
            
    write_variant_readme(variant_name, len(domains_list))
    print(f"[+] Saved variant '{variant_name}' ({len(domains_list)} domains) to {variant_dir}")

def write_variant_readme(variant_name, count):
    """Writes a beautiful README.md for the specific variant folder."""
    descriptions = {
        "lite": "Designed for maximum speed and stability. Targets high-severity security threats like malware, phishing, and cryptomining. Near-zero false positives.",
        "medium": "Balanced protection and usability. Blocks security threats, ads, trackers, and spam domains. Recommended for standard home networks.",
        "high": "Maximum security ruleset. Blocks ads, trackers, malware, spam, dating, social tracking, gambling, and torrent networks. May block some web features.",
        "nsfw": "Dedicated blocklist for filtering adult content, pornography, and age-restricted domains. Ideal for parental controls.",
        "adblock": "Optimized ruleset formatted for browser extensions (uBlock Origin, AdGuard). Supports cosmetic and network blocking."
    }
    
    desc = descriptions.get(variant_name, "DNS blocking lists.")
    readme_content = f"""# 🛡️ blackList - {variant_name.capitalize()} Variant

This directory contains the compiled **{variant_name.capitalize()}** blocklist variant.

*   **Status**: Active
*   **Total blocked domains**: `{count:,}`
*   **Target audience**: {desc}

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
    readme_path = os.path.join("variants", variant_name, "README.md")
    with open(readme_path, "w") as f:
        f.write(readme_content)

def main():
    print("=== Step 2: Blacklist Domain Validator Start ===")
    config = load_config()
    whitelist = load_whitelist(config.get("whitelist_file", "whitelist.txt"))
    max_per_cat = config.get("max_domains_per_category", 100000)

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
        
        category_domains[category] = domains

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
        
        # Enforce max limit per category if configured
        if len(final_list) > max_per_cat:
            print(f"[!] Category '{category}' exceeded limit. Truncating to {max_per_cat}.")
            final_list = final_list[:max_per_cat]

        summary_stats["categories"][category] = len(final_list)
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

    master_domains_list = sorted(list(all_master_domains))
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

    # 4. Write master domains JSON format (minified to keep file size small)
    domain_map = {}
    for category, domains in category_domains.items():
        for d in domains:
            if d not in domain_map:
                domain_map[d] = []
            domain_map[d].append(category)

    master_json_path = os.path.join(master_dir, "domains.json")
    with open(master_json_path, "w") as f:
        json.dump(domain_map, f, separators=(',', ':'))  # minified — no whitespace

    # Compile Variant Blocklists
    print("[*] Compiling variant blocklists...")
    save_variant("lite", ["malware", "phishing", "cryptomining"], category_domains, max_per_cat)
    save_variant("medium", ["malware", "phishing", "cryptomining", "ads", "tracking", "spam"], category_domains, max_per_cat)
    save_variant("high", ["malware", "phishing", "cryptomining", "ads", "tracking", "spam", "dating", "social", "gambling", "torrent", "crawled"], category_domains, max_per_cat)
    save_variant("nsfw", ["nsfw"], category_domains, max_per_cat)
    
    # Save a separate adblock variant folder representing full master list
    adblock_var_dir = os.path.join("variants", "adblock")
    os.makedirs(adblock_var_dir, exist_ok=True)
    import shutil
    shutil.copy2(os.path.join(master_dir, "adblock.txt"), os.path.join(adblock_var_dir, "adblock.txt"))
    shutil.copy2(os.path.join(master_dir, "domains.txt"), os.path.join(adblock_var_dir, "domains.txt"))
    shutil.copy2(os.path.join(master_dir, "hosts.txt"), os.path.join(adblock_var_dir, "hosts.txt"))
    write_variant_readme("adblock", len(master_domains_list))

    # 5. Write stats file
    with open(stats_file, "w") as f:
        json.dump(summary_stats, f, indent=2)

    print(f"[+] Compiled master list contains {len(master_domains_list)} clean distinct domains.")
    print("=== Step 2: Validator Complete ===")

if __name__ == "__main__":
    main()
