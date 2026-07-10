#!/usr/bin/env python3
import os
import re
import sys
import json
import yaml
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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

def clean_and_extract_domain(line):
    """
    Cleans a line of raw text and extracts a valid domain name.
    Supports hosts format (e.g., 0.0.0.0 domain.com), raw domains, URLs, and Adblock patterns.
    """
    line = line.strip()
    if not line or line.startswith(('#', '!', '[', '@@')):
        return None

    # Handle hosts file format (e.g., "127.0.0.1 target.com" or "0.0.0.0 target.com")
    parts = line.split()
    if len(parts) >= 2:
        # Check if first part is an IP address
        if IP_REGEX.match(parts[0]):
            potential_domain = parts[1]
        else:
            potential_domain = parts[0]
    else:
        potential_domain = line

    # Handle Adblock/EasyList syntax (e.g., ||domain.com^ or ||domain.com$third-party)
    if potential_domain.startswith('||'):
        potential_domain = potential_domain[2:]
    for char in ('^', '$', '/', ':', '?'):
        if char in potential_domain:
            potential_domain = potential_domain.split(char)[0]

    # Clean port if any (e.g., domain.com:8080)
    if ':' in potential_domain:
        potential_domain = potential_domain.split(':')[0]

    potential_domain = potential_domain.strip().lower()

    # Validate domain syntax and make sure it is not an IP address itself
    if DOMAIN_REGEX.match(potential_domain) and not IP_REGEX.match(potential_domain):
        return potential_domain

    return None

def fetch_feed(feed):
    """Fetches a single blocklist feed via HTTP."""
    name = feed.get("name", "Unknown Feed")
    url = feed.get("url")
    category = feed.get("category", "unclassified")
    
    print(f"[*] Fetching feed: {name} ({url})...")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            lines = response.text.splitlines()
            domains = set()
            for line in lines:
                dom = clean_and_extract_domain(line)
                if dom:
                    domains.add(dom)
            print(f"[+] Downloaded {len(domains)} domains from {name}.")
            return {
                "name": name,
                "category": category,
                "domains": domains,
                "success": True
            }
        else:
            print(f"[-] HTTP error {response.status_code} for feed {name}")
            return {"name": name, "category": category, "domains": set(), "success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        print(f"[-] Failed to download feed {name}: {e}")
        return {"name": name, "category": category, "domains": set(), "success": False, "error": str(e)}

def crawl_and_extract_domains(url, whitelist):
    """
    Crawls a target website, parses its HTML, extracts outbound links,
    and returns a set of valid domains found.
    Excludes the domain of the target site itself and whitelisted domains.
    """
    print(f"[*] Crawling website: {url}...")
    try:
        parsed_target = urlparse(url)
        target_domain = parsed_target.netloc.lower()
        if target_domain.startswith("www."):
            target_domain = target_domain[4:]
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code != 200:
            print(f"[-] Failed to crawl {url}: HTTP {response.status_code}")
            return set()
            
        html_content = response.text
        
        # 1. Find all links in href attributes
        href_domains = set()
        href_matches = re.findall(r'href=["\'](https?://[^"\']+)["\']', html_content, re.IGNORECASE)
        for link in href_matches:
            try:
                parsed_link = urlparse(link)
                domain = parsed_link.netloc.lower()
                # strip port if any
                if ':' in domain:
                    domain = domain.split(':')[0]
                # strip www.
                if domain.startswith("www."):
                    domain = domain[4:]
                
                # validate domain
                if DOMAIN_REGEX.match(domain) and not IP_REGEX.match(domain):
                    href_domains.add(domain)
            except Exception:
                continue
                
        # 2. Find any domain-like strings in the text
        text_domains = set()
        # Find strings matching: word.word.tld
        text_matches = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b', html_content)
        for match in text_matches:
            match = match.lower()
            if DOMAIN_REGEX.match(match) and not IP_REGEX.match(match):
                text_domains.add(match)
                
        all_discovered = href_domains.union(text_domains)
        
        # Filter discovered domains
        final_discovered = set()
        for d in all_discovered:
            # Exclude the crawled site's own domain or its parent
            if target_domain in d or d in target_domain:
                continue
            # Exclude common file extensions that might look like domains
            if d.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.json', '.txt', '.xml', '.html', '.pdf')):
                continue
            # Exclude whitelisted
            if is_whitelisted(d, whitelist):
                continue
            final_discovered.add(d)
            
        print(f"[+] Discovered {len(final_discovered)} domains from {url}")
        return final_discovered
    except Exception as e:
        print(f"[-] Failed to crawl {url}: {e}")
        return set()

def main():
    print("=== GitHub Domain Blacklist Pipeline Start ===")
    config = load_config()
    whitelist = load_whitelist(config.get("whitelist_file", "whitelist.txt"))

    feeds = config.get("feeds", [])
    crawl_sources = config.get("crawl_sources", [])
    max_per_cat = config.get("max_domains_per_category", 100000)
    
    categories_dir = config.get("outputs", {}).get("categories_dir", "categories")
    master_dir = config.get("outputs", {}).get("master_dir", "master")
    stats_file = config.get("outputs", {}).get("stats_file", "stats.json")

    # Create directories
    os.makedirs(categories_dir, exist_ok=True)
    os.makedirs(master_dir, exist_ok=True)

    # Dictionary to hold domain sets per category
    category_domains = {}
    
    # Execution metadata for tracking
    feed_stats = []

    # Fetch feeds in parallel
    print("[*] Fetching feeds concurrently...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_feed, feed): feed for feed in feeds}
        for future in as_completed(futures):
            res = future.result()
            feed_info = {
                "name": res["name"],
                "category": res["category"],
                "success": res["success"],
                "count": len(res["domains"])
            }
            if not res["success"]:
                feed_info["error"] = res.get("error", "Unknown")
            feed_stats.append(feed_info)

            if res["success"] and res["domains"]:
                cat = res["category"]
                if cat not in category_domains:
                    category_domains[cat] = set()
                category_domains[cat].update(res["domains"])

    # Crawl configured websites
    if crawl_sources:
        print("[*] Crawling target websites...")
        crawled_domains = set()
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(crawl_and_extract_domains, url, whitelist): url for url in crawl_sources}
            for future in as_completed(futures):
                url = futures[future]
                res_domains = future.result()
                crawled_domains.update(res_domains)
                
                # Add to feed stats
                feed_stats.append({
                    "name": f"Crawler: {urlparse(url).netloc}",
                    "category": "crawled",
                    "success": len(res_domains) > 0 or url.startswith("https"),
                    "count": len(res_domains)
                })
                
        if crawled_domains:
            category_domains["crawled"] = crawled_domains

    print("[*] Filtering and writing category files...")
    
    # Compile statistics
    summary_stats = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "total_domains": 0,
        "categories": {},
        "feeds": feed_stats
    }

    all_master_domains = set()

    for category, domains in category_domains.items():
        # Whitelist filtering
        filtered_domains = {d for d in domains if not is_whitelisted(d, whitelist)}
        
        # Enforce max limit per category if configured
        final_list = sorted(list(filtered_domains))
        if len(final_list) > max_per_cat:
            print(f"[!] Category '{category}' exceeded limit. Truncating to {max_per_cat}.")
            final_list = final_list[:max_per_cat]

        summary_stats["categories"][category] = len(final_list)
        all_master_domains.update(final_list)

        # Write category txt file
        cat_file_path = os.path.join(categories_dir, f"{category}.txt")
        with open(cat_file_path, "w") as f:
            f.write(f"# Category: {category.upper()}\n")
            f.write(f"# Count: {len(final_list)}\n")
            f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            f.write("\n".join(final_list))
        print(f"[+] Saved {len(final_list)} domains to {cat_file_path}")

    master_domains_list = sorted(list(all_master_domains))
    summary_stats["total_domains"] = len(master_domains_list)

    # 1. Write master domains list
    master_domains_path = os.path.join(master_dir, "domains.txt")
    with open(master_domains_path, "w") as f:
        f.write("# Compiled Master Blacklist - Domains Only\n")
        f.write(f"# Total Domains: {len(master_domains_list)}\n")
        f.write(f"# Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write("\n".join(master_domains_list))

    # 2. Write master hosts list (0.0.0.0 mapping)
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

    # 4. Write master domains JSON format
    domain_map = {}
    for category, domains in category_domains.items():
        for d in domains:
            if not is_whitelisted(d, whitelist):
                if d not in domain_map:
                    domain_map[d] = []
                domain_map[d].append(category)

    master_json_path = os.path.join(master_dir, "domains.json")
    with open(master_json_path, "w") as f:
        json.dump(domain_map, f, indent=2)

    # 5. Write stats file
    with open(stats_file, "w") as f:
        json.dump(summary_stats, f, indent=2)

    print(f"[+] Compiled master list contains {len(master_domains_list)} total distinct domains.")
    print("=== GitHub Domain Blacklist Pipeline Complete ===")

if __name__ == "__main__":
    main()
