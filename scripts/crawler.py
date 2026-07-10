#!/usr/bin/env python3
import os
import re
import sys
import yaml
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_config(config_path="config.yaml"):
    """Loads config.yaml safely."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[-] Error loading configuration: {e}")
        sys.exit(1)

def extract_raw_domains_from_text(text):
    """
    Extracts raw domain-like strings from text lines.
    Does simple cleaning but leaves strict validation to the validator.
    """
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!', '[', '@@')):
            continue
        
        # Split hosts format (e.g. 0.0.0.0 badsite.com)
        parts = line.split()
        potential = parts[1] if len(parts) >= 2 else parts[0]
        
        # Clean Adblock/EasyList syntax
        if potential.startswith('||'):
            potential = potential[2:]
        for char in ('^', '$', '/', ':', '?'):
            if char in potential:
                potential = potential.split(char)[0]
        
        potential = potential.strip().lower()
        if potential:
            domains.add(potential)
    return domains

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
            domains = extract_raw_domains_from_text(response.text)
            print(f"[+] Downloaded {len(domains)} raw domains from {name}.")
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

def crawl_website(url):
    """
    Crawls a target website, parses its HTML, extracts outbound links,
    and returns a set of raw domains found.
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
        discovered = set()
        
        # 1. Links in href attributes
        href_matches = re.findall(r'href=["\'](https?://[^"\']+)["\']', html_content, re.IGNORECASE)
        for link in href_matches:
            try:
                domain = urlparse(link).netloc.lower()
                if ':' in domain:
                    domain = domain.split(':')[0]
                if domain.startswith("www."):
                    domain = domain[4:]
                if domain:
                    discovered.add(domain)
            except Exception:
                continue
                
        # 2. Domain-like strings in body text
        text_matches = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b', html_content)
        for match in text_matches:
            discovered.add(match.lower())
            
        # Basic filter (exclude crawled site's own domain)
        final_discovered = set()
        for d in discovered:
            if target_domain in d or d in target_domain:
                continue
            final_discovered.add(d)
            
        print(f"[+] Discovered {len(final_discovered)} raw domains from {url}")
        return final_discovered
    except Exception as e:
        print(f"[-] Failed to crawl {url}: {e}")
        return set()

def main():
    print("=== Step 1: Blacklist Crawler & Fetcher Start ===")
    config = load_config()
    feeds = config.get("feeds", [])
    crawl_sources = config.get("crawl_sources", [])
    
    raw_dir = "raw"
    os.makedirs(raw_dir, exist_ok=True)
    
    category_domains = {}
    feed_stats = []

    # Fetch feeds in parallel
    print("[*] Fetching feeds concurrently...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_feed, feed): feed for feed in feeds}
        for future in as_completed(futures):
            res = future.result()
            feed_stats.append({
                "name": res["name"],
                "category": res["category"],
                "success": res["success"],
                "count": len(res["domains"]),
                "error": res.get("error", "")
            })
            if res["success"] and res["domains"]:
                cat = res["category"]
                if cat not in category_domains:
                    category_domains[cat] = set()
                category_domains[cat].update(res["domains"])

    # Crawl websites in parallel
    if crawl_sources:
        print("[*] Crawling target websites...")
        crawled_domains = set()
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(crawl_website, url): url for url in crawl_sources}
            for future in as_completed(futures):
                url = futures[future]
                res_domains = future.result()
                crawled_domains.update(res_domains)
                feed_stats.append({
                    "name": f"Crawler: {urlparse(url).netloc}",
                    "category": "crawled",
                    "success": len(res_domains) > 0 or url.startswith("https"),
                    "count": len(res_domains)
                })
        if crawled_domains:
            category_domains["crawled"] = crawled_domains

    # Save raw outputs
    print("[*] Writing raw files to 'raw/' directory...")
    for category, domains in category_domains.items():
        raw_file_path = os.path.join(raw_dir, f"{category}.txt")
        sorted_domains = sorted(list(domains))
        with open(raw_file_path, "w") as f:
            f.write("\n".join(sorted_domains))
        print(f"[+] Saved {len(sorted_domains)} raw domains to {raw_file_path}")

    # Save temporary stats file to be picked up by the validator
    with open(os.path.join(raw_dir, "feed_stats.json"), "w") as f:
        import json
        json.dump(feed_stats, f, indent=2)

    print("=== Step 1: Crawler Complete ===")

if __name__ == "__main__":
    main()
