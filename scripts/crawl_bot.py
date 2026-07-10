#!/usr/bin/env python3
"""
=============================================================
  Autonomous Blacklist Crawler Bot
  ----------------------------------
  This bot visits seed URLs, classifies each page by category
  (nsfw, phishing, gambling, social, malware, spam, dating, etc.)
  based on page content keywords, then follows outbound links
  to discover and categorize more domains.

  It runs for a configurable duration (default 1 hour) in a
  continuous loop and appends all discovered domains into
  raw/<category>.txt files for the validator to process.
=============================================================
"""

import os
import re
import sys
import time
import json
import yaml
import random
import logging
import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────── Logging Setup ──────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("CrawlerBot")

# ─────────────────────────── Regex Patterns ─────────────────────────────────
DOMAIN_REGEX = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$',
    re.IGNORECASE
)
IP_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# ─────────────────────── Category Keyword Map ───────────────────────────────
# These keyword lists help the bot detect a page's category
# by scanning for keywords in the page title, meta tags, and body text.
CATEGORY_KEYWORDS = {
    "nsfw": [
        "porn", "xxx", "adult", "nude", "naked", "sex", "erotic",
        "hentai", "18+", "mature content", "explicit", "OnlyFans",
        "pornography", "webcam", "escorts", "camgirl", "fetish"
    ],
    "dating": [
        "dating", "date", "find love", "singles", "hookup", "match",
        "partner", "relationship", "romance", "flirt", "meet singles",
        "tinder", "bumble", "badoo", "hinge", "grindr"
    ],
    "gambling": [
        "casino", "poker", "bet", "betting", "gambling", "slots",
        "jackpot", "lottery", "roulette", "blackjack", "sportsbook",
        "online casino", "wager", "bookie", "odds", "free spins"
    ],
    "social": [
        "facebook", "instagram", "tiktok", "twitter", "youtube",
        "snapchat", "social media", "follow us", "subscribe", "likes",
        "trending", "viral", "influencer", "reels", "stories"
    ],
    "phishing": [
        "verify your account", "confirm your password", "update your billing",
        "your account has been suspended", "click here to login",
        "bank account", "unusual activity", "secure your account",
        "your paypal", "apple id", "microsoft account", "reset password",
        "verify now", "limited time offer", "act now", "urgent"
    ],
    "malware": [
        "download now", "free software", "crack", "keygen", "serial key",
        "warez", "free antivirus", "your computer is infected",
        "remove virus", "speed up pc", "free download", "pirated",
        "hack", "exploit", "rootkit", "trojan", "ransomware",
        "free activation", "patch", "loader"
    ],
    "spam": [
        "make money fast", "earn at home", "work from home",
        "click here to win", "congratulations you won", "claim your prize",
        "free gift", "limited offer", "get rich", "mlm", "pyramid",
        "miracle cure", "lose weight fast", "diet pill", "supplement"
    ],
    "tracking": [
        "ad tracking", "analytics", "pixel", "beacon", "fingerprint",
        "telemetry", "data collection", "user tracking", "cookies",
        "retargeting", "ad server", "impression tracker"
    ],
    "torrent": [
        "torrent", "magnet link", "download torrent", "seeders", "leechers",
        "piracy", "pirate bay", "1337x", "rarbg", "yts", "free movies",
        "watch online", "stream free", "download free movie"
    ],
    "cryptomining": [
        "mine bitcoin", "crypto mining", "pool mining", "hash rate",
        "monero", "coinhive", "browser mining", "earn crypto",
        "mining pool", "proof of work", "gpu mining", "mining rig"
    ],
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
]

# ─────────────────────────── Config Loading ─────────────────────────────────
def load_config(config_path="config.yaml"):
    """Loads config.yaml safely."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        sys.exit(1)

def load_whitelist(whitelist_path="whitelist.txt"):
    """Loads whitelist.txt, ignoring comments and empty lines."""
    whitelist = set()
    if not os.path.exists(whitelist_path):
        return whitelist
    with open(whitelist_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                whitelist.add(line.lower())
    logger.info(f"Loaded {len(whitelist)} whitelisted entries.")
    return whitelist

def is_whitelisted(domain, whitelist):
    """Checks if a domain or its parent is whitelisted."""
    domain_lower = domain.lower()
    if domain_lower in whitelist:
        return True
    parts = domain_lower.split('.')
    for i in range(1, len(parts)):
        if '.'.join(parts[i:]) in whitelist:
            return True
    return False

def is_valid_domain(domain):
    """Returns True if domain passes regex validation and is not an IP."""
    return bool(DOMAIN_REGEX.match(domain)) and not bool(IP_REGEX.match(domain))

# ─────────────────────── Domain Extraction ──────────────────────────────────
def extract_domain(url):
    """Extracts clean domain from a full URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if ':' in domain:
            domain = domain.split(':')[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain if domain else None
    except Exception:
        return None

def extract_outbound_links(html, base_url):
    """Extracts all outbound links found in href attributes."""
    links = set()
    href_matches = re.findall(r'href=["\'](https?://[^"\'>\s]+)["\']', html, re.IGNORECASE)
    for href in href_matches:
        try:
            full_url = urljoin(base_url, href)
            if full_url.startswith("http"):
                links.add(full_url)
        except Exception:
            continue
    return links

# ─────────────────────── Category Detection ──────────────────────────────────
def detect_category(html_text, url):
    """
    Scans the page content and URL for category keywords.
    Returns the best matching category, or 'crawled' if unknown.
    """
    search_text = (url + " " + html_text[:50000]).lower()
    
    scores = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(search_text.count(kw.lower()) for kw in keywords)
        if score > 0:
            scores[category] = score
    
    if scores:
        # Return category with highest keyword score
        return max(scores, key=scores.get)
    
    return "crawled"  # Unknown category

# ─────────────────────── Crawler Bot Core ───────────────────────────────────
def fetch_page(url, timeout=20):
    """
    Fetches a web page and returns the (html_content, final_url) or (None, None)
    """
    try:
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
            return resp.text, resp.url
        return None, None
    except Exception:
        return None, None


def crawl_bot(seed_urls, whitelist, duration_seconds=3600, max_workers=3, delay=1.5):
    """
    Main crawler bot loop.
    - Starts from seed_urls
    - Visits pages, detects categories, follows outbound links
    - Runs for duration_seconds total
    - Returns dict of {category: set(domains)}
    """
    visited = set()
    queue = deque(seed_urls)
    category_domains = {}
    
    start_time = time.time()
    elapsed = 0
    total_visited = 0
    total_discovered = 0
    
    logger.info(f"🤖 Crawler Bot Started. Duration: {duration_seconds}s | Seeds: {len(seed_urls)}")
    
    while queue and elapsed < duration_seconds:
        elapsed = time.time() - start_time
        remaining = duration_seconds - elapsed
        logger.info(f"⏱  Elapsed: {elapsed:.0f}s / {duration_seconds}s | Queue: {len(queue)} | Visited: {total_visited} | Found: {total_discovered}")
        
        # Pull a batch of URLs from the queue
        batch = []
        for _ in range(min(max_workers, len(queue))):
            if queue:
                url = queue.popleft()
                domain = extract_domain(url)
                if domain and domain not in visited:
                    visited.add(domain)
                    batch.append(url)
        
        if not batch:
            break
        
        # Fetch pages concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fetch_page, url): url for url in batch}
            for future in as_completed(futures):
                original_url = futures[future]
                html, final_url = future.result()
                
                if not html:
                    continue
                
                total_visited += 1
                
                # Detect category from page content + URL
                category = detect_category(html, final_url or original_url)
                
                # Extract the actual domain from this page
                page_domain = extract_domain(final_url or original_url)
                if page_domain and is_valid_domain(page_domain) and not is_whitelisted(page_domain, whitelist):
                    if category not in category_domains:
                        category_domains[category] = set()
                    category_domains[category].add(page_domain)
                    total_discovered += 1
                    logger.info(f"  ✅ [{category.upper()}] {page_domain}")
                
                # Extract outbound links and add new ones to queue
                outbound_links = extract_outbound_links(html, final_url or original_url)
                new_links = 0
                for link in outbound_links:
                    link_domain = extract_domain(link)
                    if link_domain and link_domain not in visited and not is_whitelisted(link_domain, whitelist):
                        queue.append(link)
                        new_links += 1
                
                if new_links:
                    logger.info(f"  🔗 Added {new_links} new links from {page_domain or original_url}")
        
        # Polite delay between batches
        time.sleep(delay)
    
    elapsed = time.time() - start_time
    logger.info(f"🏁 Crawler Bot Finished. Total time: {elapsed:.1f}s | Visited: {total_visited} | Discovered: {total_discovered}")
    return category_domains


# ────────────────────────── Raw File Appender ────────────────────────────────
def append_to_raw(category_domains, raw_dir="raw"):
    """Appends newly discovered domains into the existing raw/<category>.txt files."""
    os.makedirs(raw_dir, exist_ok=True)
    
    total_new = 0
    for category, domains in category_domains.items():
        if not domains:
            continue
        
        raw_file = os.path.join(raw_dir, f"{category}.txt")
        
        # Load existing domains to deduplicate
        existing = set()
        if os.path.exists(raw_file):
            with open(raw_file, "r") as f:
                for line in f:
                    existing.add(line.strip().lower())
        
        # Identify new domains
        new_domains = sorted(d for d in domains if d not in existing)
        
        if new_domains:
            with open(raw_file, "a") as f:
                f.write("\n".join(new_domains) + "\n")
            logger.info(f"[+] Appended {len(new_domains)} new domains to raw/{category}.txt")
            total_new += len(new_domains)
        else:
            logger.info(f"[=] No new domains to append for category: {category}")
    
    return total_new


# ────────────────────────────── Main ────────────────────────────────────────
def main():
    print("=== 🤖 Autonomous Crawler Bot Starting ===")
    
    config = load_config()
    whitelist = load_whitelist(config.get("whitelist_file", "whitelist.txt"))
    
    # Get crawl seeds from config. Add more URLs here to expand coverage.
    seed_urls = config.get("crawl_seeds", [
        # Threat intel feeds that list malicious URLs
        "https://openphish.com",
        "https://urlhaus.abuse.ch",
        # Add any additional seed pages here via config.yaml
    ])
    
    # Duration the bot will run (default 1 hour = 3600 seconds)
    duration = config.get("crawler_duration_seconds", 3600)
    max_workers = config.get("crawler_max_workers", 3)
    delay = config.get("crawler_delay_seconds", 1.5)
    
    logger.info(f"Seeds: {len(seed_urls)} | Duration: {duration}s | Workers: {max_workers}")
    
    # Run the crawler bot
    category_domains = crawl_bot(
        seed_urls=seed_urls,
        whitelist=whitelist,
        duration_seconds=duration,
        max_workers=max_workers,
        delay=delay
    )
    
    # Append results to raw/ folder
    total_new = append_to_raw(category_domains)
    
    # Save a run summary
    summary = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "categories_discovered": {cat: len(doms) for cat, doms in category_domains.items()},
        "total_new_domains": total_new
    }
    with open("raw/bot_run_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"✅ Crawler bot finished. {total_new} new domains appended to raw/.")
    print("=== 🤖 Crawler Bot Complete ===")


if __name__ == "__main__":
    main()
