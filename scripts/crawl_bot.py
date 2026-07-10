#!/usr/bin/env python3
"""
=============================================================
  Autonomous Blacklist Crawler Bot  v3  (Internet Crawler)
  ─────────────────────────────────────────────────────────
  Domain Discovery Sources (nothing large committed to repo):
    1. Tranco Top-1M list  → downloaded to /tmp/, never saved to git
    2. Certificate Transparency logs (crt.sh) → live random domain API
    3. Threat intel seed URLs → phishing/malware domain lists
    4. Outbound link following → organic web crawl discovery

  State persistence:
    • raw/crawl_state.json  → only stores a small position counter
    • NO large files committed to the repo

  Targets: 100k+ sites per 3.5-hour run, 2× per day
=============================================================
"""

import os, re, sys, csv, time, json, gzip, yaml, random, logging, zipfile, io
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────── Logging ────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("CrawlerBot")

# ──────────────────────────── Regexes ───────────────────────────────────────
DOMAIN_REGEX = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE
)
IP_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
HREF_RE = re.compile(r'href=["\']((https?://)[^"\'>\s]{4,})["\']', re.IGNORECASE)

# ───────────────────── Category Keywords ────────────────────────────────────
CATEGORY_KEYWORDS = {
    "nsfw": [
        "porn","xxx","adult","nude","naked","sex","erotic","hentai","18+",
        "mature content","explicit","onlyfans","pornography","webcam","escorts",
        "camgirl","fetish","nudity","x-rated","sexual content",
    ],
    "dating": [
        "dating","find love","singles","hookup","match","romance","flirt",
        "meet singles","tinder","bumble","badoo","hinge","grindr","relationship",
    ],
    "gambling": [
        "casino","poker","bet","betting","gambling","slots","jackpot","lottery",
        "roulette","blackjack","sportsbook","wager","bookie","odds","free spins",
        "online casino","betway","stake","1xbet","sports betting",
    ],
    "phishing": [
        "verify your account","confirm your password","update your billing",
        "account suspended","click here to login","bank account",
        "unusual activity","secure your account","your paypal","apple id",
        "microsoft account","reset password","verify now","act now",
        "account locked","login attempt","your account has been",
    ],
    "malware": [
        "download now","free software","crack","keygen","serial key","warez",
        "free antivirus","your computer is infected","remove virus",
        "free download","pirated","hack","exploit","rootkit","trojan",
        "ransomware","free activation","patch","loader","nulled",
    ],
    "spam": [
        "make money fast","earn at home","work from home","click here to win",
        "congratulations you won","claim your prize","free gift","get rich",
        "mlm","pyramid scheme","miracle cure","lose weight fast","diet pill",
    ],
    "tracking": [
        "ad tracking","analytics pixel","beacon","fingerprint","telemetry",
        "data collection","user tracking","retargeting","ad server",
        "impression tracker","third party tracking",
    ],
    "torrent": [
        "torrent","magnet link","seeders","leechers","piracy","pirate bay",
        "1337x","rarbg","yts","free movies","watch online free",
        "download free movie","stream free","warez",
    ],
    "cryptomining": [
        "mine bitcoin","crypto mining","pool mining","hash rate","monero",
        "coinhive","browser mining","earn crypto","mining pool","gpu mining",
    ],
    "ads": [
        "advertise here","ad network","display ads","sponsored content",
        "pop-up ads","banner ads","cpm network","traffic monetization",
        "ad exchange","push notifications","native ads",
    ],
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile Safari/604.1",
]

# ─────────────────── Live Threat Intel Seeds ────────────────────────────────
THREAT_SEED_URLS = [
    ("phishing",    "https://openphish.com/feed.txt"),
    ("malware",     "https://urlhaus.abuse.ch/downloads/text/"),
    ("malware",     "https://hole.cert.pl/domains/domains.txt"),
    ("phishing",    "https://phishing.army/download/phishing_army_blocklist.txt"),
    ("phishing",    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"),
    ("ads",         "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    ("malware",     "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt"),
    ("tracking",    "https://v.firebog.net/hosts/Easyprivacy.txt"),
]

# Tranco downloaded to /tmp — never committed to git
TRANCO_TMP   = "/tmp/tranco_top1m.csv.gz"
TRANCO_URL   = "https://tranco-list.eu/download/ranked/full"
CRAWL_STATE  = "raw/crawl_state.json"

# ═══════════════════════════ Helpers ════════════════════════════════════════

def load_config(path="config.yaml"):
    try:
        with open(path) as f: return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Config error: {e}"); sys.exit(1)

def load_whitelist(path="whitelist.txt"):
    wl = set()
    if not os.path.exists(path): return wl
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                wl.add(line.lower())
    logger.info(f"Loaded {len(wl)} whitelist entries.")
    return wl

def is_whitelisted(domain, whitelist):
    d = domain.lower()
    if d in whitelist: return True
    parts = d.split('.')
    for i in range(1, len(parts)):
        if '.'.join(parts[i:]) in whitelist: return True
    return False

def is_valid_domain(domain):
    return (bool(DOMAIN_REGEX.match(domain))
            and not bool(IP_REGEX.match(domain))
            and len(domain) <= 253
            and '.' in domain)

def extract_domain(url):
    try:
        url = url if url.startswith('http') else 'http://' + url
        host = urlparse(url).netloc.lower().split(':')[0]
        return host[4:] if host.startswith('www.') else host
    except Exception:
        return None

def clean_domain_line(line):
    """Parse a domain from various list formats (hosts, plain, adblock)."""
    line = line.strip()
    if not line or line.startswith(('#', '!', ';', '//', '[')):
        return None
    # Hosts format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
    parts = line.split()
    if len(parts) == 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
        return parts[1].lower()
    # Adblock format: ||domain.com^
    if line.startswith('||'):
        return line[2:].split('^')[0].split('/')[0].lower()
    # Plain domain
    return parts[0].lower() if parts else None

def extract_outbound_domains(html, visited, queued, whitelist, limit=15):
    """Extract up to `limit` new domains from outbound links in page HTML."""
    found = []
    for m in HREF_RE.finditer(html[:80000]):
        if len(found) >= limit: break
        d = extract_domain(m.group(1))
        if (d and is_valid_domain(d)
                and d not in visited
                and d not in queued
                and not is_whitelisted(d, whitelist)):
            found.append(d)
    return found

def detect_category(html_text, url):
    text = (url + " " + html_text[:60000]).lower()
    scores = {
        cat: sum(text.count(kw.lower()) for kw in kws)
        for cat, kws in CATEGORY_KEYWORDS.items()
    }
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "crawled"

# ═══════════════════ Domain Source 1: Tranco Top-1M ═════════════════════════

def download_tranco(tmp_path=TRANCO_TMP):
    """
    Downloads Top 1M list to /tmp/ (never added to git).
    Tries Tranco first, then Cisco Umbrella, then Majestic Million.
    Uses cached /tmp/ file if it exists and is < 24h old.
    Returns list of domain strings.
    """
    # Use /tmp/ cache if fresh
    if os.path.exists(tmp_path):
        age_h = (time.time() - os.path.getmtime(tmp_path)) / 3600
        if age_h < 24:
            logger.info(f"Using /tmp/ cached top domains list ({age_h:.1f}h old).")
            domains = _parse_tranco(tmp_path)
            if domains:
                return domains

    # 1. Attempt Tranco
    logger.info("Attempting download from Tranco...")
    try:
        r = requests.get(TRANCO_URL, timeout=60, stream=True,
                         headers={"User-Agent": random.choice(USER_AGENTS)})
        if r.status_code == 200:
            with open(tmp_path, 'wb') as f:
                for chunk in r.iter_content(65536): f.write(chunk)
            domains = _parse_tranco(tmp_path)
            if domains:
                logger.info("Successfully fetched Top-1M from Tranco.")
                return domains
    except Exception as e:
        logger.warning(f"Tranco fetch failed: {e}")

    # 2. Attempt Cisco Umbrella
    logger.info("Attempting download from Cisco Umbrella...")
    umbrella_url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    try:
        r = requests.get(umbrella_url, timeout=60,
                         headers={"User-Agent": random.choice(USER_AGENTS)})
        if r.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                csv_name = z.namelist()[0]
                with z.open(csv_name) as csv_in:
                    with gzip.open(tmp_path, 'wt', encoding='utf-8') as gz_out:
                        writer = csv.writer(gz_out)
                        csv_reader = csv.reader(io.TextIOWrapper(csv_in, encoding='utf-8', errors='ignore'))
                        for row in csv_reader:
                            writer.writerow(row)
            domains = _parse_tranco(tmp_path)
            if domains:
                logger.info("Successfully fetched Top-1M from Cisco Umbrella.")
                return domains
    except Exception as e:
        logger.warning(f"Cisco Umbrella fetch failed: {e}")

    # 3. Attempt Majestic Million
    logger.info("Attempting download from Majestic Million...")
    majestic_url = "https://majestic.com/reports/majestic-million.csv"
    try:
        r = requests.get(majestic_url, timeout=60, stream=True,
                         headers={"User-Agent": random.choice(USER_AGENTS)})
        if r.status_code == 200:
            with gzip.open(tmp_path, 'wt', encoding='utf-8') as gz_out:
                writer = csv.writer(gz_out)
                lines = (line.decode('utf-8', errors='ignore') for line in r.iter_lines())
                reader = csv.reader(lines)
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) >= 3:
                        rank = row[0]
                        domain = row[2]
                        writer.writerow([rank, domain])
            domains = _parse_tranco(tmp_path)
            if domains:
                logger.info("Successfully fetched Top-1M from Majestic Million.")
                return domains
    except Exception as e:
        logger.warning(f"Majestic Million fetch failed: {e}")

    logger.error("All Top-1M domain list providers failed!")
    return []

def _parse_tranco(path):
    domains = []
    openers = [(gzip.open, {'mode': 'rt', 'encoding': 'utf-8', 'errors': 'ignore'}),
               (open,      {'mode': 'r',  'encoding': 'utf-8', 'errors': 'ignore'})]
    for opener, kwargs in openers:
        try:
            with opener(path, **kwargs) as f:
                for row in csv.reader(f):
                    if len(row) >= 2:
                        d = row[1].strip().lower()
                        if is_valid_domain(d):
                            domains.append(d)
            break
        except Exception:
            continue
    logger.info(f"Loaded {len(domains):,} domains from top-1m dataset.")
    return domains

# ═══════════════════ Domain Source 2: crt.sh CT Logs ════════════════════════

def fetch_crtsh_domains(limit=5000, whitelist=set()):
    """
    Queries the Certificate Transparency crt.sh API with random TLDs
    to discover fresh, real, registered domains across the internet.
    Each query returns up to ~100 domains — we run many queries.
    """
    # Specific query prefixes to hit index on crt.sh (e.g. login.something...)
    # This prevents database sequential scans and returns fast.
    query_terms = [
        "login%", "verify%", "secure%", "update%", "account%",
        "signin%", "support%", "billing%", "banking%", "service%",
        "online%", "free%", "gift%", "win%", "claim%",
        "portal%", "auth%", "webmail%", "office%", "admin%",
    ]
    found = set()
    max_attempts = 3
    attempts = 0

    logger.info(f"Fetching random domains from crt.sh Certificate Transparency logs...")
    
    # Shuffle query terms to get random ones
    random.shuffle(query_terms)

    for term in query_terms:
        if len(found) >= limit or attempts >= max_attempts:
            break
        try:
            url = f"https://crt.sh/?q={term}&output=json"
            logger.info(f"Querying crt.sh for prefix: {term} (Attempt {attempts + 1}/{max_attempts})...")
            r = requests.get(url, timeout=15,
                             headers={"User-Agent": random.choice(USER_AGENTS)})
            attempts += 1
            if r.status_code != 200:
                continue
            entries = r.json()
            for entry in entries:
                name = entry.get("name_value", "").lower()
                for d in name.split('\n'):
                    d = d.strip().lstrip('*.')
                    if is_valid_domain(d) and not is_whitelisted(d, whitelist):
                        found.add(d)
        except Exception as e:
            logger.warning(f"crt.sh query for {term} failed: {e}")

    result = list(found)[:limit]
    logger.info(f"crt.sh: discovered {len(result):,} fresh domains.")
    return result

# ═══════════════════ Domain Source 3: Threat Intel Feeds ════════════════════

def load_threat_seeds(whitelist):
    """Downloads threat intel feeds. Returns list of (domain, category) tuples."""
    results = []
    for category, url in THREAT_SEED_URLS:
        try:
            r = requests.get(url, timeout=30,
                             headers={"User-Agent": random.choice(USER_AGENTS)})
            if r.status_code != 200:
                continue
            count = 0
            for line in r.text.splitlines():
                d = clean_domain_line(line)
                if not d: continue
                d = extract_domain(d) or d
                if is_valid_domain(d) and not is_whitelisted(d, whitelist):
                    results.append((d, category))
                    count += 1
            logger.info(f"  [{category}] {url.split('/')[-1]}: {count:,} domains")
        except Exception as e:
            logger.warning(f"  Feed failed {url}: {e}")
    logger.info(f"Threat seeds total: {len(results):,} domains.")
    return results

# ═══════════════════════ Crawl State ════════════════════════════════════════

def load_crawl_state():
    if os.path.exists(CRAWL_STATE):
        try:
            with open(CRAWL_STATE) as f: return json.load(f)
        except Exception: pass
    return {"tranco_position": 0, "total_visited_all_runs": 0, "runs": 0}

def save_crawl_state(state):
    os.makedirs("raw", exist_ok=True)
    with open(CRAWL_STATE, 'w') as f: json.dump(state, f, indent=2)

# ═══════════════════════ Page Fetcher ═══════════════════════════════════════

def fetch_page(domain, timeout=7):
    """Try HTTPS then HTTP. Returns (html, final_url) or (None, None)."""
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close',
    }
    for scheme in ('https', 'http'):
        try:
            r = requests.get(f"{scheme}://{domain}", headers=headers,
                             timeout=timeout, allow_redirects=True, stream=False)
            if r.status_code == 200 and 'text/html' in r.headers.get('Content-Type',''):
                return r.text[:150000], r.url
        except Exception:
            continue
    return None, None

# ════════════════════════ Main Crawler Loop ══════════════════════════════════

def crawl_bot(tranco_domains, threat_seeds, crtsh_domains, whitelist,
              tranco_start=0, duration_seconds=12600, max_workers=40, delay=0.3):
    """
    Feeds the queue from 3 sources and crawls for `duration_seconds`.
    Returns (category_domains dict, new_tranco_position, total_visited).
    """
    visited      = set()
    queued       = set()
    queue        = deque()
    # Separate priority dict: forced category for threat seeds
    forced_cat   = {}
    category_domains = {}

    def enqueue(domain, cat=None):
        if domain and domain not in queued and is_valid_domain(domain):
            queue.append(domain)
            queued.add(domain)
            if cat: forced_cat[domain] = cat

    # ── Priority 1: Threat intel (known-bad domains, already categorised) ──
    logger.info("Loading threat intel seeds into queue...")
    for domain, cat in threat_seeds:
        enqueue(domain, cat)

    # ── Priority 2: crt.sh random internet domains ──
    logger.info("Loading crt.sh internet domains into queue...")
    for d in crtsh_domains:
        enqueue(d)

    # ── Priority 3: Tranco list (continues from saved position) ──
    logger.info(f"Loading Tranco domains from position {tranco_start:,}...")
    tranco_pos = tranco_start
    preload = 300000  # pre-load 300k domains into queue
    loaded  = 0
    for i in range(tranco_start, min(tranco_start + preload, len(tranco_domains))):
        d = tranco_domains[i]
        if not is_whitelisted(d, whitelist):
            enqueue(d)
            loaded += 1
        tranco_pos = i + 1

    logger.info(
        f"Queue ready: {len(threat_seeds):,} threat + "
        f"{len(crtsh_domains):,} crt.sh + "
        f"{loaded:,} Tranco = {len(queue):,} total"
    )

    start_time   = time.time()
    total_visited = 0
    total_discovered = 0
    last_log     = start_time

    logger.info(
        f"🤖 Crawler v3 Start | "
        f"Duration: {duration_seconds/3600:.1f}h | "
        f"Workers: {max_workers} | Target: 100k+ sites"
    )

    while True:
        elapsed = time.time() - start_time
        if elapsed >= duration_seconds:
            logger.info("⏰ Duration reached. Stopping.")
            break

        # Build batch of unvisited domains
        batch = []
        drain_limit = min(len(queue), max_workers * 20)
        drained = 0
        while queue and len(batch) < max_workers and drained < drain_limit:
            d = queue.popleft(); drained += 1
            if d not in visited:
                visited.add(d); batch.append(d)

        if not batch:
            logger.info("Queue exhausted.")
            break

        # Progress log every 60 seconds
        now = time.time()
        if now - last_log >= 60:
            rate = total_visited / max(elapsed, 1)
            pct  = (total_visited / 100000) * 100
            logger.info(
                f"⏱  {elapsed/3600:.2f}h | "
                f"Visited: {total_visited:,} ({pct:.0f}% of 100k target) | "
                f"Discovered: {total_discovered:,} | "
                f"Queue: {len(queue):,} | "
                f"Rate: {rate:.1f}/s"
            )
            last_log = now

        # Concurrent fetch
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(fetch_page, d): d for d in batch}
            for fut in as_completed(futures):
                domain = futures[fut]
                html, final_url = fut.result()
                if not html: continue

                total_visited += 1

                # Use forced category (threat seeds) or auto-detect
                cat = forced_cat.pop(domain, None) or detect_category(
                    html, final_url or f"http://{domain}"
                )

                final_domain = extract_domain(final_url) if final_url else domain
                if final_domain and is_valid_domain(final_domain) and not is_whitelisted(final_domain, whitelist):
                    category_domains.setdefault(cat, set()).add(final_domain)
                    total_discovered += 1

                # Follow outbound links → new domains only
                new_doms = extract_outbound_domains(html, visited, queued, whitelist, limit=15)
                for nd in new_doms:
                    enqueue(nd)

        time.sleep(delay)

    elapsed = time.time() - start_time
    rate = total_visited / max(elapsed, 1)
    logger.info(
        f"🏁 Done | {elapsed/3600:.2f}h | "
        f"Visited: {total_visited:,} | "
        f"Discovered: {total_discovered:,} | "
        f"Rate: {rate:.1f}/s | Tranco pos: {tranco_pos:,}"
    )
    return category_domains, tranco_pos, total_visited

# ═══════════════════════ Write Raw Output ════════════════════════════════════

def append_to_raw(category_domains, raw_dir="raw"):
    os.makedirs(raw_dir, exist_ok=True)
    total_new = 0
    for cat, domains in category_domains.items():
        if not domains: continue
        raw_file = os.path.join(raw_dir, f"{cat}.txt")
        existing = set()
        if os.path.exists(raw_file):
            with open(raw_file) as f:
                existing = {l.strip().lower() for l in f if l.strip()}
        new_doms = sorted(d for d in domains if d not in existing)
        if new_doms:
            with open(raw_file, 'a') as f:
                f.write('\n'.join(new_doms) + '\n')
            logger.info(f"  [{cat}] +{len(new_doms):,} new domains")
            total_new += len(new_doms)
    return total_new

# ═══════════════════════════ Main ════════════════════════════════════════════

def main():
    print("=" * 62)
    print("  🤖 Autonomous Internet Crawler Bot v3  (High-Volume)")
    print("=" * 62)

    config      = load_config()
    whitelist   = load_whitelist(config.get("whitelist_file", "whitelist.txt"))
    duration    = config.get("crawler_duration_seconds", 12600)   # 3.5 h
    max_workers = config.get("crawler_max_workers", 40)
    delay       = config.get("crawler_delay_seconds", 0.3)

    # Load persistent position (tiny JSON, fine to commit)
    state      = load_crawl_state()
    tranco_pos = state.get("tranco_position", 0)
    logger.info(f"Run #{state.get('runs',0)+1} | Resuming Tranco at pos {tranco_pos:,}")

    # ── Source 1: Tranco Top-1M → /tmp/ only, never in git ──
    tranco_domains = download_tranco()
    if tranco_pos >= len(tranco_domains) and tranco_domains:
        logger.info("Tranco exhausted — wrapping to position 0.")
        tranco_pos = 0

    # ── Source 2: crt.sh Certificate Transparency (random internet domains) ──
    crtsh_domains = fetch_crtsh_domains(limit=10000, whitelist=whitelist)

    # ── Source 3: Live threat intel feeds ──
    threat_seeds = load_threat_seeds(whitelist)

    # ── Run ──
    category_domains, new_pos, visited_count = crawl_bot(
        tranco_domains  = tranco_domains,
        threat_seeds    = threat_seeds,
        crtsh_domains   = crtsh_domains,
        whitelist       = whitelist,
        tranco_start    = tranco_pos,
        duration_seconds= duration,
        max_workers     = max_workers,
        delay           = delay,
    )

    # ── Save results ──
    total_new = append_to_raw(category_domains)

    # ── Update tiny state file (just numbers, not domain lists) ──
    state["tranco_position"]        = new_pos
    state["total_visited_all_runs"] = state.get("total_visited_all_runs", 0) + visited_count
    state["runs"]                   = state.get("runs", 0) + 1
    state["last_run"]               = datetime.now(timezone.utc).isoformat()
    state["last_run_visited"]       = visited_count
    state["last_run_new_domains"]   = total_new
    save_crawl_state(state)

    # ── Run summary ──
    summary = {
        "run_at": state["last_run"],
        "duration_seconds": duration,
        "sites_visited": visited_count,
        "new_domains_found": total_new,
        "tranco_position": new_pos,
        "total_visited_all_runs": state["total_visited_all_runs"],
        "categories": {c: len(d) for c, d in category_domains.items()},
    }
    with open("raw/bot_run_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)

    print("=" * 62)
    print(f"  ✅ Visited: {visited_count:,} | New blacklisted: {total_new:,}")
    print(f"  📍 Tranco pos saved: {new_pos:,} / {len(tranco_domains):,}")
    print(f"  🌐 Total all runs: {state['total_visited_all_runs']:,}")
    print("=" * 62)


if __name__ == "__main__":
    main()
