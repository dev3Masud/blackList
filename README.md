# 🛡️ GitHub Domain Blacklist & Threat Registry

An automated domain blacklist collection engine that scrapes threat-intelligence feeds daily, parses and validates targets, runs whitelist filters to prevent false positives, and organizes them by threat categories. 

This repository serves both compiled output lists (hosts, raw lists, AdBlock filters) and an interactive web dashboard for real-time security lookup.

---

## 📊 Live Dashboard
The interactive statistics panel, feed status tracking, and real-time domain search tool can be accessed on **GitHub Pages** for this repository.

---

## 🗂️ Blacklist Formats & Feeds

### Compiled Master Lists (All Categories Combined)
These lists combine all threat domains (excluding whitelisted ones) and are updated daily:

*   **Raw Domains List:** `master/domains.txt`
*   **Hosts File Format:** `master/hosts.txt` (Premapped to `0.0.0.0`)
*   **AdBlock Filter Format:** `master/adblock.txt` (Compatible with uBlock Origin, AdGuard, Brave)
*   **JSON Map Database:** `master/domains.json`

### Categorized Sub-Lists
If you only wish to block specific categories, you can pull separate feeds directly:

*   **Ads & Adware:** `categories/ads.txt`
*   **Malware & Exploits:** `categories/malware.txt`
*   **Phishing & Social Engineering:** `categories/phishing.txt`
*   **Spam & Scams:** `categories/spam.txt`
*   **Tracking & Telemetry:** `categories/tracking.txt`

---

## ⚙️ Integration Guides

### 1. Pi-hole / AdGuard Home
1. Copy the raw URL for either `master/domains.txt` or a specific category list.
2. In your **Pi-hole** admin dashboard:
   - Navigate to **Adlists**.
   - Paste the URL under **Address** and add a comment.
   - Run `pihole -g` in terminal or click **Update Gravity**.
3. In **AdGuard Home**:
   - Go to **Filters** -> **DNS Blocklists**.
   - Click **Add Blocklist** -> **Add a custom list**.
   - Input list Name and URL, then click **Save**.

### 2. Local System Hosts File
You can append the contents of `master/hosts.txt` to your system's local hosts file:
*   **Linux / macOS:** `/etc/hosts`
*   **Windows:** `C:\Windows\System32\drivers\etc\hosts`

### 3. Browser Extensions (uBlock Origin / AdGuard)
1. Open the extension dashboard/settings.
2. Navigate to **Filter lists** (or **My Filters**).
3. Scroll to the bottom and check **Import** under Custom.
4. Paste the raw link to `master/adblock.txt` and click **Apply changes**.

---

## 🚀 Setup & Actions Configuration

To ensure the GitHub Actions daily workflow succeeds in committing and pushing changes:

1. Go to your repository settings on GitHub.
2. Navigate to **Actions** -> **General**.
3. Under **Workflow permissions**, select **Read and write permissions**.
4. Check **Allow GitHub Actions to create and approve pull requests**.
5. Save settings.

---

## 🛠️ Local Development

If you wish to run the compilation script locally:

1. Install Python 3.10+
2. Create virtual environment & install requirements:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Run the generator script:
   ```bash
   python scripts/update_blacklist.py
   ```
4. Customize feeds inside [config.yaml](file:///home/who/Documents/AI-Coding/Github/blackList/config.yaml) and whitelists inside [whitelist.txt](file:///home/who/Documents/AI-Coding/Github/blackList/whitelist.txt).
