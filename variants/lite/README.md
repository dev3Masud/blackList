# 🛡️ blackList - Lite Variant

This directory contains the compiled **Lite** blocklist variant.

*   **Status**: Active
*   **Total blocked domains**: `100,000`
*   **Target audience**: Designed for maximum speed and stability. Targets high-severity security threats like malware, phishing, and cryptomining. Near-zero false positives.

---

## 📦 Blocked Categories & Domain Types

This variant contains lists designed to block the following domain categories:

| Category | Type of Domains Blocked |
| -------- | ----------------------- |
| 🔴 **Malware Sites** | Command & control servers, distribution endpoints, ransomware, and spyware platforms. |
| 🔴 **Phishing Pages** | Fraudulent login pages, credential harvesting forms, and identity spoofing sites. |
| 🔴 **Cryptomining** | Cryptojacking scripts, browser miners, and pool connection endpoints. |

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
