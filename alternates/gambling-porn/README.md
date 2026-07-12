# 🛡️ blackList - Alternate: gambling-porn

This directory contains the compiled **gambling-porn** blocklist.

*   **Status**: Active
*   **Total blocked domains**: `3,958,751`
*   **Target audience**: Alternate blocklist configuration. Combines the base security blocklist with: malware, phishing, cryptomining, ads, tracking, gambling, nsfw.

---

## 📦 Blocked Categories & Domain Types

This configuration contains lists designed to block the following domain categories:

| Category | Blocked Domains | Description |
| -------- | --------------- | ----------- |
| 🔴 **Malware Sites** | `1,841,096` | Command & control servers, distribution endpoints, ransomware, and spyware platforms. |
| 🔴 **Phishing Pages** | `120,620` | Fraudulent login pages, credential harvesting forms, and identity spoofing sites. |
| 🔴 **Cryptomining** | `297` | Cryptojacking scripts, browser miners, and pool connection endpoints. |
| 🔴 **Advertising Domains** | `565,997` | Ad delivery networks, promotional servers, and banner scripting endpoints. |
| 🔴 **Tracking & Telemetry** | `714,857` | Analytics scripts, user profiling telemetry, and commercial data harvesting domains. |
| 🔴 **Gambling & Casinos** | `353,368` | Online betting sites, slot machines, lottery portals, and digital casinos. |
| 🔴 **NSFW (Adult) Content** | `1,025,290` | Pornography, adult video portals, online dating platforms, and age-restricted domains. |

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
