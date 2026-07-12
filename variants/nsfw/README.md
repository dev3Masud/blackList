# 🛡️ blackList - Nsfw Variant

This directory contains the compiled **nsfw** blocklist.

*   **Status**: Active
*   **Total blocked domains**: `1,027,649`
*   **Target audience**: Dedicated blocklist for filtering adult content, pornography, and age-restricted domains. Ideal for parental controls.

---

## 📦 Blocked Categories & Domain Types

This configuration contains lists designed to block the following domain categories:

| Category | Blocked Domains | Description |
| -------- | --------------- | ----------- |
| 🔴 **NSFW (Adult) Content** | `1,027,649` | Pornography, adult video portals, online dating platforms, and age-restricted domains. |

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
