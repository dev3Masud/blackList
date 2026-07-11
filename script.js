/* ==========================================================================
   THREAT REGISTRY DASHBOARD CONTROLLER (script.js)
   --------------------------------------------------------------------------
   Manages client-side database lookup (with subdomain matching), statistics
   parsing, dynamic lists, tab controls, and clipboard copy operations.
   ========================================================================== */

let blacklistData = null;
let globalStats = null;

document.addEventListener("DOMContentLoaded", () => {
  initDashboard();
  setupTabs();
});

// Fetch stats.json compiled by pipeline
function initDashboard() {
  fetch("stats.json")
    .then(response => {
      if (!response.ok) throw new Error("Stats not available");
      return response.json();
    })
    .then(data => {
      globalStats = data;
      renderAnalytics(data);
    })
    .catch(err => {
      console.error("Error loading registry stats:", err);
      const stamp = document.getElementById("update-timestamp");
      if (stamp) stamp.innerText = "Error loading stats database.";
    });
}

// Render dynamic elements
function renderAnalytics(stats) {
  // Update timestamp
  const date = new Date(stats.last_updated);
  const timeStr = date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  
  const updateEl = document.getElementById("update-timestamp");
  if (updateEl) {
    updateEl.innerText = `Updated: ${timeStr} (${timezone})`;
  }

  // Counters (with simple countUp transition effect)
  animateCounter("stat-total", stats.total_domains);
  animateCounter("stat-categories", Object.keys(stats.categories).length);
  animateCounter("stat-feeds", stats.feeds.length);

  // Categories Grid Cards
  const categoryContainer = document.getElementById("categories-container");
  if (categoryContainer) {
    categoryContainer.innerHTML = "";
    Object.entries(stats.categories).forEach(([name, count]) => {
      const card = document.createElement("div");
      card.className = "category-card";
      card.innerHTML = `
        <div class="category-header">
          <span class="category-title">${name}</span>
          <span class="category-count">${count.toLocaleString()}</span>
        </div>
        <div class="category-download-actions">
          <a href="categories/${name}.txt" class="btn btn-secondary btn-sm" download>
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            <span>List</span>
          </a>
          <button class="btn btn-secondary btn-sm" onclick="copyText('categories/${name}.txt')">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
            <span>Copy URL</span>
          </button>
        </div>
      `;
      categoryContainer.appendChild(card);
    });
  }

  // Upstream Feed Status Table
  const tableBody = document.getElementById("feeds-table-body");
  if (tableBody) {
    tableBody.innerHTML = "";
    
    // Sort feeds by success status then name
    const sortedFeeds = [...stats.feeds].sort((a, b) => {
      if (a.success === b.success) return a.name.localeCompare(b.name);
      return a.success ? -1 : 1;
    });

    sortedFeeds.forEach(feed => {
      const row = document.createElement("tr");
      const statusBadge = feed.success 
        ? `<span class="badge-status status-online"><span class="badge-status-dot"></span>Active</span>` 
        : `<span class="badge-status status-offline" title="${feed.error || 'Unknown Connection Failure'}"><span class="badge-status-dot"></span>Offline</span>`;
      
      row.innerHTML = `
        <td style="font-weight: 600; color: var(--text-primary);">${feed.name}</td>
        <td style="text-transform: capitalize; color: var(--text-secondary);">${feed.category}</td>
        <td>${statusBadge}</td>
        <td style="font-family: var(--font-mono); text-align: right; color: var(--text-primary);">${feed.count.toLocaleString()}</td>
      `;
      tableBody.appendChild(row);
    });
  }
}

// Animate Counters
function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  
  let start = 0;
  const duration = 1000;
  const stepTime = Math.abs(Math.floor(duration / target));
  
  // Cap stepTime so it runs smoothly
  const increment = Math.ceil(target / 40); 
  const timer = setInterval(() => {
    start += increment;
    if (start >= target) {
      el.innerText = target.toLocaleString();
      clearInterval(timer);
    } else {
      el.innerText = start.toLocaleString();
    }
  }, 20);
}

// Setup Tab Controls
function setupTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  const views = document.querySelectorAll(".tab-view");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetView = tab.getAttribute("data-tab");

      tabs.forEach(t => t.classList.remove("active"));
      views.forEach(v => v.classList.remove("active"));

      tab.classList.add("active");
      
      const activeView = document.getElementById(`view-${targetView}`);
      if (activeView) activeView.classList.add("active");
    });
  });
}

// Check domain (with Wildcard Subdomain matching using sharded lookup database)
async function checkDomain() {
  const queryInput = document.getElementById("domain-query");
  const searchResult = document.getElementById("search-result");
  
  if (!queryInput || !searchResult) return;
  
  let query = queryInput.value.trim().toLowerCase();

  if (!query) {
    searchResult.style.display = "none";
    return;
  }

  // Parse URLs
  try {
    if (query.includes("://") || query.startsWith("www.")) {
      let temp = query;
      if (!temp.includes("://")) temp = "http://" + temp;
      query = new URL(temp).hostname;
    }
  } catch(e) {}

  query = query.replace(/^www\./, "");
  
  // Show loading indicator
  searchResult.style.display = "block";
  searchResult.className = "search-result loading";
  searchResult.innerHTML = `
    <span class="spinner"></span>
    <span>Checking security registry database...</span>
  `;

  // Helper to fetch shard and check domain
  async function lookupInShard(domain) {
    try {
      // 1. Compute SHA-256 hex string of domain in Javascript
      const msgBuffer = new TextEncoder().encode(domain);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      // First 2 hex characters determine the shard file
      const shardPrefix = hashHex.substring(0, 2);
      
      // Fetch the specific shard file (only ~50KB)
      const response = await fetch(`lookup/${shardPrefix}.json`);
      if (!response.ok) {
        // If file doesn't exist, domain is not blocked
        if (response.status === 404) return null;
        throw new Error(`Failed to load lookup shard ${shardPrefix}`);
      }
      
      const shardData = await response.json();
      return shardData[domain] || null;
    } catch (err) {
      console.error("Lookup error:", err);
      return null;
    }
  }

  // 1. Direct Match Check
  const directCategories = await lookupInShard(query);
  if (directCategories) {
    renderMatchResult(query, directCategories);
    return;
  }

  // 2. Wildcard Parent Domain Check (e.g. sub.badsite.com -> badsite.com)
  const parts = query.split('.');
  for (let i = 1; i < parts.length; i++) {
    const parent = parts.slice(i).join('.');
    const parentCategories = await lookupInShard(parent);
    if (parentCategories) {
      renderMatchResult(query, parentCategories, parent);
      return;
    }
  }

  // Safe result
  searchResult.className = "search-result result-safe";
  searchResult.innerHTML = `
    <div style="display:flex; align-items:center; gap: 10px;">
      <svg class="check-icon" xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
      <div>
        <strong>Domain is Safe:</strong> "${query}" is not found in active blacklist registries.
      </div>
    </div>
  `;
}

// Render blocked results
function renderMatchResult(queriedDomain, categories, blockedParent = null) {
  const searchResult = document.getElementById("search-result");
  const categoryBadges = categories.map(cat => `<span class="threat-badge">${cat.toUpperCase()}</span>`).join(" ");
  
  let matchedMessage = `Blocked under: ${categoryBadges}`;
  if (blockedParent) {
    matchedMessage = `Blocked by wildcard parent domain: <strong>${blockedParent}</strong><br><div style="margin-top: 8px;">Categories: ${categoryBadges}</div>`;
  }

  searchResult.className = "search-result result-blocked";
  searchResult.innerHTML = `
    <div style="display:flex; align-items:flex-start; gap: 10px;">
      <svg class="alert-icon" xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
      <div>
        <strong>⚠️ Security Threat Blocked:</strong> "${queriedDomain}" is blacklisted.
        <div style="margin-top: 10px; font-size: 0.9rem;">${matchedMessage}</div>
      </div>
    </div>
  `;
}

// Clipboard Copy Helper
function copyText(subpath) {
  const absoluteUrl = window.location.origin + window.location.pathname.replace("index.html", "") + subpath;
  
  navigator.clipboard.writeText(absoluteUrl).then(() => {
    const btn = event.currentTarget;
    const originalContent = btn.innerHTML;
    
    btn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
      <span>Copied!</span>
    `;
    btn.classList.add("copy-success");
    
    setTimeout(() => {
      btn.innerHTML = originalContent;
      btn.classList.remove("copy-success");
    }, 1500);
  }).catch(err => {
    console.error("Could not copy URL:", err);
  });
}

// Disclaimer Modal Controller
function openDisclaimer() {
  const modal = document.getElementById("disclaimer-modal");
  if (modal) {
    modal.classList.add("active");
    modal.setAttribute("aria-hidden", "false");
    
    // Add event listeners to close elements
    const closeElements = modal.querySelectorAll(".modal-close-btn, .modal-overlay, .modal-close-btn-action");
    closeElements.forEach(el => {
      el.addEventListener("click", closeDisclaimer);
    });

    // Close on Escape key press
    document.addEventListener("keydown", handleEscapeKey);
  }
}

function closeDisclaimer() {
  const modal = document.getElementById("disclaimer-modal");
  if (modal) {
    modal.classList.remove("active");
    modal.setAttribute("aria-hidden", "true");
    document.removeEventListener("keydown", handleEscapeKey);
  }
}

function handleEscapeKey(e) {
  if (e.key === "Escape") {
    closeDisclaimer();
  }
}
