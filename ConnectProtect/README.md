# ConnectProtect (Project CAUGHTPHISH) — AI Agent Technical Brief

**Thesis Title:** *CONNECTPROTECT: A POST CLICK SCAN WEB BROWSER-INTEGRATED SYSTEM THROUGH EDGE-BASED AI AND GENERATIVE AI FOR MALICIOUS URLS*

---

## Project Overview
ConnectProtect is a Chrome browser extension (Manifest V3) that detects phishing URLs in real-time using a **"Cognitive Speed Bump"** approach. When a user clicks a link, the extension intercepts navigation, runs an Edge-AI analysis, and displays a risk report before allowing the browser to proceed.

**Version 2.0 introduces a unified detection engine (`engine.js`) so the Speed Bump modal and the Popup manual scanner always produce identical results for the same URL.**

---

## File Glossary

| File | Role |
|---|---|
| `engine.js` | **[NEW v2.0]** Unified Edge-AI detection engine. The single source of truth for all URL analysis math. |
| `content.js` | Link interception, debounce logic, Speed Bump modal rendering. Calls `engine.js`. |
| `popup.js` | Extension dashboard controller, manual scan, list management. Calls `engine.js`. |
| `popup.html` | Extension popup UI structure. Loads `engine.js` before `popup.js`. |
| `popup.css` | Popup UI styles (v2.0 — Inter font, 3-stat grid, rich result card). |
| `inject.css` | Hardened Speed Bump modal styles injected into host pages. |
| `manifest.json` | Extension metadata. Loads `engine.js` + `content.js` as content scripts. |
| `global_Whitelist.js` | Legacy file (whitelist is now maintained inside `engine.js` as `CP_GLOBAL_WHITELIST`). |

---

## System Architecture (v2.0)

```
                ┌─────────────────────────────────────┐
                │           engine.js (v2.0)           │
                │  cp_analyzeURL(rawUrl) → result {}   │
                │  cp_isWhitelisted(rawUrl) → bool     │
                └──────────┬──────────────┬────────────┘
                           │              │
               ┌───────────▼───┐    ┌─────▼──────────┐
               │  content.js   │    │   popup.js      │
               │  Speed Bump   │    │  Manual Scan    │
               │  Modal (XAI)  │    │  Result Card    │
               └───────────────┘    └─────────────────┘
```

### Layer 1 — Interception & Debounce (`content.js`)
- Listens on `click` events in capture phase for broad compatibility.
- 600ms debounce window prevents double-modal from accidental double-clicks.

### Layer 2 — Deterministic Filtering (`content.js` + `engine.js`)
- Checks against `CP_GLOBAL_WHITELIST` (20+ trusted domains including PH banks).
- Checks user's personal whitelist and blocklist from `chrome.storage.local`.

### Layer 3 — Edge-AI Inference Engine (`engine.js`)
The **`cp_analyzeURL()`** function computes a 0–99% probability score from these signals:

| Signal | Weight | Description |
|---|---|---|
| URL Length | `0.003` per char >30 | Long URLs are mildly suspicious |
| Subdomain Depth | `0.12` per level | Deep nesting obscures real domain |
| Shannon Entropy | `0.08×` | Randomness = obfuscated domains |
| Levenshtein d=1 | `+0.45` | Very close match to a brand (typosquatting) |
| Levenshtein d=2 | `+0.30` | Close match |
| Levenshtein d=3 | `+0.15` | Moderate match |
| IP Address | `+0.55` | IP used instead of domain name |
| Suspicious TLD | `+0.28` | `.xyz`, `.tk`, `.top`, `.loan`, etc. |
| Punycode/IDN | `+0.35` | Homoglyph attack indicator (`xn--`) |
| @ Sign in URL | `+0.40` | Classic phishing redirect trick |
| Excess Hyphens | `+0.15` | >2 hyphens in hostname |
| Numeric Subdomain | `+0.20` | Subdomain is a bare number |
| Long Subdomain | `+0.18` | Subdomain segment >20 chars |

**Protected Targets (Levenshtein comparison list):**
PH: bdo.com.ph, gcash.com, bpi.com.ph, metrobank.com.ph, unionbankph.com, maya.ph, landbank.com, pnb.com.ph
Global: paypal.com, wise.com, stripe.com, facebook.com, google.com, apple.com, microsoft.com, amazon.com, netflix.com, instagram.com, twitter.com, linkedin.com, github.com

### Layer 4 — Explainable AI (XAI) UI (`inject.css`, `popup.html`, `popup.js`)
- **Speed Bump:** Animated modal with SVG risk gauge, URL box, AI narrative, signal pills, metric footer, and 4-action button grid.
- **Popup:** Rich result card with SVG gauge, risk badge, narrative, metric pills, and detail rows (entropy, closest target, subdomain depth, latency).

---

## Current Phase: Chapter 4 (Technical Testing)
Gathering data for a 2×2 Confusion Matrix using 40 test URLs (20 Safe, 20 Malicious).

- **Metrics:** Accuracy, Precision, Recall, F1-Score, Mean Latency (ms).
- **Protocol:** Use the Popup "Paste URL" scanner to record scores. The score is now identical to what the Speed Bump modal would show for the same URL.
- **Developer Note:** To force AI scanning on whitelisted sites for data collection, comment out the `cp_isWhitelisted` check in `content.js` Layer 2.

---

## Recent Changes (v2.0)
- **[NEW]** `engine.js` — Unified detection engine eliminates all score divergence between content script and popup.
- **[IMPROVED]** 13 heuristic signals (was 4) including IP detection, suspicious TLD, punycode, @ sign, subdomain depth analysis.
- **[IMPROVED]** Levenshtein now uses a gradient penalty (d=1: 0.45, d=2: 0.30, d=3: 0.15) instead of a flat penalty.
- **[IMPROVED]** Protected targets expanded from 4 to 21 domains.
- **[IMPROVED]** Speed Bump modal rebuilt with SVG gauge ring, signal pills, no inline `<style>` blocks.
- **[IMPROVED]** Popup result card now shows gauge, risk badge, narrative, pills, and a detail metric grid.
- **[FIXED]** CSS leakage: `inject.css` uses `all: initial !important` on overlay to fully reset host-page styles.
- **[FIXED]** Capture-phase click listener in `content.js` for better SPA framework compatibility.
