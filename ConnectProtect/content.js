// =============================================================================
// ConnectProtect — Content Script (content.js)  v2.0
// Handles link interception and the "Cognitive Speed Bump" modal.
// Detection logic is fully delegated to engine.js (cp_analyzeURL).
// =============================================================================

'use strict';

// ---------------------------------------------------------------------------
// LAYER 1: LINK INTERCEPTION WITH DEBOUNCE
// ---------------------------------------------------------------------------

let cp_lastClickTime = 0;

// Event: document.addEventListener('click')
// - Listens globally for click events on the webpage.
// - Finds the nearest hyperlinked anchor tag (<a>).
// - Discards links that do not begin with 'http'.
// - Debounces clicking actions: rejects clicks within 600ms of a previous click to prevent multiple modals.
// - Cancels standard browser navigation using preventDefault().
// - Dispatches the link to cp_processURL for inspection.
document.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (!link || !link.href.startsWith('http')) return;

    const now = Date.now();

    // Debounce: ignore repeated clicks within 600ms (prevents double-modal)
    if (now - cp_lastClickTime < 600) {
        e.preventDefault();
        return;
    }

    e.preventDefault();
    cp_lastClickTime = now;

    cp_processURL(link.href);
}, true); // Use capture phase for better compatibility with SPA frameworks

// ---------------------------------------------------------------------------
// LAYER 2: DETERMINISTIC FILTERING
// ---------------------------------------------------------------------------

// Function: cp_processURL
// - Inputs: rawUrl (string).
// - Step 1: Checks if rawUrl matches engine.js's built-in global whitelist, navigating immediately if matched.
// - Step 2: Queries local Chrome storage for user-defined whitelist and blocklist arrays.
// - Step 3: Resolves wrapped/redirect URL targets to check the actual destination.
// - Step 4: Extracts the clean hostname from the URL.
// - Step 5: Bypasses scanner and redirects the browser if the hostname is found on the user's whitelist.
// - Step 6: Halts execution and presents a red blocked toast if the hostname is found on the user's blocklist.
// - Step 7: Dispatches rawUrl to the AI analysis engine (engine.js) to calculate risk features.
// - Step 8: Displays the Speed Bump warning modal with the AI's risk calculation.
async function cp_processURL(rawUrl) {
    // 1. Global whitelist check (engine.js)
    if (cp_isWhitelisted(rawUrl)) {
        window.location.href = rawUrl;
        return;
    }

    try {
        chrome.storage.local.get(['whitelist', 'blocklist'], (stored) => {
            if (chrome.runtime.lastError) return; // context gone
            const userWhitelist = (stored && stored.whitelist) || [];
            const blocklist = (stored && stored.blocklist) || [];
            const targetUrl = typeof cp_extractWrappedURL === 'function' ? cp_extractWrappedURL(rawUrl) : rawUrl;
            const hostname = cp_getHostname(targetUrl);

            if (userWhitelist.some(d => hostname.endsWith(d))) {
                window.location.href = rawUrl;
                return;
            }

            if (blocklist.some(d => hostname.endsWith(d))) {
                cp_showToast(`🚨 Blocked: ${hostname} is on your Blocklist.`);
                return;
            }

            const result = cp_analyzeURL(rawUrl);
            cp_showSpeedBump(rawUrl, result);
        });
    } catch (err) {
        window.location.href = rawUrl;
    }
}

// ---------------------------------------------------------------------------
// LAYER 3: TOAST NOTIFICATION (for blocklist hits)
// ---------------------------------------------------------------------------

// Function: cp_showToast
// - Inputs: msg (string).
// - Step 1: Determines background color based on message content (green for whitelist, red for blocks).
// - Step 2: Dynamically builds a styled overlay element containing the toast message.
// - Step 3: Mounts the toast overlay container directly into the active document element.
// - Step 4: Triggers a smooth opacity fade-in transition using requestAnimationFrame.
// - Step 5: Dismisses and deletes the toast element after a 3.5-second timeout window.
function cp_showToast(msg) {
    const isWhitelist = msg.toLowerCase().includes('whitelist');
    const bgColor = isWhitelist ? '#27ae60' : '#c0392b';
    const toast = document.createElement('div');
    toast.style.cssText = `
        all: initial;
        position: fixed !important;
        top: 20px !important;
        left: 50% !important;
        transform: translateX(-50%) !important;
        background: ${bgColor} !important;
        color: white !important;
        padding: 12px 24px !important;
        border-radius: 8px !important;
        z-index: 2147483647 !important;
        font-family: 'Segoe UI', sans-serif !important;
        font-size: 14px !important;
        box-shadow: 0 10px 25px rgba(0,0,0,0.4) !important;
        opacity: 0 !important;
        transition: opacity 0.3s !important;
        white-space: nowrap !important;
    `;
    toast.innerText = msg;
    document.documentElement.appendChild(toast);
    requestAnimationFrame(() => { toast.style.opacity = '1'; });
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 350);
    }, 3500);
}

// ---------------------------------------------------------------------------
// LAYER 4: SPEED BUMP MODAL (XAI UI)
// ---------------------------------------------------------------------------

function cp_escapeHTML(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Function: cp_showSpeedBump
// - Inputs: rawUrl (string), result (object containing AI analytics).
// - Step 1: Safeguards against duplicate modal instances by returning if the Speed Bump overlay already exists.
// - Step 2: Sets a risk-tier class based on score threshold (>35% is high risk).
// - Step 3: Compiles all matched continuous and binary security flag pills.
// - Step 4: Computes gauge dimensions (SVG circle arc) relative to the calculated percentage score.
// - Step 5: Creates and injects the modal dialog HTML structure including styling, background image, and gauges.
// - Step 6: Registers click events on the backdrop overlay to remove itself upon background clicks.
// - Step 7: Mounts the "Proceed" button handler to dismiss the warning and navigate to the requested URL.
// - Step 8: Mounts the "Open in new tab" button handler to spawn a new browsing tab.
// - Step 9: Mounts the "Cancel" button handler to dismiss the modal without action.
// - Step 10: Mounts the "Whitelist" button handler to add the domain to user whitelist and trigger a success toast.
// - Step 11: Mounts the "Block" button handler to add the domain to user blocklist and trigger a block toast.
function cp_showSpeedBump(rawUrl, result) {
    if (document.getElementById('cp-speedbump-overlay')) return;

    const { probability, riskLevel, color, narrative, features, latency, modelTrace, decisionPath } = result;
    const threshold = (modelTrace && modelTrace.threshold) || 36;
    const modelId = (modelTrace && modelTrace.modelId) || 'CP-EDGE';
    const safeRawUrl = cp_escapeHTML(rawUrl);
    const safeNarrative = cp_escapeHTML(narrative);
    const traceHtml = (decisionPath || [])
        .map(step => `<li>${cp_escapeHTML(step)}</li>`)
        .join('');
    const riskClass = probability >= threshold ? 'cp-risk-high' : 'cp-risk-low';

    // Build metric pills HTML
    const flags = [];
    // High-confidence binary signals (red)
    if (features.hasIPAddress) flags.push(['IP Address', '#c0392b']);
    if (features.hasPunycode) flags.push(['Punycode/IDN', '#c0392b']);
    if (features.hasAtSign) flags.push(['@ Sign', '#c0392b']);
    if (features.hasNumericMainDomain) flags.push(['Numeric Domain', '#c0392b']);
    if (features.hasBrandKeywordInHost) flags.push(['Brand Impersonation', '#c0392b']);
    if (features.minDistance <= 3 && features.minDistance > 0)
        flags.push(['Typosquatting Detected', '#c0392b']);
    // Moderate signals (orange)
    if (features.hasSuspiciousTLD) flags.push(['Risky TLD', '#e67e22']);
    if (features.hasSuspiciousPathKeyword) flags.push(['Suspicious Path', '#e67e22']);
    if (features.hasRedirectPattern) flags.push(['Redirect Pattern', '#e67e22']);
    if (features.hasExcessiveHyphens) flags.push(['Excess Hyphens', '#e67e22']);
    if (features.hasNumericSubdomain) flags.push(['Numeric Subdomain', '#e67e22']);
    if (features.hasLongSubdomain) flags.push(['Long Subdomain', '#e67e22']);
    if (features.hasNoHttps) flags.push(['No HTTPS', '#c0392b']);
    // Continuous signals — only shown when they actually contribute to score
    if (features.subdomainDepth >= 3)
        flags.push([`Deep Subdomains (${features.subdomainDepth}lvl)`, '#e67e22']);
    else if (features.subdomainDepth === 2)
        flags.push([`Subdomain Layers (${features.subdomainDepth})`, '#7f8c8d']);
    if (features.entropy > 4.0)
        flags.push([`High Entropy (${features.entropy.toFixed(2)})`, '#e67e22']);
    else if (features.entropy > 3.5)
        flags.push([`Elevated Entropy (${features.entropy.toFixed(2)})`, '#7f8c8d']);
    if (features.length > 75)
        flags.push([`Very Long URL (${features.length}c)`, '#e67e22']);
    else if (features.length > 50)
        flags.push([`Long URL (${features.length}c)`, '#7f8c8d']);
    const segCount = (features.pathPart.match(/\//g) || []).length;
    if (segCount > 4)
        flags.push([`Deep Path (${segCount} segments)`, '#7f8c8d']);

    const pillsHtml = flags.length > 0
        ? flags.map(([label, bg]) =>
            `<span style="all:initial;display:inline-block!important;background:${bg}!important;color:white!important;
             font-size:11px!important;padding:3px 8px!important;border-radius:12px!important;
             margin:2px!important;font-family:'Segoe UI',sans-serif!important;font-weight:bold!important;">
             ${cp_escapeHTML(label)}</span>`
        ).join('')
        : `<span style="all:initial;display:inline-block!important;background:#27ae60!important;color:white!important;
           font-size:11px!important;padding:3px 8px!important;border-radius:12px!important;
           font-family:'Segoe UI',sans-serif!important;font-weight:bold!important;">No flags detected</span>`;

    // Gauge arc (SVG)
    const radius = 36;
    const circumference = 2 * Math.PI * radius;
    const arcLength = (probability / 99) * circumference;

    const overlay = document.createElement('div');
    overlay.id = 'cp-speedbump-overlay';

    overlay.innerHTML = `
        <div id="cp-modal" style="background: rgba(15, 20, 25, 0.85) url('${chrome.runtime.getURL('Tech_bg.avif')}') no-repeat center center / cover !important; background-blend-mode: overlay !important;">
            <div id="cp-modal-header" class="${riskClass}">
                🛡️ ConnectProtect — ${riskLevel}
            </div>
            <div id="cp-modal-body">

                <div style="display:flex!important;align-items:center!important;gap:20px!important;margin-bottom:18px!important;">
                    <!-- Score Gauge -->
                    <div style="flex-shrink:0!important;text-align:center!important;">
                        <svg width="90" height="90" viewBox="0 0 90 90" style="display:block!important;">
                            <circle cx="45" cy="45" r="${radius}" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="9"/>
                            <circle cx="45" cy="45" r="${radius}" fill="none" stroke="${color}" stroke-width="9"
                                stroke-dasharray="${arcLength.toFixed(1)} ${circumference.toFixed(1)}"
                                stroke-linecap="round"
                                transform="rotate(-90 45 45)"/>
                            <text x="45" y="46" text-anchor="middle" dominant-baseline="central"
                                font-size="18" font-weight="bold" fill="${color}" font-family="'Segoe UI',sans-serif">${probability}%</text>
                        </svg>
                        <div style="font-size:10px!important;color:#bdc3c7!important;font-family:'Segoe UI',sans-serif!important;margin-top:2px!important;">Risk Score</div>
                    </div>

                    <!-- URL Box -->
                    <div style="flex:1!important;min-width:0!important;">
                        <div style="font-size:11px!important;font-weight:bold!important;color:#bdc3c7!important;text-transform:uppercase!important;letter-spacing:0.5px!important;font-family:'Segoe UI',sans-serif!important;margin-bottom:4px!important;">Destination URL</div>
                        <div id="cp-url-box">${safeRawUrl}</div>
                    </div>
                </div>

                <!-- XAI Narrative -->
                <div id="cp-xai-box">
                    <strong style="font-size:11px!important;text-transform:uppercase!important;letter-spacing:0.5px!important;color:#bdc3c7!important;">Generated XAI Narrative</strong><br>
                    <span style="font-size:13px!important;">${safeNarrative}</span>
                </div>

                <!-- Metric Flags -->
                <div style="margin-bottom:14px!important;">
                    <div style="font-size:11px!important;font-weight:bold!important;color:#bdc3c7!important;text-transform:uppercase!important;letter-spacing:0.5px!important;font-family:'Segoe UI',sans-serif!important;margin-bottom:5px!important;">Detected Signals</div>
                    <div>${pillsHtml}</div>
                </div>

                <!-- Footer Metrics -->
                <div id="cp-metrics">
                    <span>Entropy: ${features.entropy.toFixed(2)}</span>
                    <span>Model: ${cp_escapeHTML(modelId)}</span>
                    <span>Threshold: ${threshold}%</span>
                    <span>Latency: ${latency}ms</span>
                </div>

                <div id="cp-trace-box">
                    <strong>Decision Trace</strong>
                    <ol>${traceHtml}</ol>
                </div>

                <!-- Action Buttons -->
                <div id="cp-btn-group">
                    <button class="cp-btn cp-btn-safe"    id="cp-btn-proceed">✔ Proceed</button>
                    <button class="cp-btn cp-btn-newtab"  id="cp-btn-newtab">↗ Open in new tab</button>
                    <button class="cp-btn cp-btn-whitelist" id="cp-btn-whitelist">＋ Whitelist</button>
                    <button class="cp-btn cp-btn-block"   id="cp-btn-block">⊘ Block</button>
                    <button class="cp-btn cp-btn-cancel"  id="cp-btn-cancel" style="grid-column:1/-1!important;">✕ Cancel</button>
                </div>
            </div>
        </div>
    `;

    document.documentElement.appendChild(overlay);

    // --- Button handlers ---
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.remove();
    });

    document.getElementById('cp-btn-proceed').onclick = () => { overlay.remove(); window.location.href = rawUrl; };
    document.getElementById('cp-btn-newtab').onclick = () => { window.open(rawUrl, '_blank', 'noopener,noreferrer'); overlay.remove(); };
    document.getElementById('cp-btn-cancel').onclick = () => overlay.remove();

    document.getElementById('cp-btn-whitelist').onclick = () => {
        cp_addToList('whitelist', result.hostname, () => {
            cp_showToast('Successfully Whitelisted');
            overlay.remove();
        });
    };

    document.getElementById('cp-btn-block').onclick = () => {
        cp_addToList('blocklist', result.hostname, () => {
            cp_showToast('Successfully Blocked');
            overlay.remove();
        });
    };
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

// Function: cp_addToList
// - Inputs: type (string), domain (string), callback (function).
// - Step 1: Retrieves the existing local storage array corresponding to the type (whitelist/blocklist).
// - Step 2: Verifies if the target domain name is already contained in the retrieved collection.
// - Step 3: Prepends the domain at index 0 of the array list if it is not a duplicate.
// - Step 4: Commits the newly updated collection back to Chrome's local storage database.
// - Step 5: Fires the provided callback function upon successful storage confirmation.
function cp_addToList(type, domain, callback) {
    chrome.storage.local.get([type], (result) => {
        const list = result[type] || [];
        if (!list.includes(domain)) {
            list.unshift(domain);
            const update = {};
            update[type] = list;
            chrome.storage.local.set(update, callback);
        } else {
            callback && callback();
        }
    });
}

// ---------------------------------------------------------------------------
// MESSAGE LISTENER (From background script)
// ---------------------------------------------------------------------------
// Event: chrome.runtime.onMessage.addListener
// - Listens for incoming runtime messaging events from background scripts.
// - Checks if the incoming message requested the "showToast" action.
// - Forwards the text content message payload directly to cp_showToast.
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "showToast") {
        cp_showToast(request.message);
    }
});
