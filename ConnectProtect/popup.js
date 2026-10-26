// =============================================================================
// ConnectProtect — Popup Script (popup.js)  v2.0
// All detection logic delegated to engine.js (cp_analyzeURL).
// =============================================================================

'use strict';

function cp_escapePopupHTML(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Event: DOMContentLoaded
// - Triggers when the extension popup HTML structure has fully loaded in the browser.
// - Establishes critical DOM element references.
// - Populates statistical count values (whitelist/blocklist length) from local storage.
// - Restores previous session details (scan counter, input field text, last scan results) from session storage.
// - Binds typing and keypress triggers (like Enter key scans) to the URL input bar.
// - Mounts standard user action click listeners for scanning, lists, and modal close triggers.
document.addEventListener('DOMContentLoaded', () => {

    // -------------------------------------------------------------------------
    // DOM References
    // -------------------------------------------------------------------------
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultDiv = document.getElementById('scanResult');

    // -------------------------------------------------------------------------
    // Initialize stats from storage
    // -------------------------------------------------------------------------
    chrome.storage.local.get(['blocklist'], (res) => {
        document.getElementById('blockCount').innerText = res.blocklist ? res.blocklist.length : 0;
    });

    chrome.storage.local.get(['whitelist'], (res) => {
        document.getElementById('whiteCount').innerText = res.whitelist ? res.whitelist.length : 0;
    });

    chrome.storage.session.get(['scanCount', 'lastUrl', 'lastResultState'], (res) => {
        document.getElementById('scanCount').innerText = res.scanCount || 0;
        if (res.lastUrl) urlInput.value = res.lastUrl;
        if (res.lastResultState) renderResult(res.lastResultState);
    });

    // Persist the URL input as the user types
    urlInput.addEventListener('input', () => {
        chrome.storage.session.set({ lastUrl: urlInput.value.trim() });
    });

    // Also trigger scan on Enter key
    urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') scanBtn.click();
    });

    // -------------------------------------------------------------------------
    // SCAN BUTTON — uses engine.js cp_analyzeURL()
    // -------------------------------------------------------------------------
    scanBtn.addEventListener('click', () => {
        const testUrl = urlInput.value.trim();
        if (!testUrl) {
            showInputError('Please enter a URL to scan.');
            return;
        }

        clearInputError();
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = `<div class="scanning-indicator">
            <span class="spinner"></span> Analyzing with Edge-AI…
        </div>`;

        // Small timeout so the "Analyzing…" UI actually renders before heavy work
        setTimeout(() => {
            // Increment session counter
            chrome.storage.session.get(['scanCount'], (res) => {
                const newCount = (res.scanCount || 0) + 1;
                chrome.storage.session.set({ scanCount: newCount });
                document.getElementById('scanCount').innerText = newCount;
            });

            // ---- THE ONLY ANALYSIS CALL — identical math as content.js ----
            const result = cp_analyzeURL(testUrl);
            // ----------------------------------------------------------------

            chrome.storage.session.set({ lastResultState: result });
            renderResult(result);

            // Reveal quick-add buttons now that we have a scanned URL
            const row = document.getElementById('scanActionRow');
            if (row) row.style.display = 'grid';
        }, 200);
    });

    // -------------------------------------------------------------------------
    // RENDER RESULT CARD
    // -------------------------------------------------------------------------
    // Function: renderResult
    // - Inputs: result (object detailing threat analysis).
    // - Step 1: Extracts critical metrics like riskLevel, brand comparisons, and latency values.
    // - Step 2: Normalizes and clamps the risk probability score between 1% and 99%.
    // - Step 3: Computes SVG circular coordinates to dynamically render the threat level indicator.
    // - Step 4: Analyzes triggered feature flags to formulate metric badge items.
    // - Step 5: Assigns a color tier based on calculated threat severity (high, borderline, safe).
    // - Step 6: Modifies card colors, background tinting, and constructs the result panel inner HTML content.
    function renderResult(result) {
        const { riskLevel, color, narrative, features, latency, hostname, modelTrace, decisionPath, xaiMode } = result;
        const threshold = (modelTrace && modelTrace.threshold) || 36;
        const modelId = (modelTrace && modelTrace.modelId) || 'CP-EDGE';
        const traceHtml = (decisionPath || [])
            .map(step => `<li>${cp_escapePopupHTML(step)}</li>`)
            .join('');

        // Guard: ensure probability is always a valid integer 1–99
        const probability = (Number.isFinite(result.probability) && result.probability >= 1)
            ? Math.min(99, Math.max(1, Math.round(result.probability)))
            : 1;

        // Gauge arc
        const radius = 30;
        const circ = 2 * Math.PI * radius;
        const arc = (probability / 99) * circ;

        // Metric pills
        const flags = [];
        if (features.hasIPAddress) flags.push({ label: 'IP Address', color: '#e74c3c' });
        if (features.hasPunycode) flags.push({ label: 'Punycode/IDN', color: '#e74c3c' });
        if (features.hasAtSign) flags.push({ label: '@ Sign', color: '#e74c3c' });
        if (features.hasNumericMainDomain) flags.push({ label: 'Numeric Domain', color: '#e74c3c' });
        if (features.hasBrandKeywordInHost) flags.push({ label: 'Brand Impersonation', color: '#e74c3c' });
        if (features.hasSuspiciousTLD) flags.push({ label: 'Risky TLD', color: '#e67e22' });
        if (features.hasSuspiciousPathKeyword) flags.push({ label: 'Suspicious Path', color: '#e67e22' });
        if (features.hasRedirectPattern) flags.push({ label: 'Redirect Pattern', color: '#e67e22' });
        if (features.hasExcessiveHyphens) flags.push({ label: 'Excess Hyphens', color: '#e67e22' });
        if (features.hasNumericSubdomain) flags.push({ label: 'Numeric Subdomain', color: '#e67e22' });
        if (features.hasLongSubdomain) flags.push({ label: 'Long Subdomain', color: '#e67e22' });
        if (features.hasNoHttps) flags.push({ label: 'No HTTPS', color: '#e74c3c' });
        if (features.subdomainDepth >= 3)
            flags.push({ label: `Deep Subdomains (${features.subdomainDepth}lvl)`, color: '#e67e22' });
        else if (features.subdomainDepth === 2)
            flags.push({ label: `Subdomain Layers (${features.subdomainDepth})`, color: '#7f8c8d' });
        if (features.entropy > 4.0)
            flags.push({ label: `High Entropy (${features.entropy.toFixed(2)})`, color: '#e67e22' });
        else if (features.entropy > 3.5)
            flags.push({ label: `Elevated Entropy (${features.entropy.toFixed(2)})`, color: '#7f8c8d' });
        if (features.length > 75)
            flags.push({ label: `Very Long URL (${features.length}c)`, color: '#e67e22' });
        else if (features.length > 50)
            flags.push({ label: `Long URL (${features.length}c)`, color: '#7f8c8d' });
        const segCount = (features.pathPart.match(/\//g) || []).length;
        if (segCount > 4)
            flags.push({ label: `Deep Path (${segCount} segments)`, color: '#7f8c8d' });

        // Determine overall risk tier for pill coloring
        const riskTierColor = probability >= threshold ? '#c0392b'       // HIGH RISK — red
                            : probability >= 31 ? '#e67e22'      // BORDERLINE — orange/yellow
                            : '#27ae60';                         // SAFE — green

        const pillsHtml = flags.length > 0
            ? flags.map(f => {
                // For high-risk URLs, promote all pill colors to match risk tier
                const pillColor = probability >= threshold ? '#c0392b'
                                : probability >= 31 ? '#e67e22'
                                : f.color;
                return `<span class="metric-pill" style="background:${pillColor}">${cp_escapePopupHTML(f.label)}</span>`;
              }).join('')
            : `<span class="metric-pill" style="background:${riskTierColor}">No Flags</span>`;


        // Color the result card border + subtle tint based on risk
        const bgTint = probability >= threshold ? '#fff5f5' : '#f0fff5';
        resultDiv.style.borderColor = color;
        resultDiv.style.background = bgTint;
        resultDiv.style.display = 'block';

        resultDiv.innerHTML = `
            <div class="result-top">
                <!-- Gauge -->
                <div class="gauge-wrap">
                    <svg width="70" height="70" viewBox="0 0 70 70">
                        <circle cx="35" cy="35" r="${radius}" fill="none" stroke="#ecf0f1" stroke-width="7"/>
                        <circle cx="35" cy="35" r="${radius}" fill="none" stroke="${color}" stroke-width="7"
                            stroke-dasharray="${arc.toFixed(1)} ${circ.toFixed(1)}"
                            stroke-linecap="round"
                            transform="rotate(-90 35 35)"/>
                        <text x="35" y="36" text-anchor="middle" dominant-baseline="central"
                            font-size="14" font-weight="bold" fill="${color}" font-family="'Segoe UI',sans-serif">
                            ${probability}%
                        </text>
                    </svg>
                    <div class="gauge-label">Risk Score</div>
                </div>

                <!-- Risk Level + URL -->
                <div class="result-info">
                    <span class="risk-badge" style="background:${color}">${cp_escapePopupHTML(riskLevel)}</span>
                    <div class="result-url">${cp_escapePopupHTML(hostname || result.normalizedUrl)}</div>
                </div>
            </div>

            <!-- Narrative -->
            <div class="result-narrative">${cp_escapePopupHTML(narrative)}</div>

            <div class="decision-trace">
                <div class="trace-title">Decision Trace</div>
                <ol>${traceHtml}</ol>
            </div>

            <!-- Pills -->
            <div class="pills-wrap">${pillsHtml}</div>

            <!-- Detail metrics -->
            <div class="detail-metrics">
                <div class="detail-row">
                    <span>Entropy</span><span>${features.entropy.toFixed(2)}</span>
                </div>
                <div class="detail-row">
                    <span>Subdomain Depth</span><span>${features.subdomainDepth}</span>
                </div>
                <div class="detail-row">
                    <span>Edge-AI Latency</span><span>${latency} ms</span>
                </div>
                <div class="detail-row">
                    <span>Model</span><span>${cp_escapePopupHTML(modelId)}</span>
                </div>
                <div class="detail-row">
                    <span>Risk Threshold</span><span>${threshold}%</span>
                </div>
                <div class="detail-row">
                    <span>XAI Mode</span><span>${cp_escapePopupHTML(xaiMode || 'Local generative XAI synthesis')}</span>
                </div>
            </div>
        `;
    }

    // -------------------------------------------------------------------------
    // INPUT ERROR HELPERS
    // -------------------------------------------------------------------------
    // Function: showInputError
    // - Inputs: msg (string).
    // - Step 1: Cleans up any existing input validation alerts.
    // - Step 2: Colors the input boundary border red.
    // - Step 3: Generates and mounts a red error notification element below the input field.
    function showInputError(msg) {
        clearInputError();
        urlInput.style.borderColor = '#e74c3c';
        const err = document.createElement('div');
        err.id = 'inputError';
        err.className = 'input-error';
        err.innerText = msg;
        urlInput.insertAdjacentElement('afterend', err);
    }

    // Function: clearInputError
    // - Step 1: Restores the default border styling of the input element.
    // - Step 2: Removes the validation error node from the document.
    function clearInputError() {
        urlInput.style.borderColor = '';
        const err = document.getElementById('inputError');
        if (err) err.remove();
    }

    // -------------------------------------------------------------------------
    // TOAST NOTIFICATION
    // -------------------------------------------------------------------------
    // Function: showPopupToast
    // - Inputs: message (string), isError (boolean).
    // - Step 1: Deletes active toast indicators from the DOM.
    // - Step 2: Instantiates a new container and appends the "cp-toast-error" class if isError is set.
    // - Step 3: Sets toast text content and mounts the node into the document body.
    // - Step 4: Triggers CSS slide-in and fade animations on sequential animation frames.
    // - Step 5: Automatically initiates slide-out and cleanup routines after 2.8 seconds.
    function showPopupToast(message, isError = false) {
        // Remove any existing toast first
        const old = document.querySelector('.cp-toast');
        if (old) old.remove();

        const toast = document.createElement('div');
        toast.className = 'cp-toast' + (isError ? ' cp-toast-error' : '');
        toast.textContent = message;
        document.body.appendChild(toast);

        // Trigger slide-in on next frame
        requestAnimationFrame(() => {
            requestAnimationFrame(() => toast.classList.add('cp-toast-show'));
        });

        // Auto-dismiss after 2.8 s
        setTimeout(() => {
            toast.classList.remove('cp-toast-show');
            setTimeout(() => toast.remove(), 300);
        }, 2800);
    }

    // -------------------------------------------------------------------------
    // SCAN-ACTION QUICK-ADD BUTTONS
    // -------------------------------------------------------------------------
    // Function: addScannedUrlToList
    // - Inputs: listType (string).
    // - Step 1: Fetches the cleaned URL string currently written inside the input field.
    // - Step 2: Validates the URL structure, prepending protocol scheme if necessary, and extracts the domain name.
    // - Step 3: Queries Chrome storage database for the corresponding collection (whitelist/blocklist).
    // - Step 4: Discards actions and displays a warning toast if the domain name is already registered in the selected list.
    // - Step 5: Appends the hostname into storage, updates count elements, and fires a green or red success toast.
    function addScannedUrlToList(listType) {
        const raw = urlInput.value.trim();
        if (!raw) { showPopupToast('No URL scanned yet.', true); return; }

        let hostname;
        try {
            let u = raw;
            if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
            hostname = new URL(u).hostname.replace(/^www\./, '').toLowerCase();
        } catch {
            showPopupToast('Invalid URL.', true);
            return;
        }

        const listLabel = listType === 'whitelist' ? 'Whitelist' : 'Blocklist';
        const countId   = listType === 'whitelist' ? 'whiteCount' : 'blockCount';

        chrome.storage.local.get([listType], (res) => {
            const list = res[listType] || [];
            if (list.includes(hostname)) {
                showPopupToast(`"${hostname}" is already in ${listLabel}.`, true);
                return;
            }
            list.push(hostname);
            chrome.storage.local.set({ [listType]: list }, () => {
                document.getElementById(countId).innerText = list.length;
                const emoji = listType === 'whitelist' ? '✅' : '🚫';
                showPopupToast(`${emoji} "${hostname}" added to ${listLabel}!`, listType === 'blocklist');
            });
        });
    }

    document.getElementById('whitelistScannedBtn').addEventListener('click', () => addScannedUrlToList('whitelist'));
    document.getElementById('blocklistScannedBtn').addEventListener('click', () => addScannedUrlToList('blocklist'));

    // =========================================================================
    // LIST MANAGEMENT MODALS
    // =========================================================================
    let currentListType = '';
    const listModal = document.getElementById('listModal');
    const confirmModal = document.getElementById('confirmModal');

    document.getElementById('viewWhitelistBtn').addEventListener('click', () => openListModal('whitelist'));
    document.getElementById('viewBlocklistBtn').addEventListener('click', () => openListModal('blocklist'));
    document.getElementById('closeModalBtn').addEventListener('click', () => listModal.classList.remove('active'));

    // Function: openListModal
    // - Inputs: type (string).
    // - Step 1: Sets current list context and modifies modal headers (Whitelisted vs Blocked).
    // - Step 2: Queries storage to fetch the corresponding lists of domain entries.
    // - Step 3: Renders placeholders if the list is empty, hiding batch removal controllers.
    // - Step 4: Loops through list arrays to construct lists containing checkbox items.
    // - Step 5: Activates list modal overlay via CSS transition classes.
    function openListModal(type) {
        currentListType = type;
        document.getElementById('modalTitle').innerText = type === 'whitelist' ? 'Whitelisted Domains' : 'Blocked Domains';
        const listUl = document.getElementById('urlList');
        const removeSelectedBtn = document.getElementById('removeSelectedBtn');
        const removeAllBtn = document.getElementById('removeAllBtn');
        listUl.innerHTML = '';
        removeSelectedBtn.style.display = 'none';

        chrome.storage.local.get([type], (result) => {
            const items = result[type] || [];
            if (items.length === 0) {
                listUl.innerHTML = '<li><i>List is empty.</i></li>';
                removeAllBtn.style.display = 'none';
            } else {
                removeAllBtn.style.display = 'block';
                items.forEach(item => {
                    const li = document.createElement('li');
                    
                    const cb = document.createElement('input');
                    cb.type = 'checkbox';
                    cb.value = item;
                    cb.className = 'item-checkbox';
                    cb.addEventListener('change', updateRemoveButton);
                    
                    const span = document.createElement('span');
                    span.innerText = item;
                    
                    li.appendChild(cb);
                    li.appendChild(span);
                    listUl.appendChild(li);
                });
            }
            listModal.classList.add('active');
        });
    }

    // Function: updateRemoveButton
    // - Step 1: Gathers all checkbox nodes currently marked as selected.
    // - Step 2: Updates the batch deletion trigger label to reflect selected counts.
    // - Step 3: Toggles visibility of the button depending on whether selected items are present.
    function updateRemoveButton() {
        const checked = document.querySelectorAll('.item-checkbox:checked');
        const removeSelectedBtn = document.getElementById('removeSelectedBtn');
        if (checked.length > 0) {
            removeSelectedBtn.style.display = 'block';
            removeSelectedBtn.innerText = `Remove (${checked.length})`;
        } else {
            removeSelectedBtn.style.display = 'none';
        }
    }

    document.getElementById('removeAllBtn').addEventListener('click', () => {
        confirmModal.classList.add('active');
    });

    document.getElementById('removeSelectedBtn').addEventListener('click', () => {
        const checked = document.querySelectorAll('.item-checkbox:checked');
        if (checked.length === 0) return;
        const toRemove = Array.from(checked).map(cb => cb.value);
        
        chrome.storage.local.get([currentListType], (result) => {
            let items = result[currentListType] || [];
            items = items.filter(item => !toRemove.includes(item));
            
            const update = {};
            update[currentListType] = items;
            chrome.storage.local.set(update, () => {
                if (currentListType === 'blocklist') {
                    document.getElementById('blockCount').innerText = items.length;
                } else {
                    document.getElementById('whiteCount').innerText = items.length;
                }
                openListModal(currentListType);
                showPopupToast(`Successfully removed ${toRemove.length} URL(s)`);
            });
        });
    });

    const cancelBtn = document.getElementById('confirmCancelBtn');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', () => confirmModal.classList.remove('active'));
    }

    document.getElementById('confirmYesBtn').addEventListener('click', () => {
        const update = {};
        update[currentListType] = [];
        chrome.storage.local.set(update, () => {
            if (currentListType === 'blocklist') {
                document.getElementById('blockCount').innerText = 0;
            } else {
                document.getElementById('whiteCount').innerText = 0;
            }
            confirmModal.classList.remove('active');
            openListModal(currentListType);
            showPopupToast('Successfully removed all URL(s)');
        });
    });
});
