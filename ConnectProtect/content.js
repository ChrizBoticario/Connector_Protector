let blockedUrls = [];
let pendingUrl = "";

/**
 * ALGORITHM 1: CANONICAL URI NORMALIZATION (Shared Logic)
 */
function normalizeUrl(url) {
    if (!url || !url.startsWith('http')) return url;
    let normalized = url.replace(/^(https?:\/\/)/, '').replace(/^(www\.|m\.)/, '').split(/[?#]/)[0];
    if (normalized.endsWith('/')) normalized = normalized.slice(0, -1);
    return normalized.toLowerCase();
}

/**
 * ALGORITHM 2: HEURISTIC SIMILARITY ANALYSIS (Levenshtein Distance)
 * Purpose: Detects "Typosquatting" (e.g., faceb00k.com).
 */
function getLevenshteinDistance(s1, s2) {
    const track = Array(s2.length + 1).fill(null).map(() => Array(s1.length + 1).fill(null));
    for (let i = 0; i <= s1.length; i += 1) track[0][i] = i;
    for (let j = 0; j <= s2.length; j += 1) track[j][0] = j;
    for (let j = 1; j <= s2.length; j += 1) {
        for (let i = 1; i <= s1.length; i += 1) {
            const indicator = s1[i - 1] === s2[j - 1] ? 0 : 1;
            track[j][i] = Math.min(
                track[j][i - 1] + 1, track[j - 1][i] + 1, track[j - 1][i - 1] + indicator
            );
        }
    }
    return track[s2.length][s1.length];
}

function checkTyposquatting(inputUrl) {
    const targets = ["facebook.com", "google.com", "gmail.com", "youtube.com", "yahoo.com"];
    const domain = normalizeUrl(inputUrl).split('/')[0];
    for (let target of targets) {
        if (domain === target) return false;
        const distance = getLevenshteinDistance(domain, target);
        if (distance > 0 && distance <= 2) return target; 
    }
    return false;
}

// Initializing the blocked list
function initializeBlockedList() {
    chrome.storage.local.get({ blockedLinks: [] }, (data) => {
        blockedUrls = data.blockedLinks;
        checkAndModifyDOM();
    });
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.blockedLinks) {
            blockedUrls = changes.blockedLinks.newValue || [];
            checkAndModifyDOM();
        }
    });
}
initializeBlockedList();

// Universal Interception
window.addEventListener("mousedown", function(event) {
    if (event.button !== 0) return; 
    const linkElement = event.target.closest("a");

    if (linkElement && linkElement.href && linkElement.href.startsWith('http')) {
        event.preventDefault();
        event.stopImmediatePropagation();
        
        const fullUrl = linkElement.href;
        const normalizedUrl = normalizeUrl(fullUrl);

        if (blockedUrls.includes(normalizedUrl)) {
            alert(`ConnectProtect: This link is BLOCKED.`);
            return;
        }

        const similarTo = checkTyposquatting(fullUrl);
        if (similarTo) {
            if (!confirm(`WARNING: This link looks like ${similarTo} but is slightly different. It might be a phishing site. Proceed anyway?`)) {
                return;
            }
        }

        pendingUrl = fullUrl;
        createModal(pendingUrl);
    }
}, true);

/**
 * ALGORITHM 3: OPTIMIZED DEBOUNCED MUTATION ANALYSIS
 * Purpose: Efficiently scans for new links on Facebook/YouTube without slowing the PC.
 */
let mutationTimeout = null;
const observer = new MutationObserver(() => {
    clearTimeout(mutationTimeout);
    mutationTimeout = setTimeout(() => {
        checkAndModifyDOM();
    }, 500); 
});
observer.observe(document.body, { childList: true, subtree: true });

function checkAndModifyDOM() {
    const allLinks = document.querySelectorAll('a[href^="http"]');
    allLinks.forEach(link => {
        const normalized = normalizeUrl(link.href);
        if (blockedUrls.includes(normalized)) {
            link.style.border = '2px solid red';
            link.style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
            link.title = "ConnectProtect: BLOCKED";
        } else {
            link.style.border = '';
            link.style.backgroundColor = '';
        }
    });
}

function createModal(url) {
    const existing = document.getElementById("cp-modal-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "cp-modal-overlay";
    
    // Injecting fallback styles with animation logic
    if (!document.head.querySelector('[data-cp-style]')) {
        const style = document.createElement('style');
        style.setAttribute('data-cp-style', 'true');
        style.textContent = `
            #cp-modal-overlay {position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.6); z-index: 999999; display: flex; justify-content: center; align-items: center;}
            #cp-modal-box {
                background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.4); width: 300px; text-align: center;
                transform: scale(0.7); opacity: 0; transition: transform 0.3s ease-out, opacity 0.3s ease-out;
            }
            #cp-modal-box.cp-show { transform: scale(1); opacity: 1; }
            .cp-btn {display: block; width: 100%; padding: 10px; margin: 5px 0; border: none; border-radius: 5px; cursor: pointer; font-family: sans-serif;}
            #cp-btn-continue {background-color: #2980b9; color: white;}
            #cp-btn-open {background-color: #4CAF50; color: white;}
            #cp-btn-block {background-color: #f44336; color: white;}
            #cp-btn-cancel {background-color: #ccc; color: #333;}
        `;
        document.head.appendChild(style);
    }
    
    const box = document.createElement("div");
    box.id = "cp-modal-box";
    box.innerHTML = `
        <div id="cp-modal-title" style="font-weight: bold; margin-bottom: 5px; font-family: sans-serif;">ConnectProtect Action</div>
        <div style="font-size: 13px; color: #cc0000; font-weight: 500; margin-bottom: 15px; font-family: sans-serif;">Make sure you know the URL is safe</div>
        <div id="cp-link-preview" style="font-size: 11px; color: #666; margin-bottom: 20px; word-break: break-all; font-family: monospace;">${url}</div>
        <button id="cp-btn-continue" class="cp-btn">Continue to Site</button>
        <button id="cp-btn-open" class="cp-btn">Open in New Window</button>
        <button id="cp-btn-block" class="cp-btn">Block Link</button>
        <button id="cp-btn-cancel" class="cp-btn">Cancel</button>
    `;
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    
    // Trigger Animation
    setTimeout(() => { box.classList.add('cp-show'); }, 10);

    // Button Logic
    document.getElementById("cp-btn-continue").addEventListener("click", () => { removeModal(); window.location.href = url; });
    document.getElementById("cp-btn-open").addEventListener("click", () => { window.open(url, '_blank'); removeModal(); });
    document.getElementById("cp-btn-block").addEventListener("click", () => {
        chrome.runtime.sendMessage({ action: "blockLink", url: url }, () => {
            alert("Link has been added to your Block List.");
            removeModal();
        });
    });
    document.getElementById("cp-btn-cancel").addEventListener("click", () => { removeModal(); });
    overlay.addEventListener("click", (e) => { if(e.target === overlay) removeModal(); });
}

function removeModal() {
    const overlay = document.getElementById("cp-modal-overlay");
    if (overlay) overlay.remove();
}