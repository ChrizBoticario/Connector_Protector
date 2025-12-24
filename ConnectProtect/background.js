/**
 * ALGORITHM 1: CANONICAL URI NORMALIZATION
 * Purpose: Transforms various URL formats into a single "Canonical" form.
 * This ensures that if you block "http://www.google.com/?test=1", 
 * the extension also blocks "https://google.com".
 */
function normalizeUrl(url) {
    if (!url || !url.startsWith('http')) return url;
    
    // Step 1: Remove protocol (http/https)
    let normalized = url.replace(/^(https?:\/\/)/, '');
    
    // Step 2: Remove 'www.' or 'm.' (mobile) prefixes
    normalized = normalized.replace(/^(www\.|m\.)/, '');
    
    // Step 3: Remove Query Parameters and Hashes (everything after ? or #)
    normalized = normalized.split(/[?#]/)[0];
    
    // Step 4: Remove Trailing Slash
    if (normalized.endsWith('/')) {
        normalized = normalized.slice(0, -1);
    }
    
    return normalized.toLowerCase();
}

// Helper to save URLs to Chrome's local storage
function addUrlToStorage(url) {
    const normalizedUrl = normalizeUrl(url); 
    if (!normalizedUrl) return; 

    chrome.storage.local.get({ blockedLinks: [] }, (data) => {
        const links = data.blockedLinks;
        if (!links.includes(normalizedUrl)) {
            links.push(normalizedUrl);
            chrome.storage.local.set({ blockedLinks: links });
        }
    });
}

// Create the Context Menu (Right-Click Menu)
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "cp-open-new",
        title: "ConnectProtect: Open in New Window",
        contexts: ["link"]
    });

    chrome.contextMenus.create({
        id: "cp-block",
        title: "ConnectProtect: Block this Link",
        contexts: ["link"]
    });
});

// Handle Context Menu Clicks
chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId === "cp-open-new") {
        chrome.windows.create({ url: info.linkUrl });
    } 
    else if (info.menuItemId === "cp-block") {
        addUrlToStorage(info.linkUrl);
    }
});

// Listen for messages from the popup or content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "blockLink" || request.action === "blockLinkFromPopup") {
        addUrlToStorage(request.url);
        sendResponse({ status: "success" });
    }
    return true; 
});