// =============================================================================
// ConnectProtect — Background Service Worker (background.js)
// Handles right-click context menu creation, event interception, and storage updates.
// =============================================================================

// Event: chrome.runtime.onInstalled
// - Triggers when the extension is first installed or updated.
// - Creates two context menu options: Whitelist and Block.
// - Sets menu targets to webpage background and hyperlinks.
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "cp-whitelist",
        title: "Whitelist this URL",
        contexts: ["page", "link"]
    });
    
    chrome.contextMenus.create({
        id: "cp-block",
        title: "Block this URL",
        contexts: ["page", "link"]
    });
});

// Event: chrome.contextMenus.onClicked
// - Triggers when a user selects a ConnectProtect option from the right-click menu.
// - Retrieves the target URL from the clicked link or page.
// - Validates and parses the URL to extract the hostname.
// - Calls addToList to store the hostname in either the whitelist or blocklist.
chrome.contextMenus.onClicked.addListener((info, tab) => {
    const targetUrl = info.linkUrl || info.pageUrl;
    if (!targetUrl) return;
    
    try {
        const urlObj = new URL(targetUrl);
        const hostname = urlObj.hostname;
        
        if (info.menuItemId === "cp-whitelist") {
            addToList("whitelist", hostname, tab.id);
        } else if (info.menuItemId === "cp-block") {
            addToList("blocklist", hostname, tab.id);
        }
    } catch (e) {
        console.error("Invalid URL clicked", e);
    }
});

// Function: addToList
// - Inputs: listName (string), hostname (string), tabId (integer).
// - Retrieves the current array for listName (whitelist/blocklist) from local storage.
// - Checks if the domain name is already registered in the retrieved list.
// - Appends the new hostname to the array if it does not already exist.
// - Commits the updated list back to chrome.storage.local.
// - Formats a success emoji message depending on which list was modified.
// - Dispatches a "showToast" message to the current active webpage tab.
function addToList(listName, hostname, tabId) {
    chrome.storage.local.get([listName], (result) => {
        let list = result[listName] || [];
        if (!list.includes(hostname)) {
            list.push(hostname);
            const update = {};
            update[listName] = list;
            chrome.storage.local.set(update, () => {
                console.log(`Added ${hostname} to ${listName}`);
                if (tabId) {
                    const msg = listName === 'whitelist' ? `✅ Added to Whitelist: ${hostname}` : `🚫 Blocked: ${hostname}`;
                    chrome.tabs.sendMessage(tabId, {
                        action: "showToast",
                        message: msg
                    }).catch(() => {});
                }
            });
        }
    });
}
