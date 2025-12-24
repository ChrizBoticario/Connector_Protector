document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const actionBtns = document.getElementById('actionBtns');
    const saveBtn = document.getElementById('saveBtn');
    const cancelBtn = document.getElementById('cancelBtn');
    const linkList = document.getElementById('linkList');
    const emptyMsg = document.getElementById('emptyMsg');

    // Load links on startup
    loadLinks();
    
    // Add listener for storage changes in case background/content script blocks something
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.blockedLinks) {
            loadLinks(); 
        }
    });

    // 1. Show Save/Cancel when user types
    urlInput.addEventListener('input', () => {
        if (urlInput.value.trim().length > 0) {
            actionBtns.style.display = 'flex';
        } else {
            actionBtns.style.display = 'none';
        }
    });

    // 2. Cancel Button Logic
    cancelBtn.addEventListener('click', () => {
        urlInput.value = '';
        actionBtns.style.display = 'none';
    });

    // 3. Save Button Logic
    saveBtn.addEventListener('click', () => {
        const url = urlInput.value.trim();
        // FIX: Ensure we only attempt to block valid URLs
        if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
            // Send the URL to background.js for normalization and saving
            chrome.runtime.sendMessage({ action: "blockLinkFromPopup", url: url }, () => {
                urlInput.value = '';
                actionBtns.style.display = 'none';
                // loadLinks() will be called automatically via the storage listener, but this ensures it.
                loadLinks(); 
            });
        } else {
            alert("Enter URL eg: 'http://' or 'https://'.");
        }
    });

    // Function to load links from chrome storage
    function loadLinks() {
        chrome.storage.local.get({ blockedLinks: [] }, (data) => {
            renderList(data.blockedLinks);
        });
    }

    // Function to remove link
    function removeLink(url) {
        chrome.storage.local.get({ blockedLinks: [] }, (data) => {
            let links = data.blockedLinks;
            // Filter out the link to be removed
            links = links.filter(item => item !== url); 
            chrome.storage.local.set({ blockedLinks: links }, () => {
                loadLinks(); // Refresh UI
            });
        });
    }

    // Function to render the list in HTML
    function renderList(links) {
        linkList.innerHTML = '';
        
        if (links.length === 0) {
            emptyMsg.style.display = 'block';
        } else {
            emptyMsg.style.display = 'none';
            links.forEach(url => {
                const li = document.createElement('li');
                
                const textSpan = document.createElement('span');
                textSpan.textContent = url.substring(0, 25) + (url.length > 25 ? '...' : '');
                textSpan.title = url; // Full URL on hover

                const delBtn = document.createElement('button');
                delBtn.textContent = 'X';
                delBtn.className = 'btn-remove';
                delBtn.onclick = () => removeLink(url);

                li.appendChild(textSpan);
                li.appendChild(delBtn);
                linkList.appendChild(li);
            });
        }
    }
});