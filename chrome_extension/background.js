// Service Worker for Chrome Extension
chrome.runtime.onInstalled.addListener(() => {
    console.log('AI Fraud Shield Extension Installed');
    
    // Set default settings
    chrome.storage.sync.set({ 
        enabled: true,
        autoCheck: false,
        badgeEnabled: true
    });
    
    // Set default badge
    chrome.action.setBadgeText({ text: '✓' });
    chrome.action.setBadgeBackgroundColor({ color: '#28a745' });
});

// Listen for navigation to check URLs
chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId === 0) { // Main frame only
        const { enabled, badgeEnabled } = await chrome.storage.sync.get(['enabled', 'badgeEnabled']);
        
        if (enabled) {
            await checkUrlSafety(details.url, badgeEnabled);
        }
    }
});

async function checkUrlSafety(url, showBadge = true) {
    // Local scam domain patterns
    const suspiciousPatterns = [
        'secure-', 'verify-', 'login-', 'update-', 'confirm-',
        'account-', 'signin-', 'authenticate'
    ];
    
    const isSuspicious = suspiciousPatterns.some(pattern => 
        url.toLowerCase().includes(pattern)
    );
    
    // Check for suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.xyz'];
    const hasSuspiciousTLD = suspiciousTLDs.some(tld => url.toLowerCase().endsWith(tld));
    
    if (isSuspicious || hasSuspiciousTLD) {
        if (showBadge) {
            chrome.action.setBadgeText({ text: '⚠️' });
            chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
        }
        
        // Show notification (only once per site)
        const notificationKey = `alert_${new URL(url).hostname}`;
        const shown = await chrome.storage.local.get(notificationKey);
        
        if (!shown[notificationKey]) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon128.png',
                title: '⚠️ AI Fraud Shield Alert',
                message: 'This site may be suspicious! Check before entering personal information.',
                priority: 2
            });
            
            // Store that we showed this notification
            chrome.storage.local.set({ [notificationKey]: true });
        }
    } else if (showBadge) {
        chrome.action.setBadgeText({ text: '✓' });
        chrome.action.setBadgeBackgroundColor({ color: '#28a745' });
    }
}

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getSettings") {
        chrome.storage.sync.get(['enabled', 'autoCheck'], (settings) => {
            sendResponse(settings);
        });
        return true;
    }
    
    if (request.action === "reportScam") {
        // Log scam report to storage
        chrome.storage.local.get(['reportedSites'], (result) => {
            const reported = result.reportedSites || [];
            reported.push({
                url: request.url,
                reason: request.reason,
                timestamp: new Date().toISOString()
            });
            chrome.storage.local.set({ reportedSites: reported });
        });
        sendResponse({ success: true });
        return true;
    }
});

// Clean old notifications from storage after 30 days
setInterval(() => {
    const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
    chrome.storage.local.get(null, (items) => {
        Object.keys(items).forEach(key => {
            if (key.startsWith('alert_')) {
                // Keep for now, implement cleanup if needed
            }
        });
    });
}, 24 * 60 * 60 * 1000); // Run once per day