// Service Worker for AI Fraud Shield Chrome Extension
// Version 2.0 - Enhanced Security

// ============ CONSTANTS & CONFIGURATION ============

const EXTENSION_CONFIG = {
    version: '2.0.0',
    name: 'AI Fraud Shield',
    checkInterval: 5000 // ms between checks
};

// Known legitimate domains (whitelist)
const LEGITIMATE_DOMAINS = new Set([
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'youtube.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'spotify.com', 'github.com',
    'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'whatsapp.com',
    'telegram.org', 'zoom.us', 'dropbox.com', 'slack.com'
]);

// Suspicious URL patterns
const SUSPICIOUS_PATTERNS = [
    // Phishing keywords
    'secure-', 'verify-', 'login-', 'update-', 'confirm-',
    'account-', 'signin-', 'authenticate', 'validate-',
    'authorize-', 'identity-', 'verification-', 'security-',
    
    // Brand impersonation
    'safaricom', 'mpesa', 'airtel', 'telkom', 'equity', 'kcb',
    'paypal', 'amazon', 'microsoft', 'apple', 'google',
    
    // Suspicious words
    'claim', 'winner', 'prize', 'reward', 'gift', 'bonus',
    'free-', 'discount-', 'limited-', 'urgent-'
];

// Suspicious domain extensions (TLDs)
const SUSPICIOUS_TLDS = new Set([
    '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click',
    '.download', '.live', '.win', '.bid', '.loan', '.review',
    '.stream', '.date', '.space', '.website', '.site', '.online',
    '.tech', '.store', '.work', '.link', '.gq', '.icu', '.cyou'
]);

// Scam keywords for content analysis
const SCAM_KEYWORDS = {
    urgency: ['urgent', 'immediately', 'asap', 'today only', 'limited time', 'expires', 'last chance'],
    threat: ['suspended', 'blocked', 'locked', 'closed', 'terminated', 'legal action', 'lawsuit'],
    reward: ['won', 'winner', 'prize', 'congratulations', 'reward', 'gift card', 'free gift'],
    sensitive: ['pin', 'password', 'otp', 'verification code', 'credit card', 'debit card', 'mpesa pin'],
    pressure: ['don\'t miss', 'act now', 'click here', 'verify now', 'confirm your identity']
};

// ============ INITIALIZATION ============

chrome.runtime.onInstalled.addListener((details) => {
    console.log(`${EXTENSION_CONFIG.name} Extension ${EXTENSION_CONFIG.version} - ${details.reason}`);
    
    // Initialize default settings
    const defaultSettings = { 
        enabled: true,
        autoCheck: true,
        badgeEnabled: true,
        notificationsEnabled: true,
        blockLevel: 'medium', // low, medium, high
        scanType: 'both' // url, content, both
    };
    
    chrome.storage.sync.set(defaultSettings);
    
    // Set default badge state
    updateBadge('🟢', '#28a745', 'Extension active');
    
    // Create context menu for reporting
    chrome.contextMenus.create({
        id: 'reportScam',
        title: 'Report this site as scam',
        contexts: ['page_action', 'link']
    });
});

// ============ NAVIGATION LISTENER ============

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId === 0) { // Main frame only
        const settings = await getSettings();
        
        if (settings.enabled) {
            const result = await analyzeUrlSafety(details.url);
            
            if (settings.badgeEnabled) {
                updateBadge(result.badge.text, result.badge.color, result.badge.title);
            }
            
            // Auto-check content if enabled
            if (settings.autoCheck && settings.scanType !== 'url') {
                await checkPageContent();
            }
            
            // Show notification for high-risk sites
            if (result.isDangerous && settings.notificationsEnabled) {
                await showSecurityNotification(result);
            }
        }
    }
});

// ============ CONTEXT MENU HANDLER ============

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === 'reportScam') {
        const url = info.linkUrl || info.pageUrl;
        await reportScamSite(url, tab.id);
        showNotification('Report Submitted', 'Thank you for helping keep others safe!', 'info');
    }
});

// ============ CORE ANALYSIS FUNCTIONS ============

async function analyzeUrlSafety(url) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.replace(/^www\./, '');
        const path = urlObj.pathname;
        const search = urlObj.search;
        
        let score = 0;
        let reasons = [];
        let riskLevel = 'safe';
        
        // Check 1: Known legitimate domains (whitelist)
        if (LEGITIMATE_DOMAINS.has(domain)) {
            return {
                isDangerous: false,
                score: 0,
                riskLevel: 'safe',
                reasons: ['Known legitimate domain'],
                badge: { text: '✓', color: '#28a745', title: 'Safe site' }
            };
        }
        
        // Check 2: Suspicious TLDs
        for (const tld of SUSPICIOUS_TLDS) {
            if (domain.endsWith(tld)) {
                score += 35;
                reasons.push(`⚠️ Suspicious domain extension: ${tld}`);
                break;
            }
        }
        
        // Check 3: IP address as domain
        if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
            score += 50;
            reasons.push('🔴 Uses IP address instead of domain name');
        }
        
        // Check 4: Suspicious patterns in domain
        for (const pattern of SUSPICIOUS_PATTERNS) {
            if (domain.includes(pattern) || path.includes(pattern) || search.includes(pattern)) {
                score += 15;
                reasons.push(`⚠️ Suspicious pattern: "${pattern}"`);
                break;
            }
        }
        
        // Check 5: Brand impersonation
        const brandImpersonation = detectBrandImpersonation(domain);
        if (brandImpersonation.detected) {
            score += 40;
            reasons.push(`🔴 ${brandImpersonation.message}`);
        }
        
        // Check 6: Hyphenated domains (often suspicious)
        if (domain.includes('-') && domain.split('-').length > 2) {
            score += 10;
            reasons.push('⚠️ Multiple hyphens in domain name');
        }
        
        // Check 7: Long URL (hiding tactic)
        if (url.length > 120) {
            score += 5;
            reasons.push('⚠️ Unusually long URL');
        }
        
        // Determine risk level and badge
        let badge, isDangerous;
        if (score >= 50) {
            isDangerous = true;
            riskLevel = 'dangerous';
            badge = { text: '⚠️', color: '#dc3545', title: 'Security Risk - Do Not Trust!' };
        } else if (score >= 25) {
            isDangerous = true;
            riskLevel = 'suspicious';
            badge = { text: '?', color: '#ffc107', title: 'Suspicious - Be Careful' };
        } else {
            isDangerous = false;
            riskLevel = 'safe';
            badge = { text: '✓', color: '#28a745', title: 'Site appears safe' };
        }
        
        return {
            isDangerous,
            score,
            riskLevel,
            reasons: reasons.slice(0, 5),
            badge,
            domain,
            url: url.slice(0, 100)
        };
        
    } catch (error) {
        console.error('URL analysis error:', error);
        return {
            isDangerous: false,
            score: 0,
            riskLevel: 'unknown',
            reasons: ['Could not analyze URL'],
            badge: { text: '?', color: '#6c757d', title: 'Unable to analyze' }
        };
    }
}

// ============ BRAND IMPERSONATION DETECTION ============

function detectBrandImpersonation(domain) {
    const brands = [
        { name: 'Safaricom', patterns: ['safaricom', 'safaric0m', 'safaricom-'] },
        { name: 'M-Pesa', patterns: ['mpesa', 'm-pesa', 'mpesa-'] },
        { name: 'Airtel', patterns: ['airtel', 'airt3l', 'airtel-'] },
        { name: 'Equity Bank', patterns: ['equity', 'equitybank', 'equity-'] },
        { name: 'KCB', patterns: ['kcb', 'kcb-', 'kcbgroup'] },
        { name: 'PayPal', patterns: ['paypal', 'pay-pal', 'paypall'] },
        { name: 'Amazon', patterns: ['amazon', 'amaz0n', 'amzn'] },
        { name: 'Microsoft', patterns: ['microsoft', 'micros0ft', 'msft'] }
    ];
    
    for (const brand of brands) {
        for (const pattern of brand.patterns) {
            if (domain.includes(pattern)) {
                // Check if it's the real domain vs fake
                const realMatch = brand.name.toLowerCase().replace(/[^a-z]/g, '');
                if (!domain.includes(realMatch) || domain !== `${realMatch}.com`) {
                    return {
                        detected: true,
                        brand: brand.name,
                        message: `Fake ${brand.name} domain detected! This looks like a phishing site.`
                    };
                }
            }
        }
    }
    
    return { detected: false };
}

// ============ PAGE CONTENT SCANNING ============

async function checkPageContent() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.id) return;
        
        // Check if content script is injected
        try {
            const response = await chrome.tabs.sendMessage(tab.id, { action: "scanContent" });
            if (response && response.hasScamIndicators) {
                await showContentWarning(response.scamDetails);
                updateBadge('⚠️', '#ffc107', 'Scam content detected');
            }
        } catch (error) {
            // Content script not injected - inject it
            if (tab.url && tab.url.startsWith('http')) {
                await chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    files: ['content.js']
                });
            }
        }
    } catch (error) {
        console.log('Content check error:', error);
    }
}

// ============ NOTIFICATION FUNCTIONS ============

async function showSecurityNotification(analysisResult) {
    const notificationKey = `alert_${analysisResult.domain}`;
    const shown = await chrome.storage.local.get(notificationKey);
    
    // Only show once per domain per session
    if (!shown[notificationKey]) {
        const notificationId = await chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: analysisResult.score >= 50 ? '⚠️ Security Alert!' : '🔍 Suspicious Site Detected',
            message: analysisResult.reasons.slice(0, 2).join('\n'),
            priority: analysisResult.score >= 50 ? 2 : 1,
            buttons: [{ title: 'Block Site' }, { title: 'Learn More' }]
        });
        
        // Store notification reference
        await chrome.storage.local.set({ [notificationKey]: true });
        
        // Auto-clear after 1 hour
        setTimeout(async () => {
            await chrome.storage.local.remove(notificationKey);
        }, 60 * 60 * 1000);
    }
}

function showNotification(title, message, type = 'info') {
    const colors = {
        info: '#17a2b8',
        warning: '#ffc107',
        danger: '#dc3545',
        success: '#28a745'
    };
    
    // Non-intrusive notification (doesn't require permission)
    console.log(`[${type.toUpperCase()}] ${title}: ${message}`);
    
    // Optional: Use chrome.notifications if permission granted
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: title,
        message: message,
        priority: 1
    }).catch(() => {
        // Silent fail if notification permission not granted
    });
}

async function showContentWarning(scamDetails) {
    const notificationId = await chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '⚠️ Scam Content Detected!',
        message: `Detected: ${scamDetails.detectedTypes.join(', ')}`,
        priority: 2,
        buttons: [{ title: 'Leave Site' }, { title: 'I Understand' }]
    });
}

// ============ BADGE UPDATE ============

function updateBadge(text, color, title) {
    try {
        chrome.action.setBadgeText({ text: text });
        chrome.action.setBadgeBackgroundColor({ color: color });
        chrome.action.setTitle({ title: title });
    } catch (error) {
        console.log('Badge update error:', error);
    }
}

// ============ SCAM REPORTING ============

async function reportScamSite(url, tabId) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        
        // Store reported site
        const reported = await chrome.storage.local.get(['reportedSites']);
        const reportedSites = reported.reportedSites || [];
        
        // Check if already reported
        const alreadyReported = reportedSites.some(site => 
            site.domain === domain && 
            Date.now() - new Date(site.timestamp).getTime() < 30 * 24 * 60 * 60 * 1000
        );
        
        if (!alreadyReported) {
            reportedSites.push({
                domain: domain,
                url: url,
                reason: 'User reported',
                timestamp: new Date().toISOString(),
                reporter: 'extension_user'
            });
            
            await chrome.storage.local.set({ reportedSites });
            
            // Optional: Send to backend API
            sendToBackendAPI(domain, url);
            
            // Update badge for this tab
            updateBadge('🚫', '#6c757d', 'Reported as scam');
            
            showNotification('Report Submitted', 'Thank you for helping protect others!', 'success');
        }
    } catch (error) {
        console.error('Report error:', error);
    }
}

async function sendToBackendAPI(domain, url) {
    try {
        // Send report to your fraud shield backend
        const response = await fetch('https://your-fraudshield-api.com/api/report-scam-site/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, url, source: 'chrome_extension' })
        }).catch(() => null);
    } catch (error) {
        // Silent fail - backend not required for extension to work
    }
}

// ============ SETTINGS MANAGEMENT ============

async function getSettings() {
    const defaults = { 
        enabled: true, 
        autoCheck: true, 
        badgeEnabled: true,
        notificationsEnabled: true,
        blockLevel: 'medium',
        scanType: 'both'
    };
    return await chrome.storage.sync.get(defaults);
}

// ============ MESSAGE HANDLING ============

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    const handlers = {
        getSettings: async () => {
            const settings = await getSettings();
            sendResponse(settings);
        },
        analyzeUrl: async () => {
            if (sender.tab && sender.tab.url) {
                const result = await analyzeUrlSafety(sender.tab.url);
                sendResponse(result);
            } else {
                sendResponse({ error: 'No URL available' });
            }
        },
        reportScam: async () => {
            if (sender.tab && sender.tab.url) {
                await reportScamSite(sender.tab.url, sender.tab.id);
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: 'No URL available' });
            }
        },
        getStats: async () => {
            const reported = await chrome.storage.local.get(['reportedSites']);
            sendResponse({ 
                totalReports: (reported.reportedSites || []).length,
                version: EXTENSION_CONFIG.version
            });
        }
    };
    
    const handler = handlers[request.action];
    if (handler) {
        handler();
        return true; // Keep message channel open for async response
    }
    
    sendResponse({ error: 'Unknown action' });
    return false;
});

// ============ PERIODIC CLEANUP ============

// Clean up old notifications from storage (once per day)
setInterval(async () => {
    const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
    const items = await chrome.storage.local.get(null);
    
    for (const [key, value] of Object.entries(items)) {
        if (key.startsWith('alert_')) {
            const timestamp = value === true ? 0 : value;
            if (timestamp && timestamp < thirtyDaysAgo) {
                await chrome.storage.local.remove(key);
            }
        }
    }
    
    // Clean old reported sites
    const reported = await chrome.storage.local.get(['reportedSites']);
    if (reported.reportedSites) {
        const filtered = reported.reportedSites.filter(site => 
            Date.now() - new Date(site.timestamp).getTime() < 90 * 24 * 60 * 60 * 1000
        );
        if (filtered.length !== reported.reportedSites.length) {
            await chrome.storage.local.set({ reportedSites: filtered });
        }
    }
}, 24 * 60 * 60 * 1000);

// ============ HEARTBEAT / KEEPALIVE ============

// Keep service worker alive for better performance
setInterval(() => {
    console.log(`${EXTENSION_CONFIG.name} service worker active`);
}, 5 * 60 * 1000); // Every 5 minutes

console.log(`${EXTENSION_CONFIG.name} Extension ${EXTENSION_CONFIG.version} - Service Worker Loaded`);