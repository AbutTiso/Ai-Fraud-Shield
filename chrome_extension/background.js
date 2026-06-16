// Service Worker for AI Fraud Shield Chrome Extension
// Version 2.0 - Enhanced Security - MODERN COLOR SCHEME

// ============ CONSTANTS & CONFIGURATION ============

const EXTENSION_CONFIG = {
    version: '2.0.0',
    name: 'AI Fraud Shield',
    checkInterval: 5000
};

// Known legitimate domains (whitelist)
const LEGITIMATE_DOMAINS = new Set([
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'youtube.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'spotify.com', 'github.com',
    'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'whatsapp.com',
    'telegram.org', 'zoom.us', 'dropbox.com', 'slack.com',
    'github.io', 'vercel.app', 'netlify.app', 'cloudflare.com'
]);

// Suspicious URL patterns
const SUSPICIOUS_PATTERNS = [
    'secure-', 'verify-', 'login-', 'update-', 'confirm-',
    'account-', 'signin-', 'authenticate', 'validate-',
    'authorize-', 'identity-', 'verification-', 'security-',
    'safaricom', 'mpesa', 'airtel', 'telkom', 'equity', 'kcb',
    'paypal', 'amazon', 'microsoft', 'apple', 'google',
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

// ============ HELPER FUNCTIONS ============

function updateBadge(text, color, title) {
    try {
        chrome.action.setBadgeText({ text: text });
        chrome.action.setBadgeBackgroundColor({ color: color });
        chrome.action.setTitle({ title: title });
    } catch (error) {
        console.log('Badge update error:', error);
    }
}

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

function showNotification(title, message, type = 'info') {
    console.log(`[${type.toUpperCase()}] ${title}: ${message}`);
    
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon128.png',
        title: title.substring(0, 50),
        message: message.substring(0, 200),
        priority: 1
    }).catch(() => {});
}

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
                const realMatch = brand.name.toLowerCase().replace(/[^a-z]/g, '');
                if (!domain.includes(realMatch) || domain !== `${realMatch}.com`) {
                    return {
                        detected: true,
                        brand: brand.name,
                        message: `Fake ${brand.name} domain detected!`
                    };
                }
            }
        }
    }
    return { detected: false };
}

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
        
        // Check 1: Known legitimate domains
        if (LEGITIMATE_DOMAINS.has(domain)) {
            return {
                isDangerous: false,
                score: 0,
                riskLevel: 'safe',
                reasons: ['Known legitimate domain'],
                badge: { text: '✓', color: '#10a37f', title: 'Safe site' }
            };
        }
        
        // Check 2: Suspicious TLDs
        for (const tld of SUSPICIOUS_TLDS) {
            if (domain.endsWith(tld)) {
                score += 35;
                reasons.push(`Suspicious domain extension: ${tld}`);
                break;
            }
        }
        
        // Check 3: IP address as domain
        if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
            score += 50;
            reasons.push('Uses IP address instead of domain name');
        }
        
        // Check 4: Suspicious patterns
        for (const pattern of SUSPICIOUS_PATTERNS) {
            if (domain.includes(pattern) || path.includes(pattern) || search.includes(pattern)) {
                score += 15;
                reasons.push(`Suspicious pattern: "${pattern}"`);
                break;
            }
        }
        
        // Check 5: Brand impersonation
        const brandImpersonation = detectBrandImpersonation(domain);
        if (brandImpersonation.detected) {
            score += 40;
            reasons.push(brandImpersonation.message);
        }
        
        // Check 6: Hyphenated domains
        if (domain.includes('-') && domain.split('-').length > 2) {
            score += 10;
            reasons.push('Multiple hyphens in domain name');
        }
        
        // Determine risk level and badge - MODERN AI COLORS
        let badge, isDangerous;
        if (score >= 50) {
            isDangerous = true;
            riskLevel = 'dangerous';
            badge = { text: '⚠️', color: '#ef4444', title: 'Security Risk - Do Not Trust!' };
        } else if (score >= 25) {
            isDangerous = true;
            riskLevel = 'suspicious';
            badge = { text: '?', color: '#f59e0b', title: 'Suspicious - Be Careful' };
        } else {
            isDangerous = false;
            riskLevel = 'safe';
            badge = { text: '✓', color: '#10a37f', title: 'Site appears safe' };
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
            badge: { text: '?', color: '#6b7280', title: 'Unable to analyze' }
        };
    }
}

async function checkPageContent() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.id) return;
        
        try {
            const response = await chrome.tabs.sendMessage(tab.id, { action: "scanContent" });
            if (response && response.hasScamIndicators) {
                updateBadge('⚠️', '#f59e0b', 'Scam content detected');
            }
        } catch (error) {
            console.log('Content script not available');
        }
    } catch (error) {
        console.log('Content check error:', error);
    }
}

async function reportScamSite(url, tabId) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        
        const reported = await chrome.storage.local.get(['reportedSites']);
        const reportedSites = reported.reportedSites || [];
        
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
            updateBadge('🚫', '#6b7280', 'Reported as scam');
            showNotification('Report Submitted', 'Thank you for helping protect others!', 'success');
        } else {
            showNotification('Already Reported', 'This site has already been reported', 'info');
        }
    } catch (error) {
        console.error('Report error:', error);
    }
}

async function showSecurityNotification(analysisResult) {
    const notificationKey = `alert_${analysisResult.domain}`;
    const shown = await chrome.storage.local.get(notificationKey);
    
    if (!shown[notificationKey]) {
        try {
            await chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icon128.png',
                title: analysisResult.score >= 50 ? 'Security Alert!' : 'Suspicious Site Detected',
                message: analysisResult.reasons.slice(0, 2).join('\n'),
                priority: analysisResult.score >= 50 ? 2 : 1
            });
            
            await chrome.storage.local.set({ [notificationKey]: true });
            
            setTimeout(async () => {
                await chrome.storage.local.remove(notificationKey);
            }, 60 * 60 * 1000);
        } catch (error) {
            console.log('Notification error:', error);
        }
    }
}

// ============ INITIALIZATION ============

chrome.runtime.onInstalled.addListener((details) => {
    console.log(`${EXTENSION_CONFIG.name} Extension ${EXTENSION_CONFIG.version} - ${details.reason}`);
    
    const defaultSettings = { 
        enabled: true,
        autoCheck: true,
        badgeEnabled: true,
        notificationsEnabled: true,
        blockLevel: 'medium',
        scanType: 'both'
    };
    
    chrome.storage.sync.set(defaultSettings);
    updateBadge('🟢', '#10a37f', 'Extension active');
    
    chrome.contextMenus.create({
        id: 'reportScam',
        title: 'Report this site as scam',
        contexts: ['page', 'link']
    }, () => {
        if (chrome.runtime.lastError && !chrome.runtime.lastError.message.includes('already exists')) {
            console.warn('Context menu error:', chrome.runtime.lastError);
        } else {
            console.log('Context menu created successfully');
        }
    });
});

// ============ NAVIGATION LISTENER ============

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId === 0) {
        const settings = await getSettings();
        
        if (settings.enabled) {
            const result = await analyzeUrlSafety(details.url);
            
            if (settings.badgeEnabled) {
                updateBadge(result.badge.text, result.badge.color, result.badge.title);
            }
            
            if (result.isDangerous && settings.notificationsEnabled) {
                await showSecurityNotification(result);
            }
        }
    }
});

// ============ CONTEXT MENU HANDLER ============

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (!info || !tab) return;
    
    if (info.menuItemId === 'reportScam') {
        const url = info.linkUrl || info.pageUrl || tab.url;
        if (url) {
            await reportScamSite(url, tab.id);
        }
    }
});

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
                sendResponse({ success: false });
            }
        },
        getStats: async () => {
            const reported = await chrome.storage.local.get(['reportedSites']);
            sendResponse({ 
                totalReports: (reported.reportedSites || []).length,
                version: EXTENSION_CONFIG.version
            });
        },
        checkPageSafety: async () => {
            if (sender.tab && sender.tab.id) {
                try {
                    const response = await chrome.tabs.sendMessage(sender.tab.id, { action: "getRiskScore" });
                    sendResponse(response);
                } catch (error) {
                    sendResponse({ score: 0, isScam: false });
                }
            } else {
                sendResponse({ score: 0, isScam: false });
            }
        }
    };
    
    const handler = handlers[request.action];
    if (handler) {
        handler();
        return true;
    }
    
    sendResponse({ error: 'Unknown action' });
    return false;
});

// ============ PERIODIC CLEANUP ============

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

setInterval(() => {
    console.log(`${EXTENSION_CONFIG.name} service worker active`);
}, 5 * 60 * 1000);

console.log(`✅ ${EXTENSION_CONFIG.name} Extension ${EXTENSION_CONFIG.version} - Service Worker Loaded Successfully`);