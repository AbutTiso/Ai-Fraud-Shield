// content.js - Runs on every webpage - FULLY FIXED VERSION

// ============ IFRAME DETECTION (Anti-clickjacking) ============
if (window.self !== window.top) {
    console.warn('🛡️ AI Fraud Shield: Page loaded in iframe - potential clickjacking attempt');
    
    const iframeWarning = document.createElement('div');
    iframeWarning.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: #dc3545;
        color: white;
        padding: 10px 15px;
        border-radius: 8px;
        z-index: 999999;
        font-family: -apple-system, sans-serif;
        font-size: 12px;
        font-weight: bold;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        animation: slideDown 0.3s ease;
    `;
    iframeWarning.innerHTML = `⚠️ Warning: This page is embedded in another site - Scammers use this trick!`;
    document.body.appendChild(iframeWarning);
    
    setTimeout(() => {
        iframeWarning.style.opacity = '0';
        setTimeout(() => iframeWarning.remove(), 500);
    }, 5000);
}

// ============ HELPER FUNCTIONS ============
function checkPageSafety() {
    let score = 0;
    const text = document.body.innerText.toLowerCase();
    const keywords = ['urgent', 'verify', 'suspended', 'blocked', 'mpesa', 'pin', 'password'];
    keywords.forEach(kw => { if (text.includes(kw)) score += 10; });
    if (document.querySelector('input[type="password"]')) score += 15;
    
    const domain = location.hostname.toLowerCase();
    const suspiciousPatterns = ['secure-', 'verify-', 'login-', 'update-', 'confirm-'];
    if (suspiciousPatterns.some(p => domain.includes(p))) score += 25;
    
    return Math.min(100, score);
}

function checkSuspiciousDomain() {
    const domain = window.location.hostname.toLowerCase();
    return ['secure-', 'verify-', 'login-', 'update-', 'confirm-', 'account-', 'security-', 'banking-', 'mpesa-', 'safaricom-']
        .some(pattern => domain.includes(pattern));
}

// ============ HIGH CONTRAST THEME ============
function applyHighContrastTheme() {
    const hostname = window.location.hostname;
    let styleContent = '';
    
    const colors = {
        bg: '#000000',
        card: '#0a0a0a',
        text: '#ffffff',
        textMuted: '#d4d4d4',
        accent: '#3b82f6',
        accentHover: '#60a5fa',
        border: '#2a2a2a',
        input: '#1a1a1a'
    };
    
    if (hostname.includes('chat.openai.com') || hostname.includes('chatgpt.com')) {
        styleContent = `
            body, html, #__next, main, .flex.h-full, .overflow-hidden,
            .bg-white, .dark\\:bg-gray-800, .bg-gray-50, .bg-gray-100,
            .bg-gray-200, .bg-gray-900, .flex-shrink-0 {
                background-color: ${colors.bg} !important;
            }
            body, p, span, div, h1, h2, h3, h4, h5, h6, li, a,
            .text-gray-600, .text-gray-700, .text-gray-800, .text-gray-900,
            .text-base, .text-sm, .text-xs, .text-lg, .text-xl,
            .prose, .markdown, .message, .text-token-text-primary {
                color: ${colors.text} !important;
            }
            .text-gray-400, .text-gray-500, .text-token-text-secondary {
                color: ${colors.textMuted} !important;
            }
            button, .btn, .rounded-full, [role="button"] {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            button:hover, .btn:hover {
                background-color: ${colors.accent} !important;
                color: ${colors.text} !important;
                border-color: ${colors.accentHover} !important;
            }
            input, textarea, .ProseMirror, [contenteditable="true"] {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            input:focus, textarea:focus {
                border-color: ${colors.accent} !important;
                outline: none !important;
            }
            pre, code, .code-block {
                background-color: ${colors.bg} !important;
                color: #fbbf24 !important;
                border: 1px solid ${colors.border} !important;
            }
            a, a:visited {
                color: ${colors.accentHover} !important;
                text-decoration: underline !important;
            }
            a:hover {
                color: ${colors.accent} !important;
            }
            ::-webkit-scrollbar { width: 10px; background: ${colors.bg}; }
            ::-webkit-scrollbar-track { background: ${colors.card}; }
            ::-webkit-scrollbar-thumb { background: ${colors.accent}; border-radius: 5px; }
            ::selection { background: ${colors.accent}; color: ${colors.text}; }
        `;
    } else if (hostname.includes('chat.deepseek.com')) {
        styleContent = `
            body, .app-container, .chat-container, main, .sidebar,
            .history-panel, .message-list, .input-area {
                background-color: ${colors.bg} !important;
            }
            .sidebar, .history-panel, .settings-panel {
                background-color: ${colors.card} !important;
                border-right: 1px solid ${colors.border} !important;
            }
            .message, .user-message, .assistant-message,
            .message-content, .bubble {
                background-color: ${colors.card} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            .user-message, [class*="user"] {
                background-color: ${colors.accent} !important;
                color: ${colors.text} !important;
            }
            p, span, div, h1, h2, h3, h4, h5, h6, li,
            .text, .message-text, .chat-text {
                color: ${colors.text} !important;
            }
            .text-muted, .timestamp, .secondary {
                color: ${colors.textMuted} !important;
            }
            textarea, input, .input-box {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            button, .btn {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            button:hover, .btn:hover {
                background-color: ${colors.accent} !important;
                color: ${colors.text} !important;
            }
            pre, code {
                background-color: ${colors.bg} !important;
                color: #fbbf24 !important;
            }
        `;
    }
    
    if (styleContent) {
        const existingStyle = document.getElementById('ai-fraud-shield-theme');
        if (existingStyle) existingStyle.remove();
        const style = document.createElement('style');
        style.id = 'ai-fraud-shield-theme';
        style.textContent = styleContent;
        document.head.appendChild(style);
    }
}

function removeHighContrastTheme() {
    const existingStyle = document.getElementById('ai-fraud-shield-theme');
    if (existingStyle) existingStyle.remove();
}

// ============ SCAM WARNING DETECTION ============
let warningAlreadyShown = false;

function checkAndDisplayScamWarning() {
    const pageText = document.body.innerText.toLowerCase();
    let scamScore = 0;
    const foundKeywords = [];
    
    const scamKeywords = [
        'urgent', 'verify your account', 'suspended', 'blocked',
        'send money', 'mpesa', 'safaricom', 'airtel', 'winner', 'prize',
        'pin', 'password', 'otp', 'verification code', 'account will be closed',
        'click here', 'limited time', 'act now', 'congratulations',
        'verify your identity', 'security alert', 'unusual activity'
    ];
    
    scamKeywords.forEach(keyword => {
        if (pageText.includes(keyword)) {
            scamScore += 10;
            foundKeywords.push(keyword);
        }
    });
    
    const links = document.querySelectorAll('a');
    const suspiciousLinks = Array.from(links).filter(link => {
        const href = link.href.toLowerCase();
        return href.includes('secure-') || href.includes('verify-') || 
               href.includes('login-') || href.includes('update-') ||
               href.includes('confirm-') || href.includes('account-');
    });
    
    if (suspiciousLinks.length > 0) {
        scamScore += Math.min(suspiciousLinks.length * 5, 25);
    }
    
    const sensitiveInputs = document.querySelectorAll(
        'input[type="password"], input[name*="pin"], input[name*="mpin"], ' +
        'input[name*="otp"], input[name*="card"], input[name*="cvv"]'
    );
    if (sensitiveInputs.length > 0 && scamScore > 30) {
        scamScore += 15;
    }
    
    const urgencyWords = ['immediately', 'asap', 'within 24 hours', 'deadline', 'expires'];
    urgencyWords.forEach(word => {
        if (pageText.includes(word)) scamScore += 5;
    });
    
    scamScore = Math.min(100, scamScore);
    
    if (scamScore < 35 || warningAlreadyShown || document.getElementById('ai-fraud-warning')) {
        return { score: scamScore, keywords: foundKeywords, isScam: scamScore > 40 };
    }
    
    warningAlreadyShown = true;
    
    const warningDiv = document.createElement('div');
    warningDiv.id = 'ai-fraud-warning';
    warningDiv.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: #000000;
        color: #ffffff;
        text-align: center;
        padding: 14px;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 14px;
        font-weight: 500;
        box-shadow: 0 4px 15px rgba(0,0,0,0.5);
        border-bottom: 2px solid #ef4444;
        animation: slideDown 0.4s ease;
        transition: opacity 0.5s ease, transform 0.4s ease;
    `;
    
    let riskColor = '#f59e0b';
    let riskText = 'SUSPICIOUS';
    if (scamScore >= 70) {
        riskColor = '#ef4444';
        riskText = 'HIGH RISK - SCAM DETECTED';
    } else if (scamScore >= 50) {
        riskColor = '#f59e0b';
        riskText = 'ELEVATED RISK';
    } else {
        riskColor = '#fbbf24';
        riskText = 'CAUTION ADVISED';
    }
    
    warningDiv.innerHTML = `
        <div style="max-width: 900px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <span style="font-size: 24px; background: ${riskColor}; border-radius: 50%; width: 32px; height: 32px; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;">⚠️</span>
                <div style="text-align: left;">
                    <strong style="color: ${riskColor};">AI Fraud Shield Alert</strong>
                    <span style="color: #d4d4d4;"> | ${riskText}</span>
                    <span style="margin-left: 8px; background: ${riskColor}; color: #000; padding: 2px 8px; border-radius: 20px; font-size: 12px; font-weight: bold;">Risk: ${scamScore}%</span>
                </div>
            </div>
            <div style="display: flex; gap: 8px;">
                <button id="learnMoreWarning" style="background: #1f2937; color: white; border: 1px solid #374151; padding: 6px 16px; border-radius: 20px; cursor: pointer; font-weight: 500; font-size: 12px;">📋 Details</button>
                <button id="closeWarning" style="background: ${riskColor}; color: #000; border: none; padding: 6px 16px; border-radius: 20px; cursor: pointer; font-weight: bold; font-size: 12px;">✕ Close</button>
            </div>
        </div>
    `;
    document.body.insertBefore(warningDiv, document.body.firstChild);
    
    // ✅ FIXED: 8 seconds auto-dismiss (not 0.5 seconds!)
    let autoDismissTimeout = setTimeout(() => {
        dismissWarning(warningDiv);
    }, 8000);
    
    document.getElementById('closeWarning')?.addEventListener('click', () => {
        clearTimeout(autoDismissTimeout);
        dismissWarning(warningDiv);
    });
    
    document.getElementById('learnMoreWarning')?.addEventListener('click', () => {
        const existingDetails = document.getElementById('warning-details');
        if (existingDetails) existingDetails.remove();
        
        const detailsDiv = document.createElement('div');
        detailsDiv.id = 'warning-details';
        detailsDiv.style.cssText = `
            position: fixed;
            top: 70px;
            left: 20px;
            right: 20px;
            max-width: 500px;
            margin: 0 auto;
            background: #0a0a0a;
            border: 1px solid #ef4444;
            border-radius: 12px;
            padding: 16px;
            z-index: 999999;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            box-shadow: 0 8px 25px rgba(0,0,0,0.5);
            animation: slideDown 0.3s ease;
        `;
        detailsDiv.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <strong style="color: #ef4444;">⚠️ Scam Indicators Found</strong>
                <button id="closeDetails" style="background: none; border: none; color: white; font-size: 20px; cursor: pointer;">✕</button>
            </div>
            <div style="color: #d4d4d4; font-size: 13px; margin-bottom: 12px;">
                <strong>Risk Score: ${scamScore}/100</strong>
                <div style="background: #1f2937; border-radius: 4px; height: 8px; margin: 8px 0;">
                    <div style="background: ${riskColor}; width: ${scamScore}%; height: 8px; border-radius: 4px;"></div>
                </div>
            </div>
            <div style="color: #d4d4d4; font-size: 12px;">
                <strong>Suspicious keywords found:</strong>
                <ul style="margin: 8px 0 0 20px; color: #fbbf24;">
                    ${foundKeywords.slice(0, 8).map(kw => `<li>${kw}</li>`).join('')}
                </ul>
                ${suspiciousLinks.length > 0 ? `<p><strong>🔗 Suspicious links:</strong> ${suspiciousLinks.length} found</p>` : ''}
                ${sensitiveInputs.length > 0 ? `<p><strong>🔐 Sensitive form fields:</strong> ${sensitiveInputs.length} found</p>` : ''}
            </div>
            <div style="margin-top: 15px; padding-top: 10px; border-top: 1px solid #2a2a2a; color: #fca5a5; font-size: 11px;">
                ⚠️ Never share passwords, PINs, OTPs, or send money to unknown sites
            </div>
        `;
        document.body.appendChild(detailsDiv);
        
        let detailsTimeout = setTimeout(() => dismissDetails(detailsDiv), 10000);
        
        document.getElementById('closeDetails')?.addEventListener('click', () => {
            clearTimeout(detailsTimeout);
            dismissDetails(detailsDiv);
        });
    });
    
    return { score: scamScore, keywords: foundKeywords, isScam: scamScore > 40 };
}

function dismissWarning(warningDiv) {
    if (!warningDiv || !warningDiv.parentNode) return;
    warningDiv.style.opacity = '0';
    warningDiv.style.transform = 'translateY(-100%)';
    setTimeout(() => {
        if (warningDiv && warningDiv.parentNode) warningDiv.remove();
    }, 500);
}

function dismissDetails(detailsDiv) {
    if (!detailsDiv || !detailsDiv.parentNode) return;
    detailsDiv.style.opacity = '0';
    detailsDiv.style.transform = 'translateY(-10px)';
    detailsDiv.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    setTimeout(() => {
        if (detailsDiv && detailsDiv.parentNode) detailsDiv.remove();
    }, 300);
}

// ============ PAGE CONTENT EXTRACTION ============
function extractPageContent() {
    const visibleText = Array.from(document.querySelectorAll('body *'))
        .filter(el => {
            const style = window.getComputedStyle(el);
            return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
        })
        .map(el => el.innerText)
        .join(' ')
        .substring(0, 10000);
    
    const links = Array.from(document.querySelectorAll('a'))
        .map(a => a.href)
        .filter(href => href && !href.startsWith('javascript:'))
        .slice(0, 100);
    
    return { text: visibleText, links: links, forms: document.querySelectorAll('form').length, title: document.title };
}

// ============ MESSAGE HANDLERS ============
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyzePage") {
        sendResponse({ content: extractPageContent(), url: window.location.href });
    } else if (request.action === "checkPageSafety") {
        const result = checkAndDisplayScamWarning();
        sendResponse({ score: result.score, isScam: result.isScam });
    } else if (request.action === "toggleDarkMode") {
        const existingStyle = document.getElementById('ai-fraud-shield-theme');
        if (existingStyle) removeHighContrastTheme();
        else applyHighContrastTheme();
        sendResponse({ success: true });
    } else if (request.action === "getRiskScore") {
        const result = checkAndDisplayScamWarning();
        sendResponse({ score: result.score, isScam: result.isScam, keywords: result.keywords });
    }
    return true;
});

// ============ DEBOUNCED SCAM DETECTION ============
let detectionTimeout;
function debouncedScamDetection() {
    clearTimeout(detectionTimeout);
    detectionTimeout = setTimeout(() => {
        checkAndDisplayScamWarning();
    }, 500);
}

// ============ ENHANCEMENT FUNCTIONS ============
function protectPasswordFields() {
    document.querySelectorAll('input[type="password"]').forEach(field => {
        if (field.dataset.fraudshieldProtected) return;
        field.dataset.fraudshieldProtected = 'true';
        
        const pageScore = checkPageSafety();
        if (pageScore > 40) {
            const warning = document.createElement('div');
            warning.style.cssText = `background:#dc3545;color:white;padding:8px 12px;border-radius:6px;font-size:12px;margin:5px 0;font-family:-apple-system,sans-serif;`;
            warning.innerHTML = `<strong>⚠️ AI Fraud Shield Warning!</strong><br>This site shows scam indicators (Score: ${pageScore}/100).<br><strong>DO NOT enter your password here!</strong>`;
            field.parentNode.insertBefore(warning, field);
            field.style.border = '2px solid #dc3545';
            field.addEventListener('focus', () => showToast('⚠️ Warning: This site is suspicious!', 'danger'));
        }
    });
}

function protectFormSubmissions() {
    document.querySelectorAll('form').forEach(form => {
        if (form.dataset.fraudshieldProtected) return;
        form.dataset.fraudshieldProtected = 'true';
        
        form.addEventListener('submit', (e) => {
            const hasSensitive = form.querySelector('input[type="password"], input[name*="pin"], input[name*="card"], input[name*="cvv"]');
            if (hasSensitive && checkPageSafety() > 50) {
                e.preventDefault();
                if (confirm(`🚨 AI FRAUD SHIELD WARNING!\n\nThis page has a scam risk score of ${checkPageSafety()}/100.\n\n⚠️ Submitting your information here could be dangerous!\n\nClick Cancel to stay safe.`)) {
                    form.submit();
                } else {
                    showToast('✅ Good decision! Your information is safe.', 'success');
                }
            }
        });
    });
}

function scanDownloads() {
    document.addEventListener('click', (e) => {
        const link = e.target.closest('a');
        if (!link || !link.href) return;
        
        const downloadExts = ['.exe', '.zip', '.rar', '.msi', '.dmg', '.apk', '.scr', '.bat', '.cmd', '.ps1'];
        if (downloadExts.some(ext => link.href.toLowerCase().includes(ext)) && checkSuspiciousDomain()) {
            e.preventDefault();
            if (confirm(`⚠️ AI FRAUD SHIELD WARNING!\n\nFile: ${link.href.substring(link.href.lastIndexOf('/') + 1)}\nDomain: ${location.hostname}\n\nDownloading from suspicious sites can install malware.\n\nContinue anyway?`)) {
                window.location.href = link.href;
            }
        }
    });
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed; bottom: 20px; right: 20px; background: ${type === 'danger' ? '#dc3545' : '#10b981'};
        color: white; padding: 12px 20px; border-radius: 10px; z-index: 999999;
        font-family: -apple-system, sans-serif; font-size: 13px; font-weight: 500;
        box-shadow: 0 8px 25px rgba(0,0,0,0.3); animation: slideUp 0.3s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 4000);
}

// ============ INITIALIZATION ============
// Add animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown { from { opacity: 0; transform: translateY(-30px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
`;
document.head.appendChild(style);

// Load settings
chrome.storage.sync.get(['darkModeEnabled'], (settings) => {
    if (settings.darkModeEnabled) applyHighContrastTheme();
});

// Initialize with debounced detection
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', debouncedScamDetection);
} else {
    debouncedScamDetection();
}

// Watch for URL changes (SPAs)
let lastUrl = location.href;
new MutationObserver(() => {
    if (location.href !== lastUrl) {
        lastUrl = location.href;
        warningAlreadyShown = false;
        debouncedScamDetection();
    }
}).observe(document, { subtree: true, childList: true });

// Start enhanced protections
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        protectPasswordFields();
        protectFormSubmissions();
        scanDownloads();
    });
} else {
    protectPasswordFields();
    protectFormSubmissions();
    scanDownloads();
}

console.log('🛡️ AI Fraud Shield: Content script loaded - FULLY FIXED');