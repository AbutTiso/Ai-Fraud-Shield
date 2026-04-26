// content.js - Runs on every webpage

// ============ HIGH CONTRAST THEME for ChatGPT & DeepSeek ============
function applyHighContrastTheme() {
    const hostname = window.location.hostname;
    let styleContent = '';
    
    // Ultra high contrast colors - WCAG AAA compliant
    const colors = {
        bg: '#000000',           // Pure black for max contrast
        card: '#0a0a0a',         // Almost black
        text: '#ffffff',         // Pure white
        textMuted: '#d4d4d4',    // Light gray (still high contrast)
        accent: '#3b82f6',       // Bright blue
        accentHover: '#60a5fa',  // Lighter blue
        border: '#2a2a2a',       // Dark gray border
        input: '#1a1a1a'         // Dark input background
    };
    
    // ChatGPT theme with maximum contrast
    if (hostname.includes('chat.openai.com') || hostname.includes('chatgpt.com')) {
        styleContent = `
            /* Force dark background on all elements */
            body, html, #__next, main, .flex.h-full, .overflow-hidden,
            .bg-white, .dark\\:bg-gray-800, .bg-gray-50, .bg-gray-100,
            .bg-gray-200, .bg-gray-900, .flex-shrink-0 {
                background-color: ${colors.bg} !important;
            }
            
            /* Force white text on all text elements */
            body, p, span, div, h1, h2, h3, h4, h5, h6, li, a,
            .text-gray-600, .text-gray-700, .text-gray-800, .text-gray-900,
            .text-base, .text-sm, .text-xs, .text-lg, .text-xl,
            .prose, .markdown, .message, .text-token-text-primary {
                color: ${colors.text} !important;
            }
            
            /* Muted text gets light gray (still readable) */
            .text-gray-400, .text-gray-500, .text-token-text-secondary {
                color: ${colors.textMuted} !important;
            }
            
            /* Buttons and interactive elements */
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
            
            /* Input fields */
            input, textarea, .ProseMirror, [contenteditable="true"] {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            
            input:focus, textarea:focus {
                border-color: ${colors.accent} !important;
                outline: none !important;
            }
            
            /* Code blocks */
            pre, code, .code-block {
                background-color: ${colors.bg} !important;
                color: #fbbf24 !important;
                border: 1px solid ${colors.border} !important;
            }
            
            /* Links */
            a, a:visited {
                color: ${colors.accentHover} !important;
                text-decoration: underline !important;
            }
            
            a:hover {
                color: ${colors.accent} !important;
            }
            
            /* Sidebar and panels */
            .dark\\:bg-gray-800, .sidebar, .nav, aside {
                background-color: ${colors.card} !important;
                border-right: 1px solid ${colors.border} !important;
            }
            
            /* Scrollbar */
            ::-webkit-scrollbar {
                width: 10px;
                background: ${colors.bg};
            }
            ::-webkit-scrollbar-track {
                background: ${colors.card};
            }
            ::-webkit-scrollbar-thumb {
                background: ${colors.accent};
                border-radius: 5px;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: ${colors.accentHover};
            }
            
            /* Selection highlight */
            ::selection {
                background: ${colors.accent};
                color: ${colors.text};
            }
        `;
    }
    
    // DeepSeek theme with maximum contrast
    else if (hostname.includes('chat.deepseek.com')) {
        styleContent = `
            /* Force dark background everywhere */
            body, .app-container, .chat-container, main, .sidebar,
            .history-panel, .message-list, .input-area {
                background-color: ${colors.bg} !important;
            }
            
            /* Cards and panels */
            .sidebar, .history-panel, .settings-panel {
                background-color: ${colors.card} !important;
                border-right: 1px solid ${colors.border} !important;
            }
            
            /* Messages */
            .message, .user-message, .assistant-message,
            .message-content, .bubble {
                background-color: ${colors.card} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            
            /* User messages stand out with accent color */
            .user-message, [class*="user"] {
                background-color: ${colors.accent} !important;
                color: ${colors.text} !important;
            }
            
            /* All text elements */
            p, span, div, h1, h2, h3, h4, h5, h6, li,
            .text, .message-text, .chat-text {
                color: ${colors.text} !important;
            }
            
            /* Secondary text */
            .text-muted, .timestamp, .secondary {
                color: ${colors.textMuted} !important;
            }
            
            /* Input fields */
            textarea, input, .input-box {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            
            textarea:focus, input:focus {
                border-color: ${colors.accent} !important;
                outline: none !important;
            }
            
            /* Buttons */
            button, .btn {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            
            button:hover, .btn:hover {
                background-color: ${colors.accent} !important;
                color: ${colors.text} !important;
            }
            
            /* Code blocks */
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
    
    // Check for suspicious links
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
    
    // Check for forms asking for sensitive info
    const sensitiveInputs = document.querySelectorAll(
        'input[type="password"], input[name*="pin"], input[name*="mpin"], ' +
        'input[name*="otp"], input[name*="card"], input[name*="cvv"]'
    );
    if (sensitiveInputs.length > 0 && scamScore > 30) {
        scamScore += 15;
    }
    
    // Check for fake urgency indicators
    const urgencyWords = ['immediately', 'asap', 'within 24 hours', 'deadline', 'expires'];
    urgencyWords.forEach(word => {
        if (pageText.includes(word)) {
            scamScore += 5;
        }
    });
    
    scamScore = Math.min(100, scamScore);
    
    // Show warning if high risk
    if (scamScore > 35 && !document.getElementById('ai-fraud-warning')) {
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
                    <span style="font-size: 24px; background: ${riskColor}; border-radius: 50%; width: 32px; height: 32px; display: inline-flex; align-items: center; justify-content: center;">⚠️</span>
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
        
        document.getElementById('closeWarning')?.addEventListener('click', () => {
            warningDiv.remove();
        });
        
        document.getElementById('learnMoreWarning')?.addEventListener('click', () => {
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
                    ${suspiciousLinks.length > 0 ? `<p style="margin-top: 10px;"><strong>🔗 Suspicious links:</strong> ${suspiciousLinks.length} found</p>` : ''}
                    ${sensitiveInputs.length > 0 ? `<p><strong>🔐 Sensitive form fields:</strong> ${sensitiveInputs.length} found</p>` : ''}
                </div>
                <div style="margin-top: 15px; padding-top: 10px; border-top: 1px solid #2a2a2a; color: #fca5a5; font-size: 11px;">
                    ⚠️ Never share passwords, PINs, OTPs, or send money to unknown sites
                </div>
            `;
            document.body.appendChild(detailsDiv);
            
            document.getElementById('closeDetails')?.addEventListener('click', () => {
                detailsDiv.remove();
            });
        });
    }
    
    return { score: scamScore, keywords: foundKeywords, isScam: scamScore > 40 };
}

// ============ PAGE CONTENT EXTRACTION ============
function extractPageContent() {
    // Get visible text only
    const visibleText = Array.from(document.querySelectorAll('body *'))
        .filter(el => {
            const style = window.getComputedStyle(el);
            return style.display !== 'none' && 
                   style.visibility !== 'hidden' && 
                   style.opacity !== '0';
        })
        .map(el => el.innerText)
        .join(' ')
        .substring(0, 10000);
    
    // Get all links
    const links = Array.from(document.querySelectorAll('a'))
        .map(a => a.href)
        .filter(href => href && !href.startsWith('javascript:'))
        .slice(0, 100);
    
    // Get form count
    const forms = document.querySelectorAll('form').length;
    
    // Get page title
    const title = document.title;
    
    return {
        text: visibleText,
        links: links,
        forms: forms,
        title: title
    };
}

// ============ MESSAGE HANDLERS ============
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Analyze page for scam indicators
    if (request.action === "analyzePage") {
        const pageContent = extractPageContent();
        
        sendResponse({
            content: pageContent,
            url: window.location.href
        });
    }
    
    // Check page safety (returns score)
    if (request.action === "checkPageSafety") {
        const result = checkAndDisplayScamWarning();
        sendResponse({ score: result.score, isScam: result.isScam });
    }
    
    // Toggle dark mode / high contrast
    if (request.action === "toggleDarkMode") {
        const existingStyle = document.getElementById('ai-fraud-shield-theme');
        if (existingStyle) {
            existingStyle.remove();
        } else {
            applyHighContrastTheme();
        }
        sendResponse({ success: true });
    }
    
    // Get current page risk score
    if (request.action === "getRiskScore") {
        const result = checkAndDisplayScamWarning();
        sendResponse({ 
            score: result.score, 
            isScam: result.isScam,
            keywords: result.keywords 
        });
    }
    
    return true;
});

// ============ INITIALIZATION ============
// Load settings and apply theme
chrome.storage.sync.get(['darkModeEnabled'], (settings) => {
    if (settings.darkModeEnabled) {
        applyHighContrastTheme();
    }
});

// Check for scam indicators after page loads (delayed to ensure DOM is ready)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => {
            checkAndDisplayScamWarning();
        }, 1500);
    });
} else {
    setTimeout(() => {
        checkAndDisplayScamWarning();
    }, 1500);
}

// Also check on URL changes (for SPAs)
let lastUrl = location.href;
new MutationObserver(() => {
    const url = location.href;
    if (url !== lastUrl) {
        lastUrl = url;
        setTimeout(() => {
            checkAndDisplayScamWarning();
        }, 1000);
    }
}).observe(document, { subtree: true, childList: true });

// Log that content script is loaded
console.log('🛡️ AI Fraud Shield: Content script loaded');