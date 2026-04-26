// content.js - Runs on every webpage

// ============ HIGH CONTRAST THEME for ChatGPT & DeepSeek ============
function applyHighContrastTheme() {
    const hostname = window.location.hostname;
    let styleContent = '';
    
    const colors = {
        bg: '#0a0e27',
        card: '#111827',
        text: '#f3f4f6',
        textMuted: '#9ca3af',
        accent: '#3b82f6',
        accentHover: '#60a5fa',
        border: '#374151',
        input: '#1f2937'
    };
    
    // ChatGPT theme with high contrast
    if (hostname.includes('chat.openai.com') || hostname.includes('chatgpt.com')) {
        styleContent = `
            body, html, #__next, main, .flex.h-full, .overflow-hidden {
                background-color: ${colors.bg} !important;
            }
            .dark\\:bg-gray-800, .bg-gray-900, .flex-shrink-0 {
                background-color: ${colors.card} !important;
            }
            .text-gray-600, .text-gray-700, .text-gray-800, .text-gray-900,
            p, span, div, .text-base, .text-sm {
                color: ${colors.text} !important;
            }
            .text-gray-400, .text-gray-500 {
                color: ${colors.textMuted} !important;
            }
            button, .btn, .rounded-full {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            button:hover {
                background-color: ${colors.accent} !important;
                color: white !important;
            }
            input, textarea, .ProseMirror {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            pre, code {
                background-color: ${colors.bg} !important;
                color: #fbbf24 !important;
            }
            a { color: ${colors.accent} !important; }
            ::-webkit-scrollbar { width: 8px; background: ${colors.bg}; }
            ::-webkit-scrollbar-thumb { background: ${colors.accent}; border-radius: 4px; }
        `;
    }
    
    // DeepSeek theme with high contrast
    else if (hostname.includes('chat.deepseek.com')) {
        styleContent = `
            body, .app-container, .chat-container {
                background-color: ${colors.bg} !important;
            }
            .sidebar, .history-panel {
                background-color: ${colors.card} !important;
            }
            .message, .user-message, .assistant-message {
                background-color: ${colors.card} !important;
                color: ${colors.text} !important;
            }
            .user-message {
                background-color: ${colors.accent} !important;
                color: white !important;
            }
            p, span, div, h1, h2, h3 {
                color: ${colors.text} !important;
            }
            textarea, input {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
                border: 1px solid ${colors.border} !important;
            }
            button {
                background-color: ${colors.input} !important;
                color: ${colors.text} !important;
            }
            button:hover {
                background-color: ${colors.accent} !important;
                color: white !important;
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
        'pin', 'password', 'otp', 'verification code', 'account will be closed'
    ];
    
    scamKeywords.forEach(keyword => {
        if (pageText.includes(keyword)) {
            scamScore += 12;
            foundKeywords.push(keyword);
        }
    });
    
    // Check for suspicious links
    const links = document.querySelectorAll('a');
    const suspiciousLinks = Array.from(links).filter(link => {
        const href = link.href.toLowerCase();
        return href.includes('secure-') || href.includes('verify-') || href.includes('login-');
    });
    
    if (suspiciousLinks.length > 0) {
        scamScore += suspiciousLinks.length * 5;
    }
    
    // Check for forms asking for sensitive info
    const inputs = document.querySelectorAll('input[type="password"], input[name*="pin"], input[name*="mpin"]');
    if (inputs.length > 0 && scamScore > 30) {
        scamScore += 15;
    }
    
    scamScore = Math.min(100, scamScore);
    
    // Show warning if high risk
    if (scamScore > 40 && !document.getElementById('ai-fraud-warning')) {
        const warningDiv = document.createElement('div');
        warningDiv.id = 'ai-fraud-warning';
        warningDiv.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #dc2626, #b91c1c);
            color: white;
            text-align: center;
            padding: 12px;
            z-index: 999999;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            font-size: 13px;
            font-weight: 500;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        `;
        warningDiv.innerHTML = `
            <div style="max-width: 800px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 20px;">⚠️</span>
                    <span><strong>AI Fraud Shield Alert</strong> | This page shows scam indicators (Risk: ${scamScore}%)</span>
                </div>
                <button id="closeWarning" style="background: white; color: #dc2626; border: none; padding: 4px 12px; border-radius: 20px; cursor: pointer; font-weight: bold; font-size: 12px;">✕ Close</button>
            </div>
        `;
        document.body.insertBefore(warningDiv, document.body.firstChild);
        
        document.getElementById('closeWarning')?.addEventListener('click', () => {
            warningDiv.remove();
        });
    }
    
    return { score: scamScore, keywords: foundKeywords, isScam: scamScore > 40 };
}

// ============ MESSAGE HANDLERS ============
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Analyze page for scam indicators
    if (request.action === "analyzePage") {
        const pageText = document.body.innerText;
        const links = Array.from(document.querySelectorAll('a')).map(a => a.href);
        const forms = document.querySelectorAll('form').length;
        const title = document.title;
        
        sendResponse({
            content: {
                text: pageText.substring(0, 5000),
                links: links.slice(0, 100),
                forms: forms,
                title: title
            },
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
    
    return true;
});

// ============ INITIALIZATION ============
// Load settings and apply theme
chrome.storage.sync.get(['darkModeEnabled'], (settings) => {
    if (settings.darkModeEnabled) {
        applyHighContrastTheme();
    }
});

// Check for scam indicators after page loads
setTimeout(() => {
    checkAndDisplayScamWarning();
}, 2000);