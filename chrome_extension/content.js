// content.js - Runs on every webpage

// ============ HIGH CONTRAST THEME for ChatGPT & DeepSeek ============
function applyHighContrastTheme() {
    const hostname = window.location.hostname;
    let styleContent = '';
    
    // Ultra high contrast colors - WCAG AAA compliant
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
    
    // ChatGPT theme with maximum contrast
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
            .dark\\:bg-gray-800, .sidebar, .nav, aside {
                background-color: ${colors.card} !important;
                border-right: 1px solid ${colors.border} !important;
            }
            ::-webkit-scrollbar { width: 10px; background: ${colors.bg}; }
            ::-webkit-scrollbar-track { background: ${colors.card}; }
            ::-webkit-scrollbar-thumb { background: ${colors.accent}; border-radius: 5px; }
            ::-webkit-scrollbar-thumb:hover { background: ${colors.accentHover}; }
            ::selection { background: ${colors.accent}; color: ${colors.text}; }
        `;
    }
    
    // DeepSeek theme with maximum contrast
    else if (hostname.includes('chat.deepseek.com')) {
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
            textarea:focus, input:focus {
                border-color: ${colors.accent} !important;
                outline: none !important;
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

// ============ SCAM WARNING DETECTION - AUTO DISMISS ============
// FIXED: Global variable to track if warning was already shown on this page
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
    
    // FIXED: Don't show if already dismissed on this page or score too low
    if (scamScore < 35 || warningAlreadyShown || document.getElementById('ai-fraud-warning')) {
        return { score: scamScore, keywords: foundKeywords, isScam: scamScore > 40 };
    }
    
    warningAlreadyShown = true;
    
    // ============ CREATE WARNING BANNER ============
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
                <button id="learnMoreWarning" style="background: #1f2937; color: white; border: 1px solid #374151; padding: 6px 16px; border-radius: 20px; cursor: pointer; font-weight: 500; font-size: 12px; white-space: nowrap;">📋 Details</button>
                <button id="closeWarning" style="background: ${riskColor}; color: #000; border: none; padding: 6px 16px; border-radius: 20px; cursor: pointer; font-weight: bold; font-size: 12px; white-space: nowrap;">✕ Close</button>
            </div>
        </div>
    `;
    document.body.insertBefore(warningDiv, document.body.firstChild);
    
    // ============================================================
    // FIXED: AUTO-DISMISS AFTER 8 SECONDS (between 5-10 seconds)
    // ============================================================
    let autoDismissTimeout = setTimeout(() => {
        dismissWarning(warningDiv);
    }, 500); // 8 seconds - adjust this number (5000=5s, 10000=10s)
    
    // ============ CLOSE BUTTON - Manual dismiss ============
    document.getElementById('closeWarning')?.addEventListener('click', () => {
        clearTimeout(autoDismissTimeout); // Cancel auto-dismiss since user clicked
        dismissWarning(warningDiv);
    });
    
    // ============ DETAILS BUTTON ============
    document.getElementById('learnMoreWarning')?.addEventListener('click', () => {
        // Remove existing details if any
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
                <button id="closeDetails" style="background: none; border: none; color: white; font-size: 20px; cursor: pointer; padding: 4px 8px;">✕</button>
            </div>
            <div style="color: #d4d4d4; font-size: 13px; margin-bottom: 12px;">
                <strong>Risk Score: ${scamScore}/100</strong>
                <div style="background: #1f2937; border-radius: 4px; height: 8px; margin: 8px 0;">
                    <div style="background: ${riskColor}; width: ${scamScore}%; height: 8px; border-radius: 4px; transition: width 0.3s ease;"></div>
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
        
        // Auto-dismiss details after 10 seconds
        let detailsTimeout = setTimeout(() => {
            dismissDetails(detailsDiv);
        }, 10000);
        
        document.getElementById('closeDetails')?.addEventListener('click', () => {
            clearTimeout(detailsTimeout);
            dismissDetails(detailsDiv);
        });
    });
    
    return { score: scamScore, keywords: foundKeywords, isScam: scamScore > 40 };
}

// FIXED: Smooth dismiss function for warning banner
function dismissWarning(warningDiv) {
    if (!warningDiv || !warningDiv.parentNode) return;
    warningDiv.style.opacity = '0';
    warningDiv.style.transform = 'translateY(-100%)';
    setTimeout(() => {
        if (warningDiv && warningDiv.parentNode) {
            warningDiv.remove();
        }
    }, 500);
}

// FIXED: Smooth dismiss function for details panel
function dismissDetails(detailsDiv) {
    if (!detailsDiv || !detailsDiv.parentNode) return;
    detailsDiv.style.opacity = '0';
    detailsDiv.style.transform = 'translateY(-10px)';
    detailsDiv.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    setTimeout(() => {
        if (detailsDiv && detailsDiv.parentNode) {
            detailsDiv.remove();
        }
    }, 300);
}

// ============ PAGE CONTENT EXTRACTION ============
function extractPageContent() {
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
    
    const links = Array.from(document.querySelectorAll('a'))
        .map(a => a.href)
        .filter(href => href && !href.startsWith('javascript:'))
        .slice(0, 100);
    
    const forms = document.querySelectorAll('form').length;
    const title = document.title;
    
    return { text: visibleText, links: links, forms: forms, title: title };
}

// ============ MESSAGE HANDLERS ============
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyzePage") {
        const pageContent = extractPageContent();
        sendResponse({ content: pageContent, url: window.location.href });
    }
    
    if (request.action === "checkPageSafety") {
        const result = checkAndDisplayScamWarning();
        sendResponse({ score: result.score, isScam: result.isScam });
    }
    
    if (request.action === "toggleDarkMode") {
        const existingStyle = document.getElementById('ai-fraud-shield-theme');
        if (existingStyle) {
            existingStyle.remove();
        } else {
            applyHighContrastTheme();
        }
        sendResponse({ success: true });
    }
    
    if (request.action === "getRiskScore") {
        const result = checkAndDisplayScamWarning();
        sendResponse({ score: result.score, isScam: result.isScam, keywords: result.keywords });
    }
    
    return true;
});

// ============ INITIALIZATION ============
// Add animations
const animationStyle = document.createElement('style');
animationStyle.textContent = `
    @keyframes slideDown {
        from { opacity: 0; transform: translateY(-30px); }
        to { opacity: 1; transform: translateY(0); }
    }
`;
document.head.appendChild(animationStyle);

// Load settings and apply theme
chrome.storage.sync.get(['darkModeEnabled'], (settings) => {
    if (settings.darkModeEnabled) {
        applyHighContrastTheme();
    }
});

// Check for scam indicators after page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => checkAndDisplayScamWarning(), 1500);
    });
} else {
    setTimeout(() => checkAndDisplayScamWarning(), 1500);
}

// Also check on URL changes (for SPAs)
let lastUrl = location.href;
new MutationObserver(() => {
    const url = location.href;
    if (url !== lastUrl) {
        lastUrl = url;
        warningAlreadyShown = false; // Reset for new page
        setTimeout(() => checkAndDisplayScamWarning(), 1000);
    }
}).observe(document, { subtree: true, childList: true });

console.log('🛡️ AI Fraud Shield: Content script loaded');


// ============================================================
// ENHANCEMENT: PASSWORD FIELD PROTECTION
// ============================================================
function protectPasswordFields() {
  const passwordFields = document.querySelectorAll('input[type="password"]');
  
  passwordFields.forEach(field => {
    // Skip if already protected
    if (field.dataset.fraudshieldProtected) return;
    field.dataset.fraudshieldProtected = 'true';
    
    // Check if page is suspicious
    const pageScore = checkPageSafety();
    
    if (pageScore > 40) {
      // Add warning near password field
      const warning = document.createElement('div');
      warning.style.cssText = `
        background: #dc3545;
        color: white;
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 12px;
        margin: 5px 0;
        animation: slideDown 0.3s ease;
        font-family: -apple-system, sans-serif;
      `;
      warning.innerHTML = `
        <strong>⚠️ AI Fraud Shield Warning!</strong><br>
        This site shows scam indicators (Score: ${pageScore}/100).<br>
        <strong>DO NOT enter your password here!</strong>
      `;
      field.parentNode.insertBefore(warning, field);
      
      // Add red border to password field
      field.style.border = '2px solid #dc3545';
      field.style.boxShadow = '0 0 10px rgba(220,53,69,0.3)';
      
      // Warn on focus
      field.addEventListener('focus', () => {
        showToast('⚠️ Warning: This site is suspicious. Do not enter your password!', 'danger');
      });
    }
  });
}

// ============================================================
// ENHANCEMENT: FORM SUBMISSION WARNING
// ============================================================
function protectFormSubmissions() {
  const forms = document.querySelectorAll('form');
  
  forms.forEach(form => {
    if (form.dataset.fraudshieldProtected) return;
    form.dataset.fraudshieldProtected = 'true';
    
    form.addEventListener('submit', async (e) => {
      // Check if form has password/sensitive fields
      const hasPassword = form.querySelector('input[type="password"]');
      const hasCard = form.querySelector('input[name*="card"], input[name*="credit"], input[name*="cvv"]');
      const hasPin = form.querySelector('input[name*="pin"], input[name*="mpin"], input[name*="otp"]');
      
      if (hasPassword || hasCard || hasPin) {
        const pageScore = checkPageSafety();
        
        if (pageScore > 50) {
          e.preventDefault();
          
          const confirmed = confirm(
            `🚨 AI FRAUD SHIELD WARNING!\n\n` +
            `This page has a scam risk score of ${pageScore}/100.\n\n` +
            `⚠️ Submitting your information here could be dangerous!\n\n` +
            `Are you ABSOLUTELY sure you want to continue?\n\n` +
            `Click Cancel to stay safe.`
          );
          
          if (!confirmed) {
            showToast('✅ Good decision! Your information is safe.', 'success');
          } else {
            form.submit();
          }
        }
      }
    });
  });
}

// ============================================================
// ENHANCEMENT: CHECK PAGE SAFETY (Local + API)
// ============================================================
function checkPageSafety() {
  let score = 0;
  const pageText = document.body.innerText.toLowerCase();
  
  // Check for scam keywords
  const scamKeywords = [
    'verify your account', 'suspended', 'blocked', 'urgent',
    'send money', 'mpesa', 'pin', 'password', 'otp',
    'click here', 'limited time', 'act now'
  ];
  
  scamKeywords.forEach(keyword => {
    if (pageText.includes(keyword)) score += 8;
  });
  
  // Check for suspicious patterns
  const hasPasswordForm = document.querySelector('input[type="password"]') !== null;
  const hasSuspiciousDomain = checkSuspiciousDomain();
  const hasHiddenFields = document.querySelectorAll('input[type="hidden"]').length > 3;
  
  if (hasPasswordForm) score += 10;
  if (hasSuspiciousDomain) score += 25;
  if (hasHiddenFields) score += 5;
  
  return Math.min(100, score);
}

function checkSuspiciousDomain() {
  const domain = window.location.hostname.toLowerCase();
  const suspiciousPatterns = [
    'secure-', 'verify-', 'login-', 'update-', 'confirm-',
    'account-', 'security-', 'banking-', 'mpesa-', 'safaricom-'
  ];
  
  return suspiciousPatterns.some(pattern => domain.includes(pattern));
}

// ============================================================
// ENHANCEMENT: DOWNLOAD SCANNING
// ============================================================
function scanDownloads() {
  // Intercept download links
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (!link) return;
    
    const href = link.href;
    if (!href) return;
    
    // Check if it's a download link
    const downloadExtensions = ['.exe', '.zip', '.rar', '.msi', '.dmg', '.apk', '.scr', '.bat', '.cmd', '.ps1'];
    const isDownload = downloadExtensions.some(ext => href.toLowerCase().includes(ext));
    
    if (isDownload) {
      const suspicious = checkSuspiciousDomain();
      if (suspicious) {
        e.preventDefault();
        
        const warning = confirm(
          `⚠️ AI FRAUD SHIELD WARNING!\n\n` +
          `This download is from a suspicious domain!\n\n` +
          `File: ${href.substring(href.lastIndexOf('/') + 1)}\n` +
          `Domain: ${window.location.hostname}\n\n` +
          `Downloading from suspicious sites can install malware.\n\n` +
          `Cancel to stay safe.`
        );
        
        if (warning) {
          window.location.href = href;
        }
      }
    }
  });
}

// ============================================================
// ENHANCEMENT: REAL-TIME URL SAFETY CHECK
// ============================================================
async function checkCurrentUrl() {
  const url = window.location.href;
  
  // Skip known safe domains
  const safeDomains = ['google.com', 'facebook.com', 'twitter.com', 'youtube.com', 'wikipedia.org'];
  const domain = window.location.hostname.replace('www.', '');
  if (safeDomains.some(safe => domain.includes(safe))) return;
  
  try {
    const response = await fetch('http://127.0.0.1:8000/api/v1/check/url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'test_key_123'
      },
      body: JSON.stringify({ url: url })
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.is_safe === false && data.score > 40) {
        showUrlWarning(data.score, data.warnings);
      }
    }
  } catch (e) {
    // API not available - skip
  }
}

function showUrlWarning(score, warnings) {
  const existingWarning = document.getElementById('fraudshield-url-warning');
  if (existingWarning) return;
  
  const banner = document.createElement('div');
  banner.id = 'fraudshield-url-warning';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: #dc3545;
    color: white;
    padding: 12px 20px;
    text-align: center;
    z-index: 999999;
    font-family: -apple-system, sans-serif;
    font-size: 14px;
    font-weight: 600;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    animation: slideDown 0.4s ease;
  `;
  
  banner.innerHTML = `
    <div style="display:flex;justify-content:center;align-items:center;gap:15px;flex-wrap:wrap;">
      <span>🚨 <strong>WARNING:</strong> This URL is suspicious (Score: ${score}/100)</span>
      <button onclick="this.parentElement.parentElement.remove()" style="background:white;color:#dc3545;border:none;padding:5px 15px;border-radius:20px;cursor:pointer;font-weight:700;">✕ Dismiss</button>
    </div>
  `;
  
  document.body.insertBefore(banner, document.body.firstChild);
  
  // Auto-dismiss after 8 seconds
  setTimeout(() => {
    if (banner.parentNode) {
      banner.style.opacity = '0';
      banner.style.transition = 'opacity 0.5s';
      setTimeout(() => banner.remove(), 500);
    }
  }, 8000);
}

// ============================================================
// ENHANCEMENT: TOAST NOTIFICATIONS
// ============================================================
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  const bgColor = type === 'danger' ? '#dc3545' : type === 'success' ? '#10b981' : '#002855';
  
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: ${bgColor};
    color: white;
    padding: 12px 20px;
    border-radius: 10px;
    z-index: 999999;
    font-family: -apple-system, sans-serif;
    font-size: 13px;
    font-weight: 500;
    box-shadow: 0 8px 25px rgba(0,0,0,0.3);
    animation: slideUp 0.3s ease;
    max-width: 350px;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ============================================================
// INITIALIZE ALL PROTECTIONS
// ============================================================
function initEnhancedProtection() {
  console.log('🛡️ AI Fraud Shield - Enhanced Protection Active');
  
  // Run on page load
  protectPasswordFields();
  protectFormSubmissions();
  scanDownloads();
  checkCurrentUrl();
  
  // Re-run on DOM changes (for SPAs)
  const observer = new MutationObserver(() => {
    protectPasswordFields();
    protectFormSubmissions();
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

// Add CSS animations
const protectionStyles = document.createElement('style');
protectionStyles.textContent = `
  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-30px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes slideUp {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }
`;
document.head.appendChild(protectionStyles);

// Start protection
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initEnhancedProtection);
} else {
  initEnhancedProtection();
}

console.log('🛡️ AI Fraud Shield: Enhanced Extension Loaded');