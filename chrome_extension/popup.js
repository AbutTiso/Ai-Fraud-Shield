// Get CSRF token from cookies (for Django backend)
function getCSRFToken() {
    return document.cookie.split('; ')
        .find(row => row.startsWith('csrftoken='))
        ?.split('=')[1] || '';
}

// Load dark mode setting
chrome.storage.sync.get(['darkModeEnabled'], (settings) => {
    const darkModeToggle = document.getElementById('darkModeToggle');
    if (darkModeToggle) {
        darkModeToggle.checked = settings.darkModeEnabled || false;
        
        darkModeToggle.addEventListener('change', async (e) => {
            chrome.storage.sync.set({ darkModeEnabled: e.target.checked });
            
            // Send message to content script to apply theme
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.id) {
                chrome.tabs.sendMessage(tab.id, { action: "toggleDarkMode" }).catch(() => {
                    console.log('Content script not ready');
                });
            }
        });
    }
});

document.getElementById('checkPageBtn').addEventListener('click', async () => {
    const loading = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    
    loading.classList.add('show');
    resultDiv.classList.remove('show');
    
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
            displayError("Cannot analyze browser internal pages");
            loading.classList.remove('show');
            return;
        }
        
        chrome.tabs.sendMessage(tab.id, { action: "analyzePage" }, async (response) => {
            if (chrome.runtime.lastError) {
                console.error(chrome.runtime.lastError);
                displayError("Please refresh the page and try again");
                loading.classList.remove('show');
                return;
            }
            
            if (response && response.content) {
                try {
                    const analysis = await analyzeWithBackend(response.content, response.url);
                    displayResult(analysis);
                } catch (error) {
                    console.error('Backend error:', error);
                    const fallbackAnalysis = analyzeLocally(response.content, response.url);
                    displayResult(fallbackAnalysis, true);
                }
            } else {
                displayError("Could not extract page content");
            }
            loading.classList.remove('show');
        });
    } catch (error) {
        console.error('Error:', error);
        displayError("Error analyzing page. Make sure you're on a valid webpage.");
        loading.classList.remove('show');
    }
});

async function analyzeWithBackend(content, url) {
    const response = await fetch('http://localhost:8000/api/detect-web/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken(),
            'X-Requested-With': 'XMLHttpRequest',
        },
        credentials: 'include',
        body: JSON.stringify({
            url: url,
            content: content.text,
            links: content.links,
            forms: content.forms,
            title: content.title
        })
    });
    
    if (!response.ok) {
        throw new Error('Backend analysis failed');
    }
    
    return await response.json();
}

function analyzeLocally(content, url) {
    const scamKeywords = [
        'urgent', 'verify', 'account suspended', 'win', 'prize',
        'click here', 'send money', 'mpesa', 'congratulations',
        'limited time', 'act now', 'verify your account'
    ];
    
    let score = 0;
    let reasons = [];
    const text = content.text.toLowerCase();
    
    scamKeywords.forEach(keyword => {
        if (text.includes(keyword)) {
            score += 15;
            reasons.push(`⚠️ Found suspicious phrase: "${keyword}"`);
        }
    });
    
    const suspiciousUrls = content.links.filter(link => 
        link.includes('secure-') || link.includes('verify-') || link.includes('login-')
    );
    
    if (suspiciousUrls.length > 0) {
        score += 20;
        reasons.push(`🔗 Found ${suspiciousUrls.length} suspicious link(s)`);
    }
    
    if (content.forms > 0 && score > 30) {
        score += 10;
        reasons.push(`📝 Page has forms asking for information`);
    }
    
    score = Math.min(score, 100);
    
    let risk_level, color, emoji;
    if (score >= 60) {
        risk_level = "HIGH RISK - SCAM DETECTED";
        color = "danger";
        emoji = "🔴🚨";
    } else if (score >= 30) {
        risk_level = "MEDIUM RISK - SUSPICIOUS";
        color = "warning";
        emoji = "⚠️🟡";
    } else {
        risk_level = "LOW RISK - LIKELY SAFE";
        color = "success";
        emoji = "✅🟢";
    }
    
    return {
        score: score,
        risk_level: risk_level,
        color: color,
        emoji: emoji,
        message: `Analysis of: ${content.title.substring(0, 50)}`,
        reasons: reasons.length ? reasons : ["✅ No scam indicators found"],
        warnings: reasons,
        recommendations: [
            "🔒 Never enter personal information on suspicious sites",
            "📞 Verify website legitimacy through official channels"
        ]
    };
}

function displayResult(data, isLocal = false) {
    const resultDiv = document.getElementById('result');
    
    let riskClass = '';
    if (data.risk_level.includes('HIGH')) riskClass = 'risk-high';
    else if (data.risk_level.includes('MEDIUM')) riskClass = 'risk-medium';
    else riskClass = 'risk-low';
    
    let reasonsHtml = '<ul style="margin: 10px 0 0 20px; padding: 0;">';
    const reasons = data.reasons || data.warnings || [];
    reasons.slice(0, 5).forEach(reason => {
        reasonsHtml += `<li style="margin: 5px 0;">${reason}</li>`;
    });
    reasonsHtml += '</ul>';
    
    let recommendationsHtml = '';
    if (data.recommendations && data.recommendations.length > 0) {
        recommendationsHtml = '<hr><strong>💡 Recommendations:</strong><ul style="margin: 8px 0 0 20px;">';
        data.recommendations.forEach(rec => {
            recommendationsHtml += `<li style="margin: 5px 0;">${rec}</li>`;
        });
        recommendationsHtml += '</ul>';
    }
    
    const localNote = isLocal ? '<div class="badge badge-warning" style="margin-bottom: 8px;">📡 Using local analysis (backend unavailable)</div>' : '';
    
    resultDiv.className = `result show ${riskClass}`;
    resultDiv.innerHTML = `
        ${localNote}
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <strong style="font-size: 14px;">${data.emoji} ${data.risk_level}</strong>
            <span class="risk-score">${data.score}/100</span>
        </div>
        <div class="progress" style="height: 8px; margin: 10px 0; border-radius: 4px;">
            <div class="progress-bar" role="progressbar" 
                 style="width: ${data.score}%; background-color: ${data.color === 'danger' ? '#dc3545' : (data.color === 'warning' ? '#ffc107' : '#28a745')}; border-radius: 4px;">
            </div>
        </div>
        <p style="margin: 10px 0 0; font-size: 13px;">${data.message}</p>
        ${reasonsHtml}
        ${recommendationsHtml}
        <hr>
        <small style="color: #666; display: block; text-align: center;">
            ⚠️ Never share passwords, PINs, or send money to unknown sites
        </small>
    `;
    
    resultDiv.classList.add('show');
}

function displayError(message) {
    const resultDiv = document.getElementById('result');
    resultDiv.className = 'result show risk-high';
    resultDiv.innerHTML = `
        <strong>⚠️ Error</strong><br>
        ${message}<br><br>
        <small>Tips:<br>
        • Make sure you're on a regular webpage<br>
        • Try refreshing the page<br>
        • The page might not allow analysis</small>
    `;
    resultDiv.classList.add('show');
}