// detector/static/detector/js/main.js

// Get CSRF token
function getCSRFToken() {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.startsWith('csrftoken=')) {
                cookieValue = decodeURIComponent(cookie.substring('csrftoken='.length));
                break;
            }
        }
    }
    return cookieValue;
}

// Show toast notification
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0 position-fixed bottom-0 end-0 m-3`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.style.zIndex = '9999';
    toast.style.position = 'fixed';
    toast.style.bottom = '20px';
    toast.style.right = '20px';
    toast.style.minWidth = '250px';
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    document.body.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast, { delay: 3000 });
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// Export reports as CSV
async function exportReports() {
    try {
        showToast('📥 Preparing export...', 'info');
        const response = await fetch('/api/export/', {
            headers: {
                'X-CSRFToken': getCSRFToken(),
            },
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `scam_reports_${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            showToast('✅ Export successful! Check your downloads folder.', 'success');
        } else {
            showToast('❌ Export failed. Please try again.', 'danger');
        }
    } catch (error) {
        console.error('Export error:', error);
        showToast('❌ Network error. Cannot export reports.', 'danger');
    }
}

// Tab switching
function switchTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    const activeTab = document.getElementById(`${tabName}Tab`);
    if (activeTab) {
        activeTab.classList.add('active');
    }
    
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-tab') === tabName) {
            btn.classList.add('active');
        }
    });
    
    if (tabName === 'stats') {
        loadStats();
    }
}

// Load examples
function loadExample(type, exampleType) {
    const examples = {
        sms: {
            scam: 'URGENT: Your M-Pesa account has been suspended due to suspicious activity. Click http://mpesa-update.co.ke to verify your details immediately or your account will be deactivated.',
            prize: 'CONGRATULATIONS! You have won Ksh 250,000 in our Safaricom promotion. Click https://bit.ly/claim-prize to claim your prize now!',
            safe: 'Safaricom: Your M-Pesa transaction of Ksh 500 to John Mwangi on 25/04/2026 was successful. New balance: Ksh 2,450. Thank you for using M-Pesa.'
        },
        email: {
            phishing: `From: "Safaricom Support" <no-reply@safaricom-secure.tk>
Subject: ⚠️ URGENT: Your M-Pesa Account Has Been Suspended

Dear Valued Customer,

We detected unusual activity on your M-Pesa account. For security reasons, we have temporarily suspended your account.

To verify your account and restore full access, click the link below:

http://mpesa-verify.secure-login.com/verify-account

Failure to verify within 24 hours will result in permanent account closure.

Thank you,
Safaricom Security Team`,
            safe: `From: "Safaricom" <customercare@safaricom.com>
Subject: Your M-Pesa Transaction Receipt

Dear Customer,

Your transaction has been completed successfully.

Transaction Details:
Date: 25/04/2026
Amount: Ksh 500.00
Sent to: John Mwangi (0712345678)
Transaction ID: QK4L83XG1A
Balance: Ksh 2,450.00

Thank you for using M-Pesa.

This is a system generated message.`
        }
    };
    
    const textarea = document.getElementById(`${type}Text`);
    if (textarea && examples[type] && examples[type][exampleType]) {
        textarea.value = examples[type][exampleType];
        document.getElementById(`${type}Result`).classList.remove('show');
    }
}

// Load statistics
async function loadStats() {
    try {
        const response = await fetch('/api/stats/', {
            headers: {
                'X-CSRFToken': getCSRFToken(),
            },
            credentials: 'same-origin'
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            document.getElementById('totalReports').textContent = data.total_reports || 0;
            document.getElementById('highRisk').textContent = data.high_risk_count || 0;
            document.getElementById('smsCount').textContent = data.sms_count || 0;
            document.getElementById('emailCount').textContent = data.email_count || 0;
            document.getElementById('whatsappCount').textContent = data.whatsapp_count || 0;
            document.getElementById('avgRiskScore').textContent = data.average_risk_score || 0;
            
            const recentDiv = document.getElementById('recentScams');
            if (data.recent_scams && data.recent_scams.length === 0) {
                recentDiv.innerHTML = '<p class="text-muted">No reports yet. Start detecting scams!</p>';
            } else if (data.recent_scams) {
                recentDiv.innerHTML = data.recent_scams.map(scam => `
                    <div class="scam-item">
                        <strong>[${scam.type}]</strong> 
                        <span class="badge ${scam.score >= 70 ? 'bg-danger' : (scam.score >= 40 ? 'bg-warning' : 'bg-success')}">
                            Score: ${scam.score}/100
                        </span><br>
                        <small>${scam.date}</small><br>
                        <small class="text-muted">${escapeHtml(scam.content.substring(0, 80))}...</small>
                    </div>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Error loading stats:', error);
        document.getElementById('recentScams').innerHTML = '<p class="text-danger">Error loading statistics. Make sure the server is running.</p>';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Enhanced Email Result Display (Shows links as NON-clickable text)
function displayEmailResult(data, resultDivId) {
    const resultDiv = document.getElementById(resultDivId);
    
    let headerClass = 'success';
    if (data.color === 'danger' || data.score >= 60) headerClass = 'danger';
    else if (data.color === 'warning' || data.score >= 30) headerClass = 'warning';
    
    let warningsHtml = '';
    const warningsList = data.warnings || data.reasons || [];
    if (warningsList.length > 0) {
        warningsHtml = '<h6 class="mt-3">🚨 Issues Detected:</h6>';
        warningsList.slice(0, 8).forEach(warning => {
            warningsHtml += `<div class="reason-item" style="border-left-color: ${headerClass === 'danger' ? '#dc3545' : (headerClass === 'warning' ? '#ffc107' : '#28a745')};">${escapeHtml(warning)}</div>`;
        });
    }
    
    let urlHtml = '';
    if (data.url_analyses && data.url_analyses.length > 0) {
        urlHtml = '<h6 class="mt-3">🔗 Links Found in This Email (Analyzed as TEXT - NOT Clickable):</h6>';
        urlHtml += '<div class="alert alert-secondary" style="font-size: 0.85rem; background: #f8f9fa;">';
        urlHtml += '<strong>⚠️ Important:</strong> These links are shown as PLAIN TEXT for your safety. ';
        urlHtml += 'Do NOT type them into your browser unless you are 100% sure they are safe.<br><br>';
        
        data.url_analyses.forEach((url, index) => {
            const urlColor = url.risk === 'DANGEROUS' ? '#dc3545' : (url.risk === 'SUSPICIOUS' ? '#ffc107' : '#28a745');
            urlHtml += `
                <div class="reason-item" style="border-left-color: ${urlColor}; margin-top: 10px;">
                    <div><strong>${url.emoji || '🔗'} Link ${index + 1}: ${url.risk || 'UNKNOWN'}</strong></div>
                    <div class="url-text-display">
                        <strong>URL (TEXT only - not clickable):</strong><br>
                        <span style="color: #666;">${escapeHtml(url.url)}</span>
                    </div>
                    <div style="margin-top: 5px;"><strong>Domain:</strong> ${escapeHtml(url.domain)}</div>
                    <div><strong>Message:</strong> ${escapeHtml(url.message)}</div>
                    ${url.reasons ? `<div><strong>⚠️ Issues:</strong><br>${url.reasons.map(r => `• ${escapeHtml(r)}`).join('<br>')}</div>` : ''}
                </div>
            `;
        });
        urlHtml += '</div>';
    } else if (data.urls_found > 0) {
        urlHtml = `<div class="alert alert-info mt-3"><strong>🔗 Found ${data.urls_found} URL(s)</strong> in this email.</div>`;
    }
    
    let recommendationsHtml = '';
    if (data.recommendations && data.recommendations.length > 0) {
        recommendationsHtml = '<h6 class="mt-3">💡 What To Do:</h6>';
        recommendationsHtml += '<div style="background: #f8f9fa; padding: 12px; border-radius: 8px;">';
        data.recommendations.forEach(rec => {
            recommendationsHtml += `<div style="margin-bottom: 8px;">✓ ${escapeHtml(rec)}</div>`;
        });
        recommendationsHtml += '</div>';
    } else if (data.action) {
        recommendationsHtml = `<div class="alert alert-warning mt-3"><strong>⚠️ Recommended Action:</strong> ${escapeHtml(data.action)}</div>`;
    } else if (data.recommendation) {
        recommendationsHtml = `<div class="alert alert-info mt-3"><strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}</div>`;
    }
    
    resultDiv.innerHTML = `
        <div class="result-header ${headerClass}">
            <h3>${data.emoji || '🔍'} ${data.risk_level || 'Analysis Complete'}</h3>
        </div>
        <div class="result-body">
            <p class="fw-bold">${escapeHtml(data.summary || data.message || 'Email analyzed successfully')}</p>
            
            <div class="risk-score">Risk Score: <span style="color: ${headerClass === 'danger' ? '#dc3545' : (headerClass === 'warning' ? '#ffc107' : '#28a745')};">${data.score || 0}</span> / 100</div>
            <div class="progress risk-progress"><div class="progress-bar bg-${headerClass}" style="width: ${data.score || 0}%;"></div></div>
            
            ${warningsHtml}
            ${urlHtml}
            ${recommendationsHtml}
            
            <hr>
            <div style="background: #fff3cd; padding: 12px; border-radius: 8px; margin-top: 15px;">
                <small style="color: #856404;">
                    <strong>⚠️ REMEMBER:</strong> The links above are shown as TEXT only. 
                    Do NOT copy them into your browser unless you have verified they are safe. 
                    Legitimate companies will never ask for your PIN, password, or M-Pesa code via email.
                </small>
            </div>
        </div>
    `;
    
    resultDiv.classList.add('show');
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Display SMS/URL/General results
function displayGeneralResult(data, resultDivId) {
    const resultDiv = document.getElementById(resultDivId);
    
    let headerClass = 'success';
    if (data.color === 'danger' || data.score >= 60) headerClass = 'danger';
    else if (data.color === 'warning' || data.score >= 30) headerClass = 'warning';
    
    let warningsHtml = '';
    const warningsList = data.warnings || data.reasons || [];
    if (warningsList.length > 0) {
        warningsHtml = '<h6 class="mt-3">⚠️ Details:</h6>';
        warningsList.slice(0, 8).forEach(warning => {
            warningsHtml += `<div class="reason-item" style="border-left-color: ${headerClass === 'danger' ? '#dc3545' : (headerClass === 'warning' ? '#ffc107' : '#28a745')};">${escapeHtml(warning)}</div>`;
        });
    }
    
    let urlSpecificHtml = '';
    if (data.type === 'URL' || data.domain) {
        urlSpecificHtml = `
            <div class="row mt-3">
                <div class="col-md-6">
                    <div class="alert alert-secondary">
                        <strong>🌐 Domain:</strong><br>
                        <code>${escapeHtml(data.domain || 'Unknown')}</code>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="alert ${data.has_https ? 'alert-success' : 'alert-warning'}">
                        <strong>🔒 HTTPS:</strong><br>
                        ${data.has_https ? '✅ Secure connection' : '⚠️ Not using HTTPS (insecure)'}
                    </div>
                </div>
            </div>
        `;
        
        if (data.url) {
            urlSpecificHtml += `
                <div class="alert alert-info">
                    <strong>🔗 Checked URL:</strong><br>
                    <code style="word-break: break-all;">${escapeHtml(data.url)}</code>
                </div>
            `;
        }
    }
    
    let recommendationsHtml = '';
    if (data.recommendations && data.recommendations.length > 0) {
        recommendationsHtml = '<h6 class="mt-3">💡 What To Do:</h6><div style="background: #f8f9fa; padding: 12px; border-radius: 8px;">';
        data.recommendations.forEach(rec => { recommendationsHtml += `<div>✓ ${escapeHtml(rec)}</div>`; });
        recommendationsHtml += '</div>';
    } else if (data.recommendation) {
        recommendationsHtml = `<div class="alert alert-info mt-3"><strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}</div>`;
    }
    
    resultDiv.innerHTML = `
        <div class="result-header ${headerClass}">
            <h3>${data.emoji || '🔍'} ${data.risk_level || 'Analysis Complete'}</h3>
            ${data.score ? `<div class="score-circle"><div class="score-value">${data.score}%</div><div class="score-label">Risk Score</div></div>` : ''}
        </div>
        <div class="result-body">
            <p class="fw-bold">${escapeHtml(data.message || data.summary || 'Analysis complete')}</p>
            
            ${data.score ? `
            <div class="risk-score">Risk Score: <span style="color: ${headerClass === 'danger' ? '#dc3545' : (headerClass === 'warning' ? '#ffc107' : '#28a745')};">${data.score}</span> / 100</div>
            <div class="progress risk-progress"><div class="progress-bar bg-${headerClass}" style="width: ${data.score}%;"></div></div>
            ` : ''}
            
            ${urlSpecificHtml}
            ${warningsHtml}
            ${recommendationsHtml}
            
            ${data.analysis_time ? `<div class="text-muted mt-3"><small>Analyzed at: ${data.analysis_time}</small></div>` : ''}
        </div>
    `;
    resultDiv.classList.add('show');
}

// Display WhatsApp results
function displayWhatsAppResult(data, resultDivId) {
    const resultDiv = document.getElementById(resultDivId);
    
    const scorePercent = data.score;
    let headerClass = 'success';
    if (scorePercent >= 50) headerClass = 'danger';
    else if (scorePercent >= 25) headerClass = 'warning';
    
    let suspiciousHtml = '';
    if (data.suspicious_messages && data.suspicious_messages.length > 0) {
        suspiciousHtml = `
            <div class="mt-3">
                <strong>Suspicious messages detected:</strong>
                <ul class="mt-2">
                    ${data.suspicious_messages.map(msg => `<li class="text-danger">"${escapeHtml(msg)}..."</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    const reasonsHtml = data.reasons ? data.reasons.map(reason => `<li>${escapeHtml(reason)}</li>`).join('') : '<li>No specific indicators found</li>';
    
    resultDiv.innerHTML = `
        <div class="result-header ${data.color || headerClass}">
            <h3>${data.emoji} ${data.risk_level}</h3>
            <div class="score-circle">
                <div class="score-value">${scorePercent}%</div>
                <div class="score-label">Risk Score</div>
            </div>
        </div>
        <div class="result-body">
            <div class="alert alert-${data.color === 'danger' ? 'danger' : (data.color === 'warning' ? 'warning' : 'success')}">
                <strong>${escapeHtml(data.message)}</strong>
            </div>
            
            ${data.recommendation ? `<div class="alert alert-info"><strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}</div>` : ''}
            
            <div class="row mb-3">
                <div class="col-md-6">
                    <strong>📊 Statistics:</strong>
                    <ul class="mt-2">
                        <li>Messages analyzed: ${data.message_count || 0}</li>
                        <li>Unique senders: ${data.unique_senders || 'N/A'}</li>
                        ${data.grammar_issues ? `<li>Grammar issues: ${data.grammar_issues}</li>` : ''}
                    </ul>
                </div>
                <div class="col-md-6">
                    <div class="progress mb-2" style="height: 30px;">
                        <div class="progress-bar bg-${headerClass}" role="progressbar" 
                             style="width: ${scorePercent}%;" 
                             aria-valuenow="${scorePercent}" aria-valuemin="0" aria-valuemax="100">
                            ${scorePercent}% Risk
                        </div>
                    </div>
                </div>
            </div>
            
            <strong>⚠️ Indicators Found:</strong>
            <ul>${reasonsHtml}</ul>
            
            ${suspiciousHtml}
            
            <div class="alert alert-secondary mt-3">
                <strong>💡 Safety Tips:</strong>
                <ul class="mb-0 mt-2">
                    <li>Never share your M-PESA PIN or OTP with anyone</li>
                    <li>Verify urgent money requests through a phone call</li>
                    <li>Don't click on suspicious links - they may steal your data</li>
                    <li>Report scam numbers to your mobile service provider</li>
                    <li>Block and report scammers on WhatsApp immediately</li>
                </ul>
            </div>
        </div>
    `;
    
    resultDiv.classList.add('show');
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Unified display result function
function displayResult(data, resultDivId, spinnerId) {
    const resultDiv = document.getElementById(resultDivId);
    const spinner = document.getElementById(spinnerId);
    
    if (spinner) spinner.classList.remove('show');
    
    if (!data || data.error) {
        resultDiv.innerHTML = `
            <div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 10px;">
                <h3>⚠️ Error</h3>
                <p>${escapeHtml(data?.error || 'An error occurred during analysis')}</p>
            </div>
        `;
        resultDiv.classList.add('show');
        return;
    }
    
    if (data.type === 'EMAIL' || data.url_analyses) {
        displayEmailResult(data, resultDivId);
    } else if (data.suspicious_messages !== undefined || data.message_count !== undefined) {
        displayWhatsAppResult(data, resultDivId);
    } else {
        displayGeneralResult(data, resultDivId);
    }
}

// Initialize all event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // SMS Form Handler
    const smsForm = document.getElementById('smsForm');
    if (smsForm) {
        smsForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const smsText = document.getElementById('smsText').value;
            if (!smsText.trim()) {
                showToast('Please enter SMS text to analyze', 'warning');
                return;
            }
            
            const spinner = document.getElementById('smsSpinner');
            const analyzeBtn = e.target.querySelector('.btn-analyze');
            
            spinner.classList.add('show');
            analyzeBtn.disabled = true;
            document.getElementById('smsResult').classList.remove('show');
            
            try {
                const formData = new FormData();
                formData.append('sms_text', smsText);
                
                const response = await fetch('/api/detect-sms/', {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': getCSRFToken(),
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'same-origin',
                    body: formData
                });
                
                const data = await response.json();
                displayResult(data, 'smsResult', 'smsSpinner');
                loadStats();
            } catch (error) {
                console.error('Error:', error);
                showToast('Network error. Please check if the server is running.', 'danger');
            } finally {
                spinner.classList.remove('show');
                analyzeBtn.disabled = false;
            }
        });
    }
    
    // Email Form Handler
    const emailForm = document.getElementById('emailForm');
    if (emailForm) {
        emailForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const emailText = document.getElementById('emailText').value;
            if (!emailText.trim()) {
                showToast('Please enter email content to analyze', 'warning');
                return;
            }
            
            const spinner = document.getElementById('emailSpinner');
            const analyzeBtn = e.target.querySelector('.btn-analyze');
            
            spinner.classList.add('show');
            analyzeBtn.disabled = true;
            document.getElementById('emailResult').classList.remove('show');
            
            try {
                const formData = new FormData();
                formData.append('email_text', emailText);
                
                const response = await fetch('/api/detect-email/', {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': getCSRFToken(),
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'same-origin',
                    body: formData
                });
                
                const data = await response.json();
                displayResult(data, 'emailResult', 'emailSpinner');
                loadStats();
                showToast('✅ Email analyzed safely - no links were clicked!', 'success');
            } catch (error) {
                console.error('Error:', error);
                showToast('Network error. Please check if the server is running.', 'danger');
            } finally {
                spinner.classList.remove('show');
                analyzeBtn.disabled = false;
            }
        });
    }
    
    // WhatsApp Form Handler
    const whatsappForm = document.getElementById('whatsappForm');
    if (whatsappForm) {
        whatsappForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const chatText = document.getElementById('whatsappText').value;
            if (!chatText.trim()) {
                showToast('Please paste WhatsApp chat content', 'warning');
                return;
            }
            
            const spinner = document.getElementById('whatsappSpinner');
            const analyzeBtn = e.target.querySelector('.btn-analyze');
            
            spinner.classList.add('show');
            analyzeBtn.disabled = true;
            document.getElementById('whatsappResult').classList.remove('show');
            
            const formData = new FormData();
            formData.append('chat_text', chatText);
            
            try {
                const response = await fetch('/api/detect-whatsapp/', {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': getCSRFToken(),
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    credentials: 'same-origin',
                    body: formData
                });
                
                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Server error: ${response.status}`);
                }
                
                const data = await response.json();
                displayResult(data, 'whatsappResult', 'whatsappSpinner');
                loadStats();
                showToast('✅ Analysis complete!', 'success');
                
            } catch (error) {
                console.error('Error:', error);
                showToast(error.message, 'danger');
                document.getElementById('whatsappResult').innerHTML = `
                    <div class="alert alert-danger">
                        <strong>❌ Error:</strong> ${escapeHtml(error.message)}<br>
                        <small>Please check that you've pasted valid WhatsApp chat content and the server is running.</small>
                    </div>
                `;
                document.getElementById('whatsappResult').classList.add('show');
            } finally {
                spinner.classList.remove('show');
                analyzeBtn.disabled = false;
            }
        });
    }
    
    // URL Checker Handler
    const urlForm = document.getElementById('urlForm');
    if (urlForm) {
        urlForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('urlInput').value.trim();
            if (!url) {
                showToast('Please enter a URL', 'warning');
                return;
            }
            
            const spinner = document.getElementById('urlSpinner');
            const resultDiv = document.getElementById('urlResult');
            
            spinner.classList.add('show');
            resultDiv.classList.remove('show');
            
            try {
                const response = await fetch('/api/check-url/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken() },
                    body: JSON.stringify({ url: url })
                });
                
                const data = await response.json();
                displayResult(data, 'urlResult', 'urlSpinner');
            } catch (error) {
                showToast('Network error: ' + error.message, 'danger');
                spinner.classList.remove('show');
            } finally {
                spinner.classList.remove('show');
            }
        });
    }
    
    // Screenshot OCR Handler
    const dropZone = document.getElementById('dropZone');
    const screenshotInput = document.getElementById('screenshotInput');
    const previewDiv = document.getElementById('screenshotPreview');
    const previewImage = document.getElementById('previewImage');
    const analyzeScreenshotBtn = document.getElementById('analyzeScreenshotBtn');
    let currentImageFile = null;

    if (dropZone) {
        dropZone.addEventListener('click', () => screenshotInput.click());
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#764ba2';
            dropZone.style.backgroundColor = '#f0f0ff';
        });
        
        dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#667eea';
            dropZone.style.backgroundColor = 'transparent';
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#667eea';
            dropZone.style.backgroundColor = 'transparent';
            const file = e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) {
                handleImageFile(file);
            } else {
                showToast('Please upload an image file', 'warning');
            }
        });
    }

    if (screenshotInput) {
        screenshotInput.addEventListener('change', (e) => {
            if (e.target.files[0]) handleImageFile(e.target.files[0]);
        });
    }

    function handleImageFile(file) {
        if (file.size > 5 * 1024 * 1024) {
            showToast('File too large. Maximum 5MB', 'warning');
            return;
        }
        currentImageFile = file;
        const reader = new FileReader();
        reader.onload = (e) => {
            previewImage.src = e.target.result;
            previewDiv.style.display = 'block';
        };
        reader.readAsDataURL(file);
    }

    if (analyzeScreenshotBtn) {
        analyzeScreenshotBtn.addEventListener('click', async () => {
            if (!currentImageFile) return;
            
            const spinner = document.getElementById('screenshotSpinner');
            const resultDiv = document.getElementById('screenshotResult');
            
            spinner.classList.add('show');
            resultDiv.classList.remove('show');
            
            try {
                const worker = await Tesseract.createWorker('eng');
                const { data: { text } } = await worker.recognize(currentImageFile);
                await worker.terminate();
                
                const response = await fetch('/api/detect-screenshot-text/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: text })
                });
                
                const data = await response.json();
                displayResult(data, 'screenshotResult', 'screenshotSpinner');
            } catch (error) {
                resultDiv.innerHTML = `<div class="alert alert-danger">OCR failed: ${error.message}</div>`;
                resultDiv.classList.add('show');
                spinner.classList.remove('show');
            } finally {
                spinner.classList.remove('show');
            }
        });
    }
    
    // Example buttons handler
    document.querySelectorAll('.example-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.getAttribute('data-type');
            const example = btn.getAttribute('data-example');
            if (type && example) {
                loadExample(type, example);
            }
        });
    });
    
    // Tab buttons handler
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.getAttribute('data-tab');
            if (tabName) {
                switchTab(tabName);
            }
        });
    });
    
    // Load stats on page load
    loadStats();
    
    // Auto-refresh stats every 30 seconds
    setInterval(() => {
        if (document.getElementById('statsTab') && document.getElementById('statsTab').classList.contains('active')) {
            loadStats();
        }
    }, 30000);
});