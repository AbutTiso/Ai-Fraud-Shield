// detector/static/detector/js/main.js - COMPLETE VERSION

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
        loadEnhancedStats();
    }
}

// Update all charts with new data
function updateCharts(data) {
    console.log('Updating charts with data:', data);
    
    if (scamTypeChart) {
        scamTypeChart.data.datasets[0].data = [
            data.sms_count || 0,
            data.email_count || 0,
            data.whatsapp_count || 0,
            data.screenshot_count || 0,
            data.url_count || 0
        ];
        scamTypeChart.update();
    }
    
    if (riskDistributionChart && data.risk_distribution) {
        riskDistributionChart.data.datasets[0].data = [
            data.risk_distribution.high || 0,
            data.risk_distribution.medium || 0,
            data.risk_distribution.low || 0
        ];
        riskDistributionChart.update();
    }
    
    if (trendChart && data.weekly_trend) {
        trendChart.data.datasets[0].data = data.weekly_trend;
        trendChart.update();
    }
}

// Load examples
function loadExample(type, exampleType) {
    const examples = {
        sms: {
            scam: 'URGENT: Your M-Pesa account has been suspended due to suspicious activity. Click http://mpesa-update.co.ke to verify your details immediately or your account will be deactivated.',
            prize: 'CONGRATULATIONS! You have won Ksh 250,000 in our Safaricom promotion. Click https://bit.ly/claim-prize to claim your prize now!',
            safe: 'Safaricom: Your M-Pesa transaction of Ksh 500 to John Mwangi was successful. New balance: Ksh 2,450. Thank you for using M-Pesa.'
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

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============ DISPLAY FUNCTIONS ============

// Enhanced Email Result Display (Shows links as NON-clickable text)
function displayEmailResult(data, resultDivId) {
    const resultDiv = document.getElementById(resultDivId);
    
    let headerClass = 'success';
    if (data.color === 'danger' || data.score >= 60) headerClass = 'danger';
    else if (data.color === 'warning' || data.score >= 30) headerClass = 'warning';
    
    // Build warnings HTML
    let warningsHtml = '';
    const warningsList = data.warnings || data.reasons || [];
    if (warningsList.length > 0) {
        warningsHtml = '<h6 class="mt-3">🚨 Issues Detected:</h6>';
        warningsList.slice(0, 8).forEach(warning => {
            warningsHtml += `<div class="reason-item" style="border-left-color: ${headerClass === 'danger' ? '#dc3545' : (headerClass === 'warning' ? '#ffc107' : '#28a745')};">${escapeHtml(warning)}</div>`;
        });
    }
    
    // Build URL analysis HTML (NON-CLICKABLE)
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
    
    // Build recommendations
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

// ============ CHART FUNCTIONS ============

// Chart instances
let scamTypeChart = null;
let riskDistributionChart = null;
let trendChart = null;

// Get last 7 days labels
function getLast7Days() {
    const days = [];
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        days.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    return days;
}

// Initialize charts
function initCharts() {
    console.log('Initializing charts...');
    
    // Scam Type Pie Chart
    const typeCanvas = document.getElementById('scamTypeChart');
    if (typeCanvas) {
        const typeCtx = typeCanvas.getContext('2d');
        if (scamTypeChart) {
            scamTypeChart.destroy();
        }
        scamTypeChart = new Chart(typeCtx, {
            type: 'doughnut',
            data: {
                labels: ['SMS', 'Email', 'WhatsApp', 'Screenshot', 'URL','Phone','Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0, 0],
                    backgroundColor: ['#17a2b8', '#fd7e14', '#20c997', '#6f42c1', '#6610f2', '#6c757d', '#dee2e6'],
                    borderWidth: 0,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { position: 'bottom', labels: { font: { size: 11 } } },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
        console.log('Scam type chart initialized');
    }

    // Risk Distribution Bar Chart
    const riskCanvas = document.getElementById('riskDistributionChart');
    if (riskCanvas) {
        const riskCtx = riskCanvas.getContext('2d');
        if (riskDistributionChart) {
            riskDistributionChart.destroy();
        }
        riskDistributionChart = new Chart(riskCtx, {
            type: 'bar',
            data: {
                labels: ['High Risk (70-100)', 'Medium Risk (40-69)', 'Low Risk (0-39)'],
                datasets: [{
                    label: 'Number of Reports',
                    data: [0, 0, 0],
                    backgroundColor: ['#dc3545', '#ffc107', '#28a745'],
                    borderRadius: 8,
                    barPercentage: 0.6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { position: 'top' } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#e9ecef' }, title: { display: true, text: 'Number of Reports' } },
                    x: { grid: { display: false }, title: { display: true, text: 'Risk Level' } }
                }
            }
        });
        console.log('Risk distribution chart initialized');
    }

    // Trend Line Chart
    const trendCanvas = document.getElementById('trendChart');
    if (trendCanvas) {
        const trendCtx = trendCanvas.getContext('2d');
        if (trendChart) {
            trendChart.destroy();
        }
        trendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: getLast7Days(),
                datasets: [{
                    label: 'Scams Detected',
                    data: [0, 0, 0, 0, 0, 0, 0],
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#2563eb',
                    pointBorderColor: 'white',
                    pointBorderWidth: 2,
                    pointRadius: 5,
                    pointHoverRadius: 7
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: { legend: { position: 'top' } },
                scales: {
                    y: { beginAtZero: true, grid: { color: '#e9ecef' }, title: { display: true, text: 'Number of Scams' } },
                    x: { grid: { display: false }, title: { display: true, text: 'Date' } }
                }
            }
        });
        console.log('Trend chart initialized');
    }
}

// Update enhanced statistics with charts
async function loadEnhancedStats() {
    console.log('Loading enhanced stats...');
    try {
        const response = await fetch('/api/stats/', {
            headers: { 
                'X-CSRFToken': getCSRFToken(),
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin'
        });
        const data = await response.json();
        console.log('Stats data received:', data);
        
        if (data.status === 'success') {
            // Update summary cards
            const statTotal = document.getElementById('statTotalReports');
            const statHigh = document.getElementById('statHighRisk');
            const statAvg = document.getElementById('statAvgScore');
            
            if (statTotal) statTotal.innerHTML = (data.total_reports || 0).toLocaleString();
            if (statHigh) statHigh.innerHTML = (data.high_risk_count || 0).toLocaleString();
            if (statAvg) statAvg.innerHTML = (data.average_risk_score || 0) + '%';
            
            // Update main stats bar
            const totalReports = document.getElementById('totalReports');
            const highRisk = document.getElementById('highRisk');
            const smsCount = document.getElementById('smsCount');
            const emailCount = document.getElementById('emailCount');
            const whatsappCount = document.getElementById('whatsappCount');
            const avgRiskScore = document.getElementById('avgRiskScore');
            const callCount = document.getElementById('callCount');
            
            if (totalReports) totalReports.innerHTML = data.total_reports || 0;
            if (highRisk) highRisk.innerHTML = data.high_risk_count || 0;
            if (smsCount) smsCount.innerHTML = data.sms_count || 0;
            if (emailCount) emailCount.innerHTML = data.email_count || 0;
            if (whatsappCount) whatsappCount.innerHTML = data.whatsapp_count || 0;
            if (avgRiskScore) avgRiskScore.innerHTML = data.average_risk_score || 0;
            if (callCount) callCount.innerHTML = data.call_count || 0;
            
            // Update pie chart
            if (scamTypeChart) {
                scamTypeChart.data.datasets[0].data = [
                    data.sms_count || 0,
                    data.email_count || 0,
                    data.whatsapp_count || 0,
                    data.screenshot_count || 0,
                    data.url_count || 0
                ];
                scamTypeChart.update();
                console.log('Pie chart updated:', scamTypeChart.data.datasets[0].data);
            }
            
            // Update risk distribution
            if (riskDistributionChart && data.risk_distribution) {
                riskDistributionChart.data.datasets[0].data = [
                    data.risk_distribution.high || 0,
                    data.risk_distribution.medium || 0,
                    data.risk_distribution.low || 0
                ];
                riskDistributionChart.update();
                console.log('Risk chart updated:', riskDistributionChart.data.datasets[0].data);
            }
            
            // Update trend chart
            if (trendChart && data.weekly_trend) {
                trendChart.data.datasets[0].data = data.weekly_trend;
                trendChart.update();
                console.log('Trend chart updated:', data.weekly_trend);
            }
            
            // Update recent scams table
            updateRecentScamsTable(data.recent_scams || []);
        } else {
            console.error('Stats API error:', data.message);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Update recent scams table
function updateRecentScamsTable(scams) {
    const tbody = document.getElementById('recentScamsBody');
    if (!tbody) return;
    
    if (scams.length === 0) {
        tbody.innerHTML = '<td><td colspan="5" class="text-center">No scam reports yet. Start detecting!</td></tr>';
        return;
    }
    
    tbody.innerHTML = scams.map(scam => `
        <tr>
            <td><small>${scam.date}</small></td>
            <td><span class="badge ${getBadgeClass(scam.type)}">${scam.type}</span></td>
            <td><small>${escapeHtml(scam.content.substring(0, 80))}${scam.content.length > 80 ? '...' : ''}</small></td>
            <td><span class="badge ${getRiskBadgeClass(scam.score)}">${scam.score}/100</span></td>
            <td><span class="badge ${getLevelBadgeClass(scam.level)}">${scam.level}</span></td>
        </tr>
    `).join('');
}

function getBadgeClass(type) {
    const classes = { 
        'SMS': 'bg-info', 
        'EMAIL': 'bg-warning', 
        'WHATSAPP': 'bg-success', 
        'SCREENSHOT': 'bg-purple', 
        'URL': 'bg-secondary',
        'CALL': 'bg-danger'
    };
    return classes[type] || 'bg-secondary';
}

function getRiskBadgeClass(score) {
    if (score >= 70) return 'bg-danger';
    if (score >= 40) return 'bg-warning';
    return 'bg-success';
}

function getLevelBadgeClass(level) {
    if (level && level.includes('HIGH')) return 'bg-danger';
    if (level && level.includes('MEDIUM')) return 'bg-warning';
    return 'bg-success';
}

// Refresh all stats
async function refreshStats() {
    showToast('Refreshing statistics...', 'info');
    await loadEnhancedStats();
    showToast('Statistics updated!', 'success');
}

// ============ REAL-TIME CALL DETECTION ============

// ============ ENHANCED REAL-TIME VOICE TRANSCRIPTION ============

let mediaRecorder = null;
let audioChunks = [];
let isMonitoring = false;
let analysisInterval = null;
let consecutiveScamPhrases = 0;
let liveTranscript = [];
let currentTranscriptText = '';
let currentScamScore = 0;
let speechRecognition = null;
let speechRecognitionActive = false;
let lastSavedTranscript = '';
let fullCallTranscript = ''; // Store entire call history
let interimTextBuffer = '';
let lastProcessedTime = 0;
let callStartTime = null;
let audioContext = null;
let sourceNode = null;
let processorNode = null;

// Real-time scam phrases (expanded)
const highRiskPhrases = [
    // English
    'mpin', 'pin number', 'send money', 'transfer', 'verify account',
    'account suspended', 'account blocked', 'urgent', 'immediately',
    'otp', 'verification code', 'password', 'bank details',
    'mpesa pin', 'credit card', 'debit card', 'processing fee',
    'wire transfer', 'western union', 'money gram', 'secret code',
    'one time password', 'transaction code', 'authorization code',
    
    // Money related
    'send ksh', 'send money now', 'pay immediately', 'deposit money',
    'withdraw funds', 'transfer funds', 'mobile money', 'cash out',
    
    // Threat related
    'legal action', 'police case', 'court case', 'arrest warrant',
    'account closure', 'permanent ban', 'legal proceedings',
    
    // Urgency
    'right now', 'this instant', 'without delay', 'act now',
    'don\'t wait', 'expiring soon', 'last warning'
];

const mediumRiskPhrases = [
    // English
    'congratulations', 'you won', 'prize', 'reward', 'free gift',
    'limited time', 'special offer', 'exclusive', 'urgent action',
    'click here', 'verify now', 'update your account', 'claim your prize',
    
    // Investment related
    'double your money', 'guaranteed returns', 'risk free', 'high profit',
    'crypto investment', 'forex trading', 'stock market', 'passive income',
    
    // Employment
    'work from home', 'easy money', 'get rich quick', 'make money online',
    'freelance opportunity', 'remote job', 'hiring now'
];

const highRiskSwahili = [
    // Critical Swahili
    'tuma pesa', 'namba ya siri', 'siri yako', 'fungua akaunti',
    'kufungiwa', 'hatari', 'haraka sana', 'sasa hivi', 'lipa',
    'nambari ya siri', 'akaunti yako', 'pesa yako', 'salio yako',
    
    // Additional Swahili scams
    'pesa taslimu', 'hamisha pesa', 'kadi ya mkopo', 'mkopo wa haraka',
    'bonyeza hapa', 'thibitisha akaunti', 'salio la mpaka',
    'maliza deni', 'funga akaunti', 'hatua za kisheria'
];

// Save transcribed call to database
async function saveVoiceCallToDatabase(transcript, score, fullTranscript = null) {
    if (!transcript || transcript.length < 10) return;
    if (lastSavedTranscript === transcript && !fullTranscript) return;
    
    try {
        const dataToSend = fullTranscript || transcript;
        const formData = new FormData();
        formData.append('transcript', dataToSend);
        
        const response = await fetch('/api/detect-call/', {
            method: 'POST',
            headers: { 'X-CSRFToken': getCSRFToken() },
            credentials: 'same-origin',
            body: formData
        });
        
        if (response.ok) {
            if (fullTranscript) {
                lastSavedTranscript = fullTranscript;
                console.log('✅ Full call transcript saved to database - Score:', score);
            } else {
                lastSavedTranscript = transcript;
                console.log('✅ Voice segment saved to database - Score:', score);
            }
            await loadEnhancedStats();
        }
    } catch (error) {
        console.error('Error saving voice call:', error);
    }
}

// Create enhanced live transcript display
// Create live transcript display - SIMPLIFIED WORKING VERSION
// Create live transcript display - FIXED FOR YOUR HTML STRUCTURE
function createLiveTranscriptDisplay() {
    // Find the container directly by ID (your HTML has liveTranscriptContainer)
    const container = document.getElementById('liveTranscriptContainer');
    
    if (!container) {
        console.error('liveTranscriptContainer not found');
        return;
    }
    
    // Check if panel already exists
    if (document.getElementById('liveTranscriptPanel')) {
        console.log('Panel already exists');
        return;
    }
    
    const transcriptPanel = document.createElement('div');
    transcriptPanel.id = 'liveTranscriptPanel';
    transcriptPanel.className = 'mt-3 p-2';
    transcriptPanel.style.background = 'rgba(0,0,0,0.2)';
    transcriptPanel.style.borderRadius = '12px';
    transcriptPanel.style.border = '1px solid rgba(255,255,255,0.1)';
    transcriptPanel.innerHTML = `
        <div class="d-flex justify-content-between align-items-center mb-2">
            <strong><i class="fas fa-comment-dots"></i> Live Call Transcript</strong>
            <small class="text-muted" id="transcriptTimer">00:00</small>
        </div>
        <div id="interimTranscript" class="text-muted small mb-2" style="font-style: italic; background: rgba(0,0,0,0.15); padding: 8px; border-radius: 6px; min-height: 40px;">
            <span class="text-muted">🎤 Speak into your microphone...</span>
        </div>
        <div id="liveTranscript" style="max-height: 200px; overflow-y: auto; text-align: left; font-size: 0.85rem; background: rgba(0,0,0,0.15); border-radius: 6px; padding: 8px;">
            <div class="text-muted">Waiting for speech...</div>
        </div>
        <div class="mt-2">
            <div class="row">
                <div class="col-8">
                    <div class="progress" style="height: 8px;">
                        <div id="scamMeterBar" class="progress-bar bg-success" style="width: 0%;"></div>
                    </div>
                </div>
                <div class="col-4 text-end">
                    <small id="scamMeterText" class="text-muted">✓ Safe</small>
                </div>
            </div>
        </div>
        <div id="realtimeAlerts" class="mt-2" style="max-height: 100px; overflow-y: auto; font-size: 0.75rem;"></div>
    `;
    
    container.appendChild(transcriptPanel);
    console.log('✅ Transcript panel created successfully in container');
}
// Update timer display
function updateCallTimer() {
    const timerEl = document.getElementById('transcriptTimer');
    if (timerEl && callStartTime) {
        const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        timerEl.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
}

// Update live transcript display with formatting
function updateLiveTranscriptDisplay(text, isFinal = true) {
    const transcriptDiv = document.getElementById('liveTranscript');
    if (!transcriptDiv) return;
    
    const timestamp = new Date().toLocaleTimeString();
    
    if (isFinal) {
        const transcriptEntry = document.createElement('div');
        transcriptEntry.className = 'transcript-entry';
        transcriptEntry.style.cssText = 'padding: 4px 8px; margin: 2px 0; border-radius: 6px; font-size: 0.8rem; border-left: 3px solid #667eea;';
        transcriptEntry.innerHTML = `<small class="text-muted">[${timestamp}]</small> <strong>Caller:</strong> "${escapeHtml(text)}"`;
        transcriptDiv.appendChild(transcriptEntry);
        transcriptDiv.scrollTop = transcriptDiv.scrollHeight;
        
        // Keep only last 30 messages
        while (transcriptDiv.children.length > 30) {
            transcriptDiv.removeChild(transcriptDiv.firstChild);
        }
    } else {
        // Update interim display
        const interimDiv = document.getElementById('interimTranscript');
        if (interimDiv) {
            interimDiv.innerHTML = `<em class="text-muted">🎙️ ${escapeHtml(text)}</em>`;
        }
    }
}

// Enhanced scam meter with color coding
function updateScamMeter(score) {
    currentScamScore = Math.min(100, Math.max(0, score));
    const meterBar = document.getElementById('scamMeterBar');
    const meterText = document.getElementById('scamMeterText');
    
    if (meterBar) {
        meterBar.style.width = currentScamScore + '%';
        meterBar.style.transition = 'width 0.3s ease';
        
        if (currentScamScore >= 70) {
            meterBar.style.backgroundColor = '#dc3545';
            if (meterText) {
                meterText.innerHTML = '🔴 CRITICAL RISK';
                meterText.style.color = '#dc3545';
            }
        } else if (currentScamScore >= 50) {
            meterBar.style.backgroundColor = '#fd7e14';
            if (meterText) {
                meterText.innerHTML = '🟠 HIGH RISK';
                meterText.style.color = '#fd7e14';
            }
        } else if (currentScamScore >= 25) {
            meterBar.style.backgroundColor = '#ffc107';
            if (meterText) {
                meterText.innerHTML = '🟡 MEDIUM RISK';
                meterText.style.color = '#ffc107';
            }
        } else {
            meterBar.style.backgroundColor = '#28a745';
            if (meterText) {
                meterText.innerHTML = '🟢 LOW RISK';
                meterText.style.color = '#28a745';
            }
        }
    }
}

// Play alert sound
function playAlertBeep() {
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioCtx.createOscillator();
        const gainNode = audioCtx.createGain();
        oscillator.connect(gainNode);
        gainNode.connect(audioCtx.destination);
        oscillator.frequency.value = 880;
        gainNode.gain.value = 0.3;
        oscillator.start();
        gainNode.gain.exponentialRampToValueAtTime(0.00001, audioCtx.currentTime + 0.5);
        oscillator.stop(audioCtx.currentTime + 0.5);
    } catch(e) {
        if (navigator.vibrate) navigator.vibrate([300, 100, 300]);
    }
}

// Add real-time alert
function addRealtimeAlert(type, message) {
    const alertsDiv = document.getElementById('realtimeAlerts');
    if (!alertsDiv) return;
    
    const timestamp = new Date().toLocaleTimeString();
    const bgColor = type === 'danger' ? '#dc3545' : (type === 'warning' ? '#ffc107' : '#17a2b8');
    const textColor = type === 'warning' ? '#333' : 'white';
    
    const alertDiv = document.createElement('div');
    alertDiv.style.cssText = `background: ${bgColor}; color: ${textColor}; padding: 6px 10px; margin: 3px 0; border-radius: 6px; font-size: 0.75rem; animation: fadeIn 0.3s ease;`;
    alertDiv.innerHTML = `<strong>[${timestamp}]</strong> ${message}`;
    
    alertsDiv.prepend(alertDiv);
    
    while (alertsDiv.children.length > 15) {
        alertsDiv.removeChild(alertsDiv.lastChild);
    }
    
    if (type === 'danger') {
        const dangerAlert = document.getElementById('dangerAlert');
        if (dangerAlert) {
            dangerAlert.style.display = 'block';
            dangerAlert.style.animation = 'flash 0.5s ease-in-out 3';
            setTimeout(() => {
                if (dangerAlert) dangerAlert.style.display = 'none';
            }, 3000);
        }
    }
}

// Show full screen scam alert
function showFullScreenAlert() {
    let modal = document.getElementById('scamAlertModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'scamAlertModal';
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content" style="background: linear-gradient(135deg, #dc3545, #b91c1c); color: white;">
                    <div class="modal-header border-0">
                        <h5 class="modal-title"><i class="fas fa-exclamation-triangle"></i> SCAM ALERT!</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body text-center">
                        <div style="font-size: 3rem;">🚨</div>
                        <h4>Multiple Scam Indicators Detected!</h4>
                        <p>This call contains scam patterns. HANG UP immediately!</p>
                        <hr>
                        <div id="alertDetails" style="font-size: 0.85rem; text-align: left;"></div>
                    </div>
                    <div class="modal-footer border-0 justify-content-center">
                        <button type="button" class="btn btn-light" data-bs-dismiss="modal">I Understand</button>
                        <button type="button" class="btn btn-outline-light" onclick="stopCallMonitoring()">End Call & Report</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    new bootstrap.Modal(modal).show();
}

// Enhanced voice text analysis with context
let wordHistory = [];
let detectedPatterns = [];

async function analyzeVoiceText(text) {
    const textLower = text.toLowerCase();
    let highestRisk = 0;
    let alertType = null;
    let alertMessages = [];
    let scamScore = 0;
    
    // Track word history for context
    const words = textLower.split(/\s+/);
    wordHistory.push(...words);
    if (wordHistory.length > 50) wordHistory = wordHistory.slice(-50);
    
    // Check all risk phrases
    for (const phrase of highRiskPhrases) {
        if (textLower.includes(phrase.toLowerCase())) {
            highestRisk = Math.max(highestRisk, 75);
            alertMessages.push(`🔴 "${phrase}"`);
            scamScore = Math.max(scamScore, 75);
            alertType = 'danger';
        }
    }
    
    for (const phrase of highRiskSwahili) {
        if (textLower.includes(phrase.toLowerCase())) {
            highestRisk = Math.max(highestRisk, 75);
            alertMessages.push(`🔴 "${phrase}" (Swahili)`);
            scamScore = Math.max(scamScore, 75);
            alertType = 'danger';
        }
    }
    
    for (const phrase of mediumRiskPhrases) {
        if (textLower.includes(phrase.toLowerCase())) {
            highestRisk = Math.max(highestRisk, 50);
            alertMessages.push(`🟡 "${phrase}"`);
            scamScore = Math.max(scamScore, 50);
            if (!alertType) alertType = 'warning';
        }
    }
    
    // Detect patterns in context
    if (textLower.includes('urgent') && (textLower.includes('send') || textLower.includes('pay'))) {
        highestRisk = Math.max(highestRisk, 65);
        alertMessages.push(`⏰ Urgency + money request combo`);
        scamScore = Math.max(scamScore, 65);
        alertType = 'danger';
    }
    
    if ((textLower.includes('pin') || textLower.includes('password')) && 
        (textLower.includes('send') || textLower.includes('share') || textLower.includes('tell'))) {
        highestRisk = Math.max(highestRisk, 85);
        alertMessages.push(`🔐 PIN/Password request detected!`);
        scamScore = Math.max(scamScore, 85);
        alertType = 'danger';
    }
    
    // Check for consecutive scam phrases
    if (alertMessages.length > 0) {
        consecutiveScamPhrases++;
        updateScamMeter(currentScamScore + 15 * alertMessages.length);
        playAlertBeep();
        if (navigator.vibrate) navigator.vibrate([200, 100, 200]);
        
        // Show individual alerts
        for (const msg of alertMessages.slice(0, 3)) {
            addRealtimeAlert(alertType, msg);
        }
        
        // Critical: multiple detections
        if (consecutiveScamPhrases >= 3 || scamScore >= 80) {
            const fullAlert = '🔴🔴 MULTIPLE SCAM INDICATORS - DEFINITE SCAM CALL! HANG UP NOW!';
            addRealtimeAlert('danger', fullAlert);
            showFullScreenAlert();
            updateScamMeter(95);
            showToast(fullAlert, 'danger');
            await saveVoiceCallToDatabase(fullCallTranscript || text, 95);
        } else if (scamScore >= 60) {
            showToast(`${alertMessages[0]}`, 'danger');
            await saveVoiceCallToDatabase(text, scamScore);
        }
    } else {
        consecutiveScamPhrases = Math.max(0, consecutiveScamPhrases - 0.3);
        updateScamMeter(currentScamScore * 0.95);
    }
}

// Initialize speech recognition with best settings
// Initialize speech recognition - FIXED (no infinite loop)
function initSpeechRecognition() {
    if (!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)) {
        addRealtimeAlert('warning', 'Speech recognition not supported. Please use Chrome or Edge.');
        return false;
    }
    
    const SpeechRecognitionAPI = window.webkitSpeechRecognition || window.SpeechRecognition;
    speechRecognition = new SpeechRecognitionAPI();
    
    speechRecognition.continuous = true;
    speechRecognition.interimResults = true;
    speechRecognition.lang = 'en-US';
    speechRecognition.maxAlternatives = 1;
    
    speechRecognition.onstart = () => {
        console.log('Speech recognition started successfully');
        addRealtimeAlert('success', '🎤 Voice recognition active - Speak now');
        
        const interimDiv = document.getElementById('interimTranscript');
        if (interimDiv) {
            interimDiv.innerHTML = '<span class="text-success">🎤 Listening... Speak now</span>';
        }
    };
    
    speechRecognition.onresult = (event) => {
        let finalTranscript = '';
        let interimTranscript = '';
        
        for (let i = event.resultIndex; i < event.results.length; i++) {
            const result = event.results[i];
            const transcript = result[0].transcript;
            
            if (result.isFinal) {
                finalTranscript += transcript + ' ';
            } else {
                interimTranscript += transcript;
            }
        }
        
        if (interimTranscript) {
            const interimDiv = document.getElementById('interimTranscript');
            if (interimDiv) {
                interimDiv.innerHTML = `<i class="fas fa-microphone-alt"></i> <em>${escapeHtml(interimTranscript)}</em>`;
            }
        }
        
        if (finalTranscript) {
            console.log('Final transcript:', finalTranscript);
            fullCallTranscript += finalTranscript + '\n';
            updateLiveTranscriptDisplay(finalTranscript, true);
            analyzeVoiceText(finalTranscript);
        }
    };
    
    speechRecognition.onerror = (event) => {
        console.error('Speech recognition error:', event.error);
        if (event.error === 'not-allowed') {
            addRealtimeAlert('danger', 'Microphone access denied. Please allow microphone permissions.');
            // Stop monitoring if microphone denied
            stopCallMonitoring();
        } else if (event.error === 'no-speech') {
            // This is normal - just means no speech detected, don't restart
            console.log('No speech detected');
        }
    };
    
    speechRecognition.onend = () => {
        console.log('Speech recognition ended');
        // Only restart if we're actively monitoring AND recognition is still active
        if (isMonitoring && speechRecognitionActive) {
            // Wait 1 second before restarting to avoid rapid loops
            setTimeout(() => {
                if (isMonitoring && speechRecognitionActive && speechRecognition) {
                    try {
                        speechRecognition.start();
                        console.log('Speech recognition restarted');
                    } catch (e) {
                        console.log('Restart error:', e);
                        speechRecognitionActive = false;
                    }
                }
            }, 1000);
        }
    };
    
    return true;
}

// Show interim transcription
function showInterimTranscript(text) {
    const interimDiv = document.getElementById('interimTranscript');
    if (interimDiv) {
        interimDiv.innerHTML = `<i class="fas fa-microphone-alt"></i> <em>${escapeHtml(text)}</em>`;
        // Auto-clear after 1 second of no speech
        clearTimeout(window.interimTimeout);
        window.interimTimeout = setTimeout(() => {
            if (interimDiv) interimDiv.innerHTML = '';
        }, 1500);
    }
}

// Start real-time call monitoring
// Start real-time call monitoring - FIXED
async function startCallMonitoring() {
    console.log('Start monitoring clicked');
    
    try {
        // Reset state
        fullCallTranscript = '';
        consecutiveScamPhrases = 0;
        currentScamScore = 0;
        wordHistory = [];
        detectedPatterns = [];
        callStartTime = Date.now();
        
        createLiveTranscriptDisplay();
        
        // Start timer
        if (window.timerInterval) clearInterval(window.timerInterval);
        window.timerInterval = setInterval(updateCallTimer, 1000);
        
        // Request microphone
        const stream = await navigator.mediaDevices.getUserMedia({ 
            audio: {
                echoCancellation: true,
                noiseSuppression: true,
                autoGainControl: true
            } 
        });
        console.log('Microphone access granted');
        
        // Update UI
        const startBtn = document.getElementById('startCallMonitorBtn');
        const stopBtn = document.getElementById('stopCallMonitorBtn');
        const monitorStatus = document.getElementById('monitorStatus');
        
        if (startBtn) startBtn.disabled = true;
        if (stopBtn) stopBtn.disabled = false;
        if (monitorStatus) {
            monitorStatus.innerHTML = '<span class="badge bg-success animate-pulse">🎙️ LIVE - Voice Recognition Active</span>';
        }
        
        // Initialize speech recognition
        const speechSupported = initSpeechRecognition();
        
        if (speechSupported && speechRecognition) {
            // Set active flag BEFORE starting
            speechRecognitionActive = true;
            isMonitoring = true;
            
            // Add a small delay before starting
            setTimeout(() => {
                if (speechRecognition && speechRecognitionActive) {
                    try {
                        speechRecognition.start();
                        addRealtimeAlert('success', '🎤 Call monitoring active! Speak clearly.');
                        showToast('Call monitoring active - Speak now!', 'success');
                    } catch (e) {
                        console.error('Start error:', e);
                        addRealtimeAlert('danger', 'Failed to start speech recognition. Please try again.');
                        speechRecognitionActive = false;
                        isMonitoring = false;
                    }
                }
            }, 500);
        } else {
            addRealtimeAlert('warning', 'Speech recognition not supported. Using audio recording mode.');
        }
        
    } catch (error) {
        console.error('Microphone error:', error);
        showToast('Could not access microphone. Please check permissions.', 'danger');
        addRealtimeAlert('danger', 'Microphone access failed. Please allow microphone permissions.');
        
        // Reset UI
        const startBtn = document.getElementById('startCallMonitorBtn');
        if (startBtn) startBtn.disabled = false;
    }
}

// Stop call monitoring and save full transcript
function stopCallMonitoring() {
    isMonitoring = false;
    speechRecognitionActive = false;
    
    // Stop timer
    if (window.timerInterval) {
        clearInterval(window.timerInterval);
        window.timerInterval = null;
    }
    
    // Save full call transcript
    if (fullCallTranscript && fullCallTranscript.length > 50) {
        saveVoiceCallToDatabase(fullCallTranscript, currentScamScore, fullCallTranscript);
        addRealtimeAlert('info', `Call ended. Transcript saved (${Math.round(fullCallTranscript.length / 10)} words)`);
    }
    
    // Stop speech recognition
    if (speechRecognition) {
        try {
            speechRecognition.stop();
        } catch(e) {}
        speechRecognition = null;
    }
    
    // Stop media recorder
    if (mediaRecorder && mediaRecorder.state === 'recording') {
        mediaRecorder.stop();
        if (mediaRecorder.stream) {
            mediaRecorder.stream.getTracks().forEach(track => track.stop());
        }
        mediaRecorder = null;
    }
    
    // Reset variables
    audioChunks = [];
    consecutiveScamPhrases = 0;
    currentScamScore = 0;
    callStartTime = null;
    
    // Update UI
    const startBtn = document.getElementById('startCallMonitorBtn');
    const stopBtn = document.getElementById('stopCallMonitorBtn');
    const monitorStatus = document.getElementById('monitorStatus');
    
    if (startBtn) startBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = true;
    if (monitorStatus) monitorStatus.innerHTML = '<span class="badge bg-secondary">⚪ Not monitoring</span>';
    
    updateScamMeter(0);
    addRealtimeAlert('info', 'Call monitoring stopped. Transcript saved for analysis.');
    showToast('Call monitoring stopped.', 'info');
}

// Initialize call monitoring buttons
function initRealtimeCallDetection() {
    const startBtn = document.getElementById('startCallMonitorBtn');
    const stopBtn = document.getElementById('stopCallMonitorBtn');
    
    if (startBtn) {
        startBtn.addEventListener('click', startCallMonitoring);
    }
    if (stopBtn) {
        stopBtn.addEventListener('click', stopCallMonitoring);
    }
}

// ============ MANUAL CALL TRANSCRIPT ANALYSIS (SAVES TO DB) ============

const analyzeCallBtn = document.getElementById('analyzeCallBtn');
if (analyzeCallBtn) {
    analyzeCallBtn.addEventListener('click', async () => {
        const transcript = document.getElementById('callTranscript').value;
        
        if (!transcript.trim()) {
            showToast('Please enter call transcript', 'warning');
            return;
        }
        
        const spinner = document.getElementById('callSpinner');
        const resultDiv = document.getElementById('callResult');
        
        if (spinner) spinner.style.display = 'flex';
        resultDiv.classList.remove('show');
        
        try {
            const formData = new FormData();
            formData.append('transcript', transcript);
            
            const response = await fetch('/api/detect-call/', {
                method: 'POST',
                headers: { 'X-CSRFToken': getCSRFToken() },
                credentials: 'same-origin',
                body: formData
            });
            
            const data = await response.json();
            displayCallResult(data, 'callResult');
            await loadEnhancedStats();
            
            if (data.score >= 50) {
                showToast('🚨 SCAM CALL DETECTED! HANG UP NOW!', 'danger');
            } else {
                showToast('Call analysis complete', 'success');
            }
        } catch (error) {
            console.error('Error:', error);
            resultDiv.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
            resultDiv.classList.add('show');
            showToast('Network error. Please try again.', 'danger');
        } finally {
            if (spinner) spinner.style.display = 'none';
        }
    });
}

// ============ PHONE NUMBER CHECK ============

const checkNumberBtn = document.getElementById('checkNumberBtn');
if (checkNumberBtn) {
    checkNumberBtn.addEventListener('click', async () => {
        const phoneNumber = document.getElementById('callerNumber').value;
        if (!phoneNumber.trim()) {
            showToast('Please enter a phone number', 'warning');
            return;
        }
        
        const resultDiv = document.getElementById('numberCheckResult');
        resultDiv.innerHTML = '<div class="spinner-border text-primary spinner-border-sm"></div> Checking...';
        
        try {
            const response = await fetch('/api/check-phone/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken() },
                body: JSON.stringify({ phone_number: phoneNumber })
            });
            const data = await response.json();
            const riskColor = data.color === 'danger' ? '#dc3545' : (data.color === 'warning' ? '#ffc107' : '#28a745');
            resultDiv.innerHTML = `<div class="card mt-2" style="border-left: 4px solid ${riskColor};"><div class="card-body p-3">
                <div><strong>📞 Number:</strong> ${escapeHtml(data.phone || phoneNumber)}</div>
                <div><strong>📊 Risk Level:</strong> <span class="badge bg-${data.color}">${escapeHtml(data.risk_level || 'UNKNOWN')}</span></div>
                <div><strong>💬 Message:</strong> ${escapeHtml(data.message || '')}</div>
                ${data.risk_factors ? `<div><strong>⚠️ Risk Factors:</strong> ${escapeHtml(data.risk_factors.join(', '))}</div>` : ''}
                <div class="mt-2"><small>${escapeHtml(data.recommendation || 'Be cautious with unknown numbers')}</small></div>
            </div></div>`;
        } catch (error) {
            resultDiv.innerHTML = `<div class="alert alert-danger mt-2">Error: ${error.message}</div>`;
        }
    });
}

// Display Call Result
function displayCallResult(data, resultDivId) {
    const resultDiv = document.getElementById(resultDivId);
    if (!resultDiv) return;
    
    const headerClass = data.color === 'danger' ? 'danger' : (data.color === 'warning' ? 'warning' : 'success');
    let warningsHtml = '';
    if (data.warnings && data.warnings.length > 0) {
        warningsHtml = '<h6 class="mt-3">🚨 Red Flags Detected:</h6>';
        data.warnings.forEach(w => { 
            warningsHtml += `<div class="reason-item" style="border-left-color: ${data.color === 'danger' ? '#dc3545' : (data.color === 'warning' ? '#ffc107' : '#28a745')};">${escapeHtml(w)}</div>`; 
        });
    }
    
    let recommendationsHtml = '';
    if (data.recommendations && data.recommendations.length > 0) {
        recommendationsHtml = '<h6 class="mt-3">💡 What To Do:</h6><div style="background: #f8f9fa; padding: 12px; border-radius: 8px;">';
        data.recommendations.forEach(rec => {
            recommendationsHtml += `<div>✓ ${escapeHtml(rec)}</div>`;
        });
        recommendationsHtml += '</div>';
    }
    
    resultDiv.innerHTML = `
        <div class="result-header ${headerClass}">
            <h3>${data.emoji} ${data.risk_level}</h3>
            <div class="score-circle"><div class="score-value">${data.score}%</div><div class="score-label">Risk Score</div></div>
        </div>
        <div class="result-body">
            <p class="fw-bold">${escapeHtml(data.message)}</p>
            <div class="risk-score">Score: <span style="color: ${data.color === 'danger' ? '#dc3545' : (data.color === 'warning' ? '#ffc107' : '#28a745')};">${data.score}</span> / 100</div>
            <div class="progress risk-progress"><div class="progress-bar bg-${headerClass}" style="width: ${data.score}%;"></div></div>
            ${warningsHtml}
            ${recommendationsHtml}
            ${data.number_analysis ? `<hr><div class="alert alert-secondary"><strong>📞 Caller Number Analysis:</strong><br>Score: ${data.number_analysis.score || 0}%<br>${data.number_analysis.message || ''}</div>` : ''}
            <div class="alert alert-danger mt-3" style="background: #f8d7da; border-left: 4px solid #dc3545;">
                <strong><i class="fas fa-exclamation-triangle"></i> Remember:</strong>
                <ul class="mb-0 mt-2">
                    <li>🚫 NEVER share your M-PESA PIN or OTP</li>
                    <li>🚫 NEVER send money to "verify" your account</li>
                    <li>✅ Hang up and call back on official numbers</li>
                    <li>📞 Report scam calls to 333 (Safaricom) or 3333 (Airtel)</li>
                </ul>
            </div>
        </div>
    `;
    resultDiv.classList.add('show');
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ============ CHECK PHONE NUMBER (SIMPLE) ============

function checkPhoneNumber(number) {
    const cleaned = number.replace(/\D/g, '');
    if (cleaned === '0722000000') return '<div class="alert alert-success"><i class="fas fa-check-circle"></i> Official Safaricom number - Legitimate</div>';
    if (cleaned.startsWith('0900') || cleaned.startsWith('0906')) return '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle"></i> ⚠️ Premium rate number - May charge high fees!</div>';
    return '<div class="alert alert-info"><i class="fas fa-search"></i> This number is not in our scam database. Always verify before trusting.</div>';
}

// Add CSS animations
const styleSheet = document.createElement('style');
styleSheet.textContent = `
    @keyframes flash {
        0% { opacity: 1; }
        50% { opacity: 0.5; background-color: #ff4444; }
        100% { opacity: 1; }
    }
    .animate-pulse {
        animation: pulse 1.5s ease-in-out infinite;
    }
    @keyframes pulse {
        0% { opacity: 0.6; }
        50% { opacity: 1; }
        100% { opacity: 0.6; }
    }
    .transcript-entry {
        padding: 4px 8px;
        margin: 2px 0;
        border-radius: 6px;
        font-size: 0.8rem;
        word-break: break-word;
    }
    .transcript-entry:hover {
        background: rgba(255,255,255,0.1);
    }
    #interimTranscript {
        padding: 4px 8px;
        background: rgba(255,255,255,0.1);
        border-radius: 6px;
        min-height: 32px;
    }
    #scamMeterBar {
        transition: width 0.3s ease, background-color 0.3s ease;
    }
`;
document.head.appendChild(styleSheet);

// ============ EVENT LISTENERS & INITIALIZATION ============

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing...');
    
    initCharts();
    
    setTimeout(() => { loadEnhancedStats(); }, 100);
    
    const statsTabBtn = document.querySelector('[data-tab="stats"]');
    if (statsTabBtn) {
        statsTabBtn.addEventListener('click', function() {
            setTimeout(() => {
                if (scamTypeChart) scamTypeChart.update();
                if (riskDistributionChart) riskDistributionChart.update();
                if (trendChart) trendChart.update();
            }, 100);
        });
    }
    
    // SMS Form Handler
    const smsForm = document.getElementById('smsForm');
    if (smsForm) {
        smsForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const smsText = document.getElementById('smsText').value;
            if (!smsText.trim()) { showToast('Please enter SMS text', 'warning'); return; }
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
                    headers: { 'X-CSRFToken': getCSRFToken(), 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin',
                    body: formData
                });
                const data = await response.json();
                displayResult(data, 'smsResult', 'smsSpinner');
                loadEnhancedStats();
            } catch (error) { showToast('Network error', 'danger'); }
            finally { spinner.classList.remove('show'); analyzeBtn.disabled = false; }
        });
    }
    
    // Email Form Handler
    const emailForm = document.getElementById('emailForm');
    if (emailForm) {
        emailForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const emailText = document.getElementById('emailText').value;
            if (!emailText.trim()) { showToast('Please enter email content', 'warning'); return; }
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
                    headers: { 'X-CSRFToken': getCSRFToken(), 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin',
                    body: formData
                });
                const data = await response.json();
                displayResult(data, 'emailResult', 'emailSpinner');
                loadEnhancedStats();
                showToast('✅ Email analyzed safely', 'success');
            } catch (error) { showToast('Network error', 'danger'); }
            finally { spinner.classList.remove('show'); analyzeBtn.disabled = false; }
        });
    }
    
    // WhatsApp Form Handler
    const whatsappForm = document.getElementById('whatsappForm');
    if (whatsappForm) {
        whatsappForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const chatText = document.getElementById('whatsappText').value;
            if (!chatText.trim()) { showToast('Please paste WhatsApp chat', 'warning'); return; }
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
                    headers: { 'X-CSRFToken': getCSRFToken(), 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin',
                    body: formData
                });
                if (!response.ok) throw new Error(`Server error: ${response.status}`);
                const data = await response.json();
                displayResult(data, 'whatsappResult', 'whatsappSpinner');
                loadEnhancedStats();
                showToast('✅ Analysis complete!', 'success');
            } catch (error) { showToast(error.message, 'danger'); }
            finally { spinner.classList.remove('show'); analyzeBtn.disabled = false; }
        });
    }
    
    // URL Checker Handler
    const urlForm = document.getElementById('urlForm');
    if (urlForm) {
        urlForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('urlInput').value.trim();
            if (!url) { showToast('Please enter a URL', 'warning'); return; }
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
                loadEnhancedStats();
            } catch (error) { showToast('Network error: ' + error.message, 'danger'); }
            finally { spinner.classList.remove('show'); }
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
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.style.borderColor = '#764ba2'; dropZone.style.backgroundColor = '#f0f0ff'; });
        dropZone.addEventListener('dragleave', (e) => { e.preventDefault(); dropZone.style.borderColor = '#667eea'; dropZone.style.backgroundColor = 'transparent'; });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.style.borderColor = '#667eea';
            dropZone.style.backgroundColor = 'transparent';
            const file = e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) handleImageFile(file);
            else showToast('Please upload an image file', 'warning');
        });
    }
    
    if (screenshotInput) {
        screenshotInput.addEventListener('change', (e) => { if (e.target.files[0]) handleImageFile(e.target.files[0]); });
    }
    
    function handleImageFile(file) {
        if (file.size > 5 * 1024 * 1024) return showToast('File too large. Max 5MB', 'warning');
        currentImageFile = file;
        const reader = new FileReader();
        reader.onload = (e) => { previewImage.src = e.target.result; previewDiv.style.display = 'block'; };
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
                loadEnhancedStats();
            } catch (error) {
                resultDiv.innerHTML = `<div class="alert alert-danger">OCR failed: ${error.message}</div>`;
                resultDiv.classList.add('show');
                spinner.classList.remove('show');
            } finally { spinner.classList.remove('show'); }
        });
    }
    
    // Example buttons handler
    document.querySelectorAll('.example-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.getAttribute('data-type');
            const example = btn.getAttribute('data-example');
            if (type && example) loadExample(type, example);
        });
    });
    
    // Tab buttons handler
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.getAttribute('data-tab');
            if (tabName) switchTab(tabName);
        });
    });
    
    // Initialize Real-Time Call Detection
    initRealtimeCallDetection();
    
    // Auto-refresh stats every 30 seconds
    setInterval(() => {
        if (document.getElementById('statsTab') && document.getElementById('statsTab').classList.contains('active')) {
            loadEnhancedStats();
        }
    }, 30000);
});