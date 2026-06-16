// ============================================================
// dashboard.js - Enhanced Dashboard Visualizations
// Works alongside main.js
// ============================================================

// Enhanced chart instances
let hourlyChart = null;
let monthlyChart = null;
let blocklistHealthChart = null;

// ============================================================
// ENHANCED DASHBOARD CHARTS
// ============================================================

function createHourlyChart(stats) {
    const ctx = document.getElementById('hourlyChart');
    if (!ctx) return;
    if (hourlyChart) hourlyChart.destroy();
    
    const hours = stats.hourly_distribution || Array(24).fill(0);
    const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
    
    hourlyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Scams Detected',
                data: hours,
                backgroundColor: hours.map(h => h > 5 ? '#ef4444' : h > 2 ? '#f59e0b' : '#3b82f6'),
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                x: { ticks: { color: '#9ca3af', maxTicksLimit: 12 }, grid: { display: false } }
            }
        }
    });
}

function createMonthlyChart(stats) {
    const ctx = document.getElementById('monthlyChart');
    if (!ctx) return;
    if (monthlyChart) monthlyChart.destroy();
    
    monthlyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: stats.monthly_labels || ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
            datasets: [{
                label: 'Scams Reported',
                data: stats.monthly_trend || [0, 0, 0, 0],
                backgroundColor: ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b'],
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                x: { ticks: { color: '#9ca3af' }, grid: { display: false } }
            }
        }
    });
}

function createBlocklistHealthChart(stats) {
    const ctx = document.getElementById('blocklistHealthChart');
    if (!ctx) return;
    if (blocklistHealthChart) blocklistHealthChart.destroy();
    
    blocklistHealthChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Blocked', 'Confirmed', 'Pending', 'Rejected'],
            datasets: [{
                data: [
                    stats.blocked_count || 0,
                    stats.confirmed_count || 0,
                    stats.pending_count || 0,
                    stats.rejected_count || 0
                ],
                backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#6b7280'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#9ca3af', font: { size: 10 } } }
            }
        }
    });
}

function createDetectionGauge() {
    const canvas = document.getElementById('detectionGauge');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const value = 98;
    
    ctx.clearRect(0, 0, 150, 150);
    
    // Background arc
    ctx.beginPath();
    ctx.arc(75, 90, 50, Math.PI, 0);
    ctx.lineWidth = 15;
    ctx.strokeStyle = '#374151';
    ctx.stroke();
    
    // Value arc
    const angle = Math.PI + (value / 100) * Math.PI;
    const gradient = ctx.createLinearGradient(0, 0, 150, 0);
    gradient.addColorStop(0, '#3b82f6');
    gradient.addColorStop(1, '#10b981');
    
    ctx.beginPath();
    ctx.arc(75, 90, 50, Math.PI, angle);
    ctx.lineWidth = 15;
    ctx.strokeStyle = gradient;
    ctx.stroke();
}

// ============================================================
// UPDATE ENHANCED STATS
// ============================================================

function updateEnhancedStats(stats) {
    // Update summary cards
    const elements = {
        'todayTotal': stats.today_count || 0,
        'todayScams': stats.high_risk_count || 0,
        'blockedCount': stats.blocked_count || 0,
        'pendingReview': stats.pending_count || 0,
        'thisWeekTotal': stats.this_week_count || 0,
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    });
    
    // Top scam type
    const topScamType = document.getElementById('topScamType');
    if (topScamType && stats.top_scam_types && stats.top_scam_types.length > 0) {
        topScamType.textContent = stats.top_scam_types[0].type || '-';
    }
    
    // Update top scam categories list
    const topScamDiv = document.getElementById('topScamCategories');
    if (topScamDiv && stats.top_scam_types) {
        if (stats.top_scam_types.length === 0) {
            topScamDiv.innerHTML = '<div class="text-center text-muted py-4">No data yet</div>';
        } else {
            const maxCount = stats.top_scam_types[0].count || 1;
            const colors = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'];
            topScamDiv.innerHTML = stats.top_scam_types.slice(0, 8).map((s, i) => `
                <div class="top-scam-item">
                    <span class="top-scam-rank">#${i + 1}</span>
                    <span class="top-scam-name">${s.type}</span>
                    <div style="flex:1; margin: 0 10px;">
                        <div class="horizontal-bar" style="width:${(s.count/maxCount)*100}%; background: ${colors[i]};"></div>
                    </div>
                    <span class="top-scam-count">${s.count}</span>
                </div>
            `).join('');
        }
    }
    
    // Create/update enhanced charts
    createHourlyChart(stats);
    createMonthlyChart(stats);
    createBlocklistHealthChart(stats);
    createDetectionGauge();
}

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Wait for stats to load, then update enhanced charts
    const observer = new MutationObserver(function() {
        const statsTab = document.getElementById('statsTab');
        if (statsTab && statsTab.classList.contains('active')) {
            // Stats tab is visible, enhanced charts will be created by updateEnhancedStats
            observer.disconnect();
        }
    });
    
    const statsTab = document.getElementById('statsTab');
    if (statsTab) {
        observer.observe(statsTab, { attributes: true, attributeFilter: ['class'] });
    }
});