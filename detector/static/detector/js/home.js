// detector/static/detector/js/home.js
// AI Fraud Shield - Home Page JavaScript

document.addEventListener('DOMContentLoaded', function() {
    console.log('Home page JS loaded');
    
    // Load stats on page load
    loadQuickStats();
    
    // Set up tab switching
    setupTabSwitching();
    
    // Set up example buttons
    setupExampleButtons();
});

// ============================================================
// QUICK STATS
// ============================================================

function loadQuickStats() {
    fetch('/api/stats/')
        .then(r => r.json())
        .then(d => {
            if (d.stats) {
                document.getElementById('qsScans').textContent = d.stats.today_count || 0;
                document.getElementById('qsHighRisk').textContent = d.stats.high_risk_count || 0;
                document.getElementById('qsSMS').textContent = d.stats.sms_count || 0;
                document.getElementById('qsCounties').textContent = (d.stats.county_data || []).length || 0;
                document.getElementById('qsBlocked').textContent = d.stats.takedown_total || 0;
            }
        })
        .catch(error => console.error('Stats load error:', error));
}

// ============================================================
// TAB SWITCHING
// ============================================================

function setupTabSwitching() {
    // Sidebar navigation
    document.querySelectorAll('.side-link[data-tab]').forEach((link) => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Update active state
            document.querySelectorAll('.side-link').forEach((l) => l.classList.remove('active'));
            this.classList.add('active');
            
            // Show corresponding tab
            document.querySelectorAll('.tab-content').forEach((t) => t.classList.remove('active'));
            document.getElementById(this.dataset.tab + 'Tab').classList.add('active');
            
            // Load stats if stats tab
            if (this.dataset.tab === 'stats') {
                if (typeof loadEnhancedStats === 'function') {
                    loadEnhancedStats();
                }
            }
        });
    });
}

// ============================================================
// EXAMPLE BUTTONS
// ============================================================

function setupExampleButtons() {
    document.querySelectorAll('.example-btn').forEach((btn) => {
        btn.addEventListener('click', function() {
            const type = this.dataset.type;
            const example = this.dataset.example;
            
            if (typeof loadExample === 'function') {
                loadExample(type, example);
            } else {
                // Fallback if loadExample is not available
                const examples = {
                    sms: {
                        scam: "URGENT: Your M-Pesa account has been suspended due to suspicious activity. Click http://mpesa-update.co.ke to verify your details immediately or your account will be deactivated.",
                        prize: "CONGRATULATIONS! You have won Ksh 250,000 in our Safaricom promotion. Click https://bit.ly/claim-prize to claim your prize now!",
                        safe: "Safaricom: Your M-Pesa transaction of Ksh 500 to John Mwangi was successful. New balance: Ksh 2,450. Thank you for using M-Pesa."
                    }
                };
                
                const textarea = document.getElementById(`${type}Text`);
                if (textarea && examples[type] && examples[type][example]) {
                    textarea.value = examples[type][example];
                    const resultDiv = document.getElementById(`${type}Result`);
                    if (resultDiv) resultDiv.classList.remove('show');
                }
            }
        });
    });
}

// ============================================================
// SIDEBAR TOGGLE FOR MOBILE
// ============================================================

// Add mobile sidebar toggle if needed
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        sidebar.classList.toggle('sidebar-open');
    }
}

// ============================================================
// ENSURE SIDEBAR LINKS WORK
// ============================================================

// Handle sidebar footer links - they should work as normal links
// No special handling needed since they use href directly

console.log('✅ Home page JS initialized');