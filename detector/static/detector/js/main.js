// detector/static/detector/js/main.js - CLEANED & FIXED VERSION

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

// Get CSRF token
function getCSRFToken() {
  let cookieValue = null;
  if (document.cookie && document.cookie !== "") {
    const cookies = document.cookie.split(";");
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.startsWith("csrftoken=")) {
        cookieValue = decodeURIComponent(cookie.substring("csrftoken=".length));
        break;
      }
    }
  }
  return cookieValue;
}

// Show toast notification
function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast align-items-center text-white bg-${type} border-0 position-fixed bottom-0 end-0 m-3`;
  toast.setAttribute("role", "alert");
  toast.setAttribute("aria-live", "assertive");
  toast.setAttribute("aria-atomic", "true");
  toast.style.zIndex = "9999";
  toast.style.position = "fixed";
  toast.style.bottom = "20px";
  toast.style.right = "20px";
  toast.style.minWidth = "250px";

  toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

  document.body.appendChild(toast);
  const bsToast = new bootstrap.Toast(toast, { delay: 3000 });
  bsToast.show();

  toast.addEventListener("hidden.bs.toast", () => {
    toast.remove();
  });
}

// Escape HTML
function escapeHtml(text) {
  if (!text) return "";
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Export reports as CSV
async function exportReports() {
  try {
    showToast("📥 Preparing export...", "info");
    const response = await fetch("/api/export/", {
      headers: { "X-CSRFToken": getCSRFToken() },
      credentials: "same-origin",
    });

    if (response.ok) {
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scam_reports_${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      showToast(
        "✅ Export successful! Check your downloads folder.",
        "success",
      );
    } else {
      showToast("❌ Export failed. Please try again.", "danger");
    }
  } catch (error) {
    console.error("Export error:", error);
    showToast("❌ Network error. Cannot export reports.", "danger");
  }
}

// Tab switching
function switchTab(tabName) {
  document
    .querySelectorAll(".tab-content")
    .forEach((tab) => tab.classList.remove("active"));

  const activeTab = document.getElementById(`${tabName}Tab`);
  if (activeTab) activeTab.classList.add("active");

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.remove("active");
    if (btn.getAttribute("data-tab") === tabName) btn.classList.add("active");
  });

  if (tabName === "stats") {
    loadStats();
    loadActivityFeed();
}
}

// Load examples
function loadExample(type, exampleType) {
  const examples = {
    sms: {
      scam: "URGENT: Your M-Pesa account has been suspended due to suspicious activity. Click http://mpesa-update.co.ke to verify your details immediately or your account will be deactivated.",
      prize:
        "CONGRATULATIONS! You have won Ksh 250,000 in our Safaricom promotion. Click https://bit.ly/claim-prize to claim your prize now!",
      safe: "Safaricom: Your M-Pesa transaction of Ksh 500 to John Mwangi was successful. New balance: Ksh 2,450. Thank you for using M-Pesa.",
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

This is a system generated message.`,
    },

    telegram: {
      scam: "URGENT: Your M-Pesa account has been suspended. Send your PIN to 0712345678 immediately to verify and restore access.",
      prize:
        "CONGRATULATIONS! You have been selected as winner of our Telegram promotion! Send Ksh 500 to claim your iPhone 15 Pro.",
      safe: "Hey, are we still meeting for lunch at 1pm? Let me know if you can make it.",
    },
  };

  const textarea = document.getElementById(`${type}Text`);
  if (textarea && examples[type] && examples[type][exampleType]) {
    textarea.value = examples[type][exampleType];
    const resultDiv = document.getElementById(`${type}Result`);
    if (resultDiv) resultDiv.classList.remove("show");
  }
}

// ============================================================
// DISPLAY FUNCTIONS
// ============================================================

// Display Email Result (with non-clickable links)
function displayEmailResult(data, resultDivId) {
  const resultDiv = document.getElementById(resultDivId);
  if (!resultDiv) return;

  let headerClass = "success";
  if (data.color === "danger" || data.score >= 60) headerClass = "danger";
  else if (data.color === "warning" || data.score >= 30)
    headerClass = "warning";

  let warningsHtml = "";
  const warningsList = data.warnings || data.reasons || [];
  if (warningsList.length > 0) {
    warningsHtml = '<h6 class="mt-3">🚨 Issues Detected:</h6>';
    warningsList.slice(0, 8).forEach((warning) => {
      warningsHtml += `<div class="reason-item" style="border-left-color: ${headerClass === "danger" ? "#dc3545" : headerClass === "warning" ? "#ffc107" : "#28a745"};">${escapeHtml(warning)}</div>`;
    });
  }

  let urlHtml = "";
  if (data.url_analyses && data.url_analyses.length > 0) {
    urlHtml =
      '<h6 class="mt-3">🔗 Links Found (TEXT only - NOT clickable):</h6>';
    urlHtml +=
      '<div class="alert alert-secondary" style="font-size: 0.85rem; background: #f8f9fa;">';
    urlHtml +=
      "<strong>⚠️ Important:</strong> These links are shown as PLAIN TEXT for your safety.<br><br>";

    data.url_analyses.forEach((url, index) => {
      const urlColor =
        url.risk === "DANGEROUS"
          ? "#dc3545"
          : url.risk === "SUSPICIOUS"
            ? "#ffc107"
            : "#28a745";
      urlHtml += `
                <div class="reason-item" style="border-left-color: ${urlColor}; margin-top: 10px;">
                    <div><strong>${url.emoji || "🔗"} Link ${index + 1}: ${url.risk || "UNKNOWN"}</strong></div>
                    <div><strong>URL (TEXT only):</strong><br><span style="color: #666;">${escapeHtml(url.url)}</span></div>
                    <div><strong>Domain:</strong> ${escapeHtml(url.domain)}</div>
                    <div><strong>Message:</strong> ${escapeHtml(url.message)}</div>
                    ${url.reasons ? `<div><strong>⚠️ Issues:</strong><br>${url.reasons.map((r) => `• ${escapeHtml(r)}`).join("<br>")}</div>` : ""}
                </div>
            `;
    });
    urlHtml += "</div>";
  } else if (data.urls_found > 0) {
    urlHtml = `<div class="alert alert-info mt-3"><strong>🔗 Found ${data.urls_found} URL(s)</strong> in this email.</div>`;
  }

  let recommendationsHtml = "";
  if (data.recommendations && data.recommendations.length > 0) {
    recommendationsHtml =
      '<h6 class="mt-3">💡 What To Do:</h6><div style="background: #f8f9fa; padding: 12px; border-radius: 8px;">';
    data.recommendations.forEach((rec) => {
      recommendationsHtml += `<div>✓ ${escapeHtml(rec)}</div>`;
    });
    recommendationsHtml += "</div>";
  } else if (data.action) {
    recommendationsHtml = `<div class="alert alert-warning mt-3"><strong>⚠️ Recommended Action:</strong> ${escapeHtml(data.action)}</div>`;
  } else if (data.recommendation) {
    recommendationsHtml = `<div class="alert alert-info mt-3"><strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}</div>`;
  }

  resultDiv.innerHTML = `
        <div class="result-header ${headerClass}">
            <h3>${data.emoji || "🔍"} ${data.risk_level || "Analysis Complete"}</h3>
        </div>
        <div class="result-body">
            <p class="fw-bold">${escapeHtml(data.summary || data.message || "Email analyzed successfully")}</p>
            <div class="risk-score">Risk Score: <span style="color: ${headerClass === "danger" ? "#dc3545" : headerClass === "warning" ? "#ffc107" : "#28a745"};">${data.score || 0}</span> / 100</div>
            <div class="progress risk-progress"><div class="progress-bar bg-${headerClass}" style="width: ${data.score || 0}%;"></div></div>
            ${warningsHtml}
            ${urlHtml}
            ${recommendationsHtml}
            <hr>
            <div style="background: #fff3cd; padding: 12px; border-radius: 8px; margin-top: 15px;">
                <small style="color: #856404;"><strong>⚠️ REMEMBER:</strong> Don't copy links into your browser. Never share PIN, password, or M-Pesa code via email.</small>
            </div>
        </div>
    `;

  resultDiv.classList.add("show");
  resultDiv.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Display SMS/URL/General results
function displayGeneralResult(data, resultDivId) {
  const resultDiv = document.getElementById(resultDivId);
  if (!resultDiv) return;

  let headerClass = "success";
  if (data.color === "danger" || data.score >= 60) headerClass = "danger";
  else if (data.color === "warning" || data.score >= 30)
    headerClass = "warning";

  let warningsHtml = "";
  const warningsList = data.warnings || data.reasons || [];
  if (warningsList.length > 0) {
    warningsHtml = '<h6 class="mt-3">⚠️ Details:</h6>';
    warningsList.slice(0, 8).forEach((warning) => {
      warningsHtml += `<div class="reason-item" style="border-left-color: ${headerClass === "danger" ? "#dc3545" : headerClass === "warning" ? "#ffc107" : "#28a745"};">${escapeHtml(warning)}</div>`;
    });
  }

  let urlSpecificHtml = "";
  if (data.type === "URL" || data.domain) {
    urlSpecificHtml = `
            <div class="row mt-3">
                <div class="col-md-6">
                    <div class="alert alert-secondary"><strong>🌐 Domain:</strong><br><code>${escapeHtml(data.domain || "Unknown")}</code></div>
                </div>
                <div class="col-md-6">
                    <div class="alert ${data.has_https ? "alert-success" : "alert-warning"}"><strong>🔒 HTTPS:</strong><br>${data.has_https ? "✅ Secure" : "⚠️ Insecure"}</div>
                </div>
            </div>`;
    if (data.url)
      urlSpecificHtml += `<div class="alert alert-info"><strong>🔗 URL:</strong><br><code style="word-break: break-all;">${escapeHtml(data.url)}</code></div>`;
  }

  let recommendationsHtml = "";
  if (data.recommendations && data.recommendations.length > 0) {
    recommendationsHtml =
      '<h6 class="mt-3">💡 What To Do:</h6><div style="background: #f8f9fa; padding: 12px; border-radius: 8px;">';
    data.recommendations.forEach((rec) => {
      recommendationsHtml += `<div>✓ ${escapeHtml(rec)}</div>`;
    });
    recommendationsHtml += "</div>";
  } else if (data.recommendation) {
    recommendationsHtml = `<div class="alert alert-info mt-3"><strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}</div>`;
  }

  resultDiv.innerHTML = `
        <div class="result-header ${headerClass}">
            <h3>${data.emoji || "🔍"} ${data.risk_level || "Analysis Complete"}</h3>
            ${data.score ? `<div class="score-circle"><div class="score-value">${data.score}%</div><div class="score-label">Risk Score</div></div>` : ""}
        </div>
        <div class="result-body">
            <p class="fw-bold">${escapeHtml(data.message || data.summary || "Analysis complete")}</p>
            ${
              data.score
                ? `<div class="risk-score">Risk Score: <span style="color: ${headerClass === "danger" ? "#dc3545" : headerClass === "warning" ? "#ffc107" : "#28a745"};">${data.score}</span> / 100</div>
            <div class="progress risk-progress"><div class="progress-bar bg-${headerClass}" style="width: ${data.score}%;"></div></div>`
                : ""
            }
            ${urlSpecificHtml}
            ${warningsHtml}
            ${recommendationsHtml}
            ${data.analysis_time ? `<div class="text-muted mt-3"><small>Analyzed at: ${data.analysis_time}</small></div>` : ""}
        </div>
    `;
  resultDiv.classList.add("show");
}

// Display WhatsApp results
function displayWhatsAppResult(data, resultDivId) {
  const resultDiv = document.getElementById(resultDivId);
  if (!resultDiv) return;

  const scorePercent = data.score || 0;
  let headerClass = "success";
  if (scorePercent >= 50) headerClass = "danger";
  else if (scorePercent >= 25) headerClass = "warning";

  let suspiciousHtml = "";
  if (data.suspicious_messages && data.suspicious_messages.length > 0) {
    suspiciousHtml = `<div class="mt-3"><strong>Suspicious messages:</strong><ul class="mt-2">${data.suspicious_messages.map((msg) => `<li class="text-danger">"${escapeHtml(msg)}..."</li>`).join("")}</ul></div>`;
  }

  const reasonsHtml = data.reasons
    ? data.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")
    : "<li>No specific indicators found</li>";

  resultDiv.innerHTML = `
        <div class="result-header ${data.color || headerClass}">
            <h3>${data.emoji || "🔍"} ${data.risk_level || "Analysis Complete"}</h3>
            <div class="score-circle"><div class="score-value">${scorePercent}%</div><div class="score-label">Risk Score</div></div>
        </div>
        <div class="result-body">
            <div class="alert alert-${data.color === "danger" ? "danger" : data.color === "warning" ? "warning" : "success"}"><strong>${escapeHtml(data.message || "")}</strong></div>
            ${data.recommendation ? `<div class="alert alert-info"><strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}</div>` : ""}
            <div class="row mb-3">
                <div class="col-md-6"><strong>📊 Stats:</strong><ul><li>Messages: ${data.message_count || 0}</li><li>Senders: ${data.unique_senders || "N/A"}</li>${data.grammar_issues ? `<li>Grammar issues: ${data.grammar_issues}</li>` : ""}</ul></div>
                <div class="col-md-6"><div class="progress mb-2" style="height: 30px;"><div class="progress-bar bg-${headerClass}" style="width: ${scorePercent}%;">${scorePercent}% Risk</div></div></div>
            </div>
            <strong>⚠️ Indicators:</strong><ul>${reasonsHtml}</ul>
            ${suspiciousHtml}
            <div class="alert alert-secondary mt-3"><strong>💡 Safety Tips:</strong><ul class="mb-0 mt-2"><li>Never share M-PESA PIN or OTP</li><li>Verify urgent money requests by phone</li><li>Don't click suspicious links</li><li>Report scam numbers to your provider</li><li>Block & report scammers on WhatsApp</li></ul></div>
        </div>
    `;
  resultDiv.classList.add("show");
  resultDiv.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Display Call Result
function displayCallResult(data, resultDivId) {
  const resultDiv = document.getElementById(resultDivId);
  if (!resultDiv) return;

  const headerClass =
    data.color === "danger"
      ? "danger"
      : data.color === "warning"
        ? "warning"
        : "success";
  let warningsHtml = "";
  if (data.warnings && data.warnings.length > 0) {
    warningsHtml = '<h6 class="mt-3">🚨 Red Flags:</h6>';
    data.warnings.forEach((w) => {
      warningsHtml += `<div class="reason-item" style="border-left-color: ${data.color === "danger" ? "#dc3545" : data.color === "warning" ? "#ffc107" : "#28a745"};">${escapeHtml(w)}</div>`;
    });
  }

  let recommendationsHtml = "";
  if (data.recommendations && data.recommendations.length > 0) {
    recommendationsHtml =
      '<h6 class="mt-3">💡 What To Do:</h6><div style="background: #f8f9fa; padding: 12px; border-radius: 8px;">';
    data.recommendations.forEach((rec) => {
      recommendationsHtml += `<div>✓ ${escapeHtml(rec)}</div>`;
    });
    recommendationsHtml += "</div>";
  }

  resultDiv.innerHTML = `
        <div class="result-header ${headerClass}">
            <h3>${data.emoji || "📞"} ${data.risk_level || "Analysis Complete"}</h3>
            <div class="score-circle"><div class="score-value">${data.score || 0}%</div><div class="score-label">Risk Score</div></div>
        </div>
        <div class="result-body">
            <p class="fw-bold">${escapeHtml(data.message || "")}</p>
            <div class="risk-score">Score: <span style="color: ${data.color === "danger" ? "#dc3545" : data.color === "warning" ? "#ffc107" : "#28a745"};">${data.score || 0}</span> / 100</div>
            <div class="progress risk-progress"><div class="progress-bar bg-${headerClass}" style="width: ${data.score || 0}%;"></div></div>
            ${warningsHtml}
            ${recommendationsHtml}
            ${data.number_analysis ? `<hr><div class="alert alert-secondary"><strong>📞 Caller Number:</strong><br>Score: ${data.number_analysis.score || 0}%<br>${data.number_analysis.message || ""}</div>` : ""}
            <div class="alert alert-danger mt-3" style="background: #f8d7da; border-left: 4px solid #dc3545;">
                <strong><i class="fas fa-exclamation-triangle"></i> Remember:</strong>
                <ul class="mb-0 mt-2"><li>🚫 NEVER share M-PESA PIN or OTP</li><li>🚫 NEVER send money to "verify" account</li><li>✅ Hang up & call official numbers</li><li>📞 Report to 333 (Safaricom) or 3333 (Airtel)</li></ul>
            </div>
        </div>
    `;
  resultDiv.classList.add("show");
  resultDiv.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Unified display result - routes to correct display function
function displayResult(data, resultDivId, spinnerId) {
  const resultDiv = document.getElementById(resultDivId);
  const spinner = document.getElementById(spinnerId);

  if (spinner) spinner.classList.remove("show");

  if (!data || data.error) {
    resultDiv.innerHTML = `<div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 10px;"><h3>⚠️ Error</h3><p>${escapeHtml(data?.error || "An error occurred")}</p></div>`;
    resultDiv.classList.add("show");
    return;
  }

  if (data.type === "EMAIL" || data.url_analyses) {
    displayEmailResult(data, resultDivId);
  } else if (
    data.suspicious_messages !== undefined ||
    data.message_count !== undefined
  ) {
    displayWhatsAppResult(data, resultDivId);
  } else {
    displayGeneralResult(data, resultDivId);
  }
}

// ============================================================
// CHART FUNCTIONS
// ============================================================

let scamTypeChart = null;
let riskDistributionChart = null;
let trendChart = null;

function getLast7Days() {
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    days.push(
      date.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    );
  }
  return days;
}

function initCharts() {
  console.log("Initializing charts...");

  const typeCanvas = document.getElementById("scamTypeChart");
  if (typeCanvas) {
    const typeCtx = typeCanvas.getContext("2d");
    if (scamTypeChart) scamTypeChart.destroy();
    scamTypeChart = new Chart(typeCtx, {
      type: "doughnut",
      data: {
        labels: [
          "SMS",
          "Email",
          "WhatsApp",
          "Screenshot",
          "URL",
          "Calls",
          "Telegram",
        ],
        datasets: [
          {
            data: [0, 0, 0, 0, 0, 0, 0],
            backgroundColor: [
              "#17a2b8",
              "#fd7e14",
              "#20c997",
              "#6f42c1",
              "#6610f2",
              "#dc3545",
              "#0088cc",
            ],
            borderWidth: 0,
            hoverOffset: 10,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { position: "bottom", labels: { font: { size: 11 } } },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const pct =
                  total > 0 ? ((ctx.raw / total) * 100).toFixed(1) : 0;
                return `${ctx.label}: ${ctx.raw} (${pct}%)`;
              },
            },
          },
        },
      },
    });
  }

  const riskCanvas = document.getElementById("riskDistributionChart");
  if (riskCanvas) {
    const riskCtx = riskCanvas.getContext("2d");
    if (riskDistributionChart) riskDistributionChart.destroy();
    riskDistributionChart = new Chart(riskCtx, {
      type: "bar",
      data: {
        labels: [
          "High Risk (70-100)",
          "Medium Risk (40-69)",
          "Low Risk (0-39)",
        ],
        datasets: [
          {
            label: "Reports",
            data: [0, 0, 0],
            backgroundColor: ["#dc3545", "#ffc107", "#28a745"],
            borderRadius: 8,
            barPercentage: 0.6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: { legend: { position: "top" } },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: "#e9ecef" },
            title: { display: true, text: "Reports" },
          },
          x: {
            grid: { display: false },
            title: { display: true, text: "Risk Level" },
          },
        },
      },
    });
  }

  const trendCanvas = document.getElementById("trendChart");
  if (trendCanvas) {
    const trendCtx = trendCanvas.getContext("2d");
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(trendCtx, {
      type: "line",
      data: {
        labels: getLast7Days(),
        datasets: [
          {
            label: "Scams Detected",
            data: [0, 0, 0, 0, 0, 0, 0],
            borderColor: "#2563eb",
            backgroundColor: "rgba(37, 99, 235, 0.1)",
            borderWidth: 3,
            fill: true,
            tension: 0.4,
            pointBackgroundColor: "#2563eb",
            pointBorderColor: "white",
            pointBorderWidth: 2,
            pointRadius: 5,
            pointHoverRadius: 7,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: { legend: { position: "top" } },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: "#e9ecef" },
            title: { display: true, text: "Scams" },
          },
          x: {
            grid: { display: false },
            title: { display: true, text: "Date" },
          },
        },
      },
    });
  }
}

// Update charts with new data
function updateChartsInstant(s) {
  if (scamTypeChart) {
    scamTypeChart.data.datasets[0].data = [
      s.sms_count || 0,
      s.email_count || 0,
      s.whatsapp_count || 0,
      s.screenshot_count || 0,
      s.url_count || 0,
      s.call_count || 0,
      s.telegram_count || 0,
    ];
    scamTypeChart.update();
  }

  if (riskDistributionChart && s.risk_distribution) {
    riskDistributionChart.data.datasets[0].data = [
      s.risk_distribution.high || 0,
      s.risk_distribution.medium || 0,
      s.risk_distribution.low || 0,
    ];
    riskDistributionChart.update();
  }

  if (trendChart && s.weekly_trend) {
    trendChart.data.datasets[0].data = s.weekly_trend;
    trendChart.update();
  }
}

// Update charts (alias for compatibility)
function updateCharts(data) {
  if (data && data.stats) {
    updateChartsInstant(data.stats);
  } else {
    updateChartsInstant(data);
  }
}

// ============================================================
// STATS UPDATE FUNCTIONS
// ============================================================
async function loadEnhancedStats() {
  console.log("Loading enhanced stats...");
  try {
    const response = await fetch("/api/stats/", {
      headers: {
        "X-CSRFToken": getCSRFToken(),
        "Content-Type": "application/json",
      },
      credentials: "same-origin",
    });
    const data = await response.json();

    if (data.success && data.stats) {
      const s = data.stats;

      // Update stat cards
      const updates = {
        totalReports: s.total_reports,
        highRisk: s.high_risk_count,
        smsCount: s.sms_count,
        emailCount: s.email_count,
        whatsappCount: s.whatsapp_count,
        callCount: s.call_count,
        telegramCount: s.telegram_count,
        ussdReports: s.ussd_count,
        takedownTotal: s.takedown_total,
        takedownCompleted: s.takedown_completed,
        avgRiskScore: s.average_risk_score,
        statTotalReports: s.total_reports,
        statHighRisk: s.high_risk_count,
        statAvgScore: s.average_risk_score,
      };

      Object.entries(updates).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value || 0;
      });

      // Update charts
      updateChartsInstant(s);

      // Trigger enhanced dashboard charts
      if (typeof updateEnhancedStats === 'function') {
          updateEnhancedStats(s);
      }

      // Update table
      updateRecentScamsTable(s.recent_scams || []);

      // Update staff activity table
      if (data.staff_scans && data.staff_scans.length > 0) {
        const staffBody = document.getElementById('staffActivityBody');
        if (staffBody) {
          staffBody.innerHTML = data.staff_scans.map(staff => `
            <tr>
              <td><i class="fas fa-user"></i> ${staff.name || 'Unknown'}</td>
              <td><span class="badge bg-info">${staff.scans || 0}</span></td>
              <td><span class="badge bg-danger">${staff.high_risk || 0}</span></td>
              <td><span class="badge bg-success">${staff.today || 0}</span></td>
            </tr>
          `).join('');
        }
      }
    }
  } catch (error) {
    console.error("Error loading stats:", error);
  }
}


// Instant stats update (for real-time call monitoring)
async function updateStatsInstant() {
  console.log("🔄 Instant stats update...");
  try {
    const response = await fetch("/api/stats/");
    const data = await response.json();

    if (data.success && data.stats) {
      const s = data.stats;

      const updates = {
        totalReports: s.total_reports,
        highRisk: s.high_risk_count,
        smsCount: s.sms_count,
        emailCount: s.email_count,
        whatsappCount: s.whatsapp_count,
        callCount: s.call_count,
        telegramCount: s.telegram_count,
        ussdReports: s.ussd_count,
        takedownTotal: s.takedown_total,
        takedownCompleted: s.takedown_completed,
        avgRiskScore: s.average_risk_score,
        statTotalReports: s.total_reports,
        statHighRisk: s.high_risk_count,
        statAvgScore: s.average_risk_score,
      };

      Object.entries(updates).forEach(([id, value]) => {
        const el = document.getElementById(id);
        if (el && el.textContent != value) el.textContent = value || 0;
      });

      updateChartsInstant(s);
      updateRecentScamsTable(s.recent_scams || []);
    }
  } catch (error) {
    console.error("Stats update error:", error);
  }
}

function updateRecentScamsTable(scams) {
  const tbody = document.getElementById("recentScamsBody");
  if (!tbody) return;

  if (!scams || scams.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="5" class="text-center">No scam reports yet.</td></tr>';
    return;
  }

  tbody.innerHTML = scams
    .slice(0, 15)
    .map(
      (scam) => `
        <tr>
            <td><small>${scam.date || ""}</small></td>
            <td><span class="badge ${getBadgeClass(scam.type)}">${scam.type || "?"}</span></td>
            <td><small>${escapeHtml((scam.preview || scam.content || "").substring(0, 60))}${(scam.preview || scam.content || "").length > 60 ? "..." : ""}</small></td>
            <td><span class="badge ${getRiskBadgeClass(scam.score)}">${scam.score || 0}/100</span></td>
            <td><span class="badge ${getLevelBadgeClass(scam.level)}">${scam.level || "LOW"}</span></td>
        </tr>
    `,
    )
    .join("");
}

function getBadgeClass(type) {
  const classes = {
    SMS: "bg-info",
    EMAIL: "bg-warning",
    WHATSAPP: "bg-success",
    SCREENSHOT: "bg-purple",
    URL: "bg-secondary",
    CALL: "bg-danger",
    TELEGRAM: "bg-info",
  };
  return classes[type] || "bg-secondary";
}

function getRiskBadgeClass(score) {
  if (score >= 70) return "bg-danger";
  if (score >= 40) return "bg-warning";
  return "bg-success";
}

function getLevelBadgeClass(level) {
  if (level && level.includes("HIGH")) return "bg-danger";
  if (level && level.includes("MEDIUM")) return "bg-warning";
  return "bg-success";
}

async function refreshStats() {
  showToast("Refreshing statistics...", "info");
  await loadEnhancedStats();
  showToast("Statistics updated!", "success");
}

// ============================================================
// REAL-TIME CALL MONITORING
// ============================================================

let isMonitoring = false;
let consecutiveScamPhrases = 0;
let currentScamScore = 0;
let speechRecognition = null;
let speechRecognitionActive = false;
let fullCallTranscript = "";
let detectedPatterns = [];
let callStartTime = null;

// Create live transcript display
function createLiveTranscriptDisplay() {
  const container = document.getElementById("liveTranscriptContainer");
  if (!container) return;
  if (document.getElementById("liveTranscriptPanel")) return;

  const panel = document.createElement("div");
  panel.id = "liveTranscriptPanel";
  panel.className = "mt-3 p-2";
  panel.style.cssText =
    "background: rgba(0,0,0,0.2); border-radius: 12px; border: 1px solid rgba(255,255,255,0.1);";
  panel.innerHTML = `
        <div class="d-flex justify-content-between align-items-center mb-2">
            <strong><i class="fas fa-comment-dots"></i> Live Call Transcript</strong>
            <small class="text-muted" id="transcriptTimer">00:00</small>
        </div>
        <div id="interimTranscript" class="text-muted small mb-2" style="font-style: italic; background: rgba(0,0,0,0.15); padding: 8px; border-radius: 6px; min-height: 40px;">
            🎤 Speak into your microphone...
        </div>
        <div id="liveTranscript" style="max-height: 200px; overflow-y: auto; font-size: 0.85rem; background: rgba(0,0,0,0.15); border-radius: 6px; padding: 8px;">
            <div class="text-muted">Waiting for speech...</div>
        </div>
        <div class="mt-2">
            <div class="row">
                <div class="col-8"><div class="progress" style="height: 8px;"><div id="scamMeterBar" class="progress-bar bg-success" style="width: 0%;"></div></div></div>
                <div class="col-4 text-end"><small id="scamMeterText" class="text-muted">✓ Safe</small></div>
            </div>
        </div>
        <div id="realtimeAlerts" class="mt-2" style="max-height: 100px; overflow-y: auto; font-size: 0.75rem;"></div>
    `;
  container.appendChild(panel);
}

function updateCallTimer() {
  const timerEl = document.getElementById("transcriptTimer");
  if (timerEl && callStartTime) {
    const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
    timerEl.textContent = `${String(Math.floor(elapsed / 60)).padStart(2, "0")}:${String(elapsed % 60).padStart(2, "0")}`;
  }
}

function updateLiveTranscriptDisplay(text, isFinal = true) {
  const transcriptDiv = document.getElementById("liveTranscript");
  if (!transcriptDiv) return;

  const timestamp = new Date().toLocaleTimeString();

  if (isFinal) {
    const entry = document.createElement("div");
    entry.style.cssText =
      "padding: 4px 8px; margin: 2px 0; border-radius: 6px; font-size: 0.8rem; border-left: 3px solid #667eea;";
    entry.innerHTML = `<small class="text-muted">[${timestamp}]</small> <strong>Caller:</strong> "${escapeHtml(text)}"`;
    transcriptDiv.appendChild(entry);
    transcriptDiv.scrollTop = transcriptDiv.scrollHeight;
    while (transcriptDiv.children.length > 30)
      transcriptDiv.removeChild(transcriptDiv.firstChild);
  } else {
    const interimDiv = document.getElementById("interimTranscript");
    if (interimDiv)
      interimDiv.innerHTML = `<em class="text-muted">🎙️ ${escapeHtml(text)}</em>`;
  }
}

function updateScamMeter(score) {
  currentScamScore = Math.min(100, Math.max(0, score));
  const meterBar = document.getElementById("scamMeterBar");
  const meterText = document.getElementById("scamMeterText");

  if (meterBar) {
    meterBar.style.width = currentScamScore + "%";
    if (currentScamScore >= 70) {
      meterBar.style.backgroundColor = "#dc3545";
      if (meterText) {
        meterText.innerHTML = "🔴 CRITICAL RISK";
        meterText.style.color = "#dc3545";
      }
    } else if (currentScamScore >= 50) {
      meterBar.style.backgroundColor = "#fd7e14";
      if (meterText) {
        meterText.innerHTML = "🟠 HIGH RISK";
        meterText.style.color = "#fd7e14";
      }
    } else if (currentScamScore >= 25) {
      meterBar.style.backgroundColor = "#ffc107";
      if (meterText) {
        meterText.innerHTML = "🟡 MEDIUM RISK";
        meterText.style.color = "#ffc107";
      }
    } else {
      meterBar.style.backgroundColor = "#28a745";
      if (meterText) {
        meterText.innerHTML = "🟢 LOW RISK";
        meterText.style.color = "#28a745";
      }
    }
  }
}

function playAlertBeep() {
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.frequency.value = 880;
    gain.gain.value = 0.3;
    osc.start();
    gain.gain.exponentialRampToValueAtTime(0.00001, audioCtx.currentTime + 0.5);
    osc.stop(audioCtx.currentTime + 0.5);
  } catch (e) {
    if (navigator.vibrate) navigator.vibrate([300, 100, 300]);
  }
}

function addRealtimeAlert(type, message) {
  const alertsDiv = document.getElementById("realtimeAlerts");
  if (!alertsDiv) return;

  const bgColor =
    type === "danger" ? "#dc3545" : type === "warning" ? "#ffc107" : "#17a2b8";
  const textColor = type === "warning" ? "#333" : "white";

  const alertDiv = document.createElement("div");
  alertDiv.style.cssText = `background: ${bgColor}; color: ${textColor}; padding: 6px 10px; margin: 3px 0; border-radius: 6px; font-size: 0.75rem;`;
  alertDiv.innerHTML = `<strong>[${new Date().toLocaleTimeString()}]</strong> ${message}`;
  alertsDiv.prepend(alertDiv);

  while (alertsDiv.children.length > 15)
    alertsDiv.removeChild(alertsDiv.lastChild);

  if (type === "danger") {
    const dangerAlert = document.getElementById("dangerAlert");
    if (dangerAlert) {
      dangerAlert.style.display = "block";
      dangerAlert.style.animation = "flash 0.5s ease-in-out 3";
      setTimeout(() => {
        if (dangerAlert) dangerAlert.style.display = "none";
      }, 3000);
    }
  }
}

function initSpeechRecognition() {
  if (
    !("webkitSpeechRecognition" in window) &&
    !("SpeechRecognition" in window)
  ) {
    addRealtimeAlert(
      "warning",
      "Speech recognition not supported. Use Chrome or Edge.",
    );
    return false;
  }

  const SpeechRecognitionAPI =
    window.webkitSpeechRecognition || window.SpeechRecognition;
  speechRecognition = new SpeechRecognitionAPI();
  speechRecognition.continuous = true;
  speechRecognition.interimResults = true;
  speechRecognition.lang = "en-US";
  speechRecognition.maxAlternatives = 1;

  speechRecognition.onstart = () => {
    console.log("Speech recognition started");
    addRealtimeAlert("success", "🎤 Voice recognition active - Speak now");
    const interimDiv = document.getElementById("interimTranscript");
    if (interimDiv)
      interimDiv.innerHTML =
        '<span class="text-success">🎤 Listening... Speak now</span>';
    fullCallTranscript = "";
    currentScamScore = 0;
    detectedPatterns = [];
    callStartTime = Date.now();
  };

  speechRecognition.onresult = (event) => {
    let finalTranscript = "";
    let interimTranscript = "";

    for (let i = event.resultIndex; i < event.results.length; i++) {
      const result = event.results[i];
      if (result.isFinal) finalTranscript += result[0].transcript + " ";
      else interimTranscript += result[0].transcript;
    }

    if (interimTranscript) {
      const interimDiv = document.getElementById("interimTranscript");
      if (interimDiv)
        interimDiv.innerHTML = `<i class="fas fa-microphone-alt"></i> <em>${escapeHtml(interimTranscript)}</em>`;
      clearTimeout(window.interimTimeout);
      window.interimTimeout = setTimeout(() => {
        if (interimDiv) interimDiv.innerHTML = "";
      }, 1500);
    }

    if (finalTranscript && finalTranscript.trim().length > 5) {
      fullCallTranscript += finalTranscript + "\n";
      updateLiveTranscriptDisplay(finalTranscript, true);

      // Local keyword analysis
      const lowerText = finalTranscript.toLowerCase();
      let detectedScamWords = [];
      let segmentRiskIncrease = 0;

      const scamKeywords = [
        { word: "pin", points: 35, msg: "🔴 PIN requested!" },
        { word: "mpin", points: 35, msg: "🔴 MPIN requested!" },
        { word: "password", points: 35, msg: "🔴 Password requested!" },
        { word: "otp", points: 35, msg: "🔴 OTP requested!" },
        { word: "send money", points: 30, msg: "💰 Money request!" },
        { word: "tuma pesa", points: 30, msg: "💰 Money request (Swahili)!" },
        { word: "urgent", points: 20, msg: "⏰ Urgency pressure!" },
        { word: "immediately", points: 20, msg: "⏰ Urgency pressure!" },
        { word: "suspended", points: 25, msg: "🚫 Account suspension threat!" },
        { word: "blocked", points: 25, msg: "🚫 Account blocked!" },
        { word: "verify", points: 20, msg: "🔐 Verification scam!" },
        { word: "transfer", points: 25, msg: "💰 Transfer request!" },
        { word: "code", points: 25, msg: "🔐 Code requested!" },
        { word: "win", points: 15, msg: "🎁 Prize scam!" },
        { word: "mpesa", points: 15, msg: "📱 M-Pesa related!" },
        { word: "safaricom", points: 15, msg: "📱 Safaricom impersonation!" },
        { word: "account", points: 10, msg: "⚠️ Account mentioned" },
      ];

      for (const kw of scamKeywords) {
        if (lowerText.includes(kw.word)) {
          detectedScamWords.push(kw.msg);
          segmentRiskIncrease += kw.points;
        }
      }

      if (detectedScamWords.length > 0) {
        currentScamScore = Math.min(
          100,
          currentScamScore + segmentRiskIncrease,
        );
        detectedPatterns.push(...detectedScamWords);
        updateScamMeter(currentScamScore);
        addRealtimeAlert(
          "danger",
          `⚠️ SCAM: ${detectedScamWords[0]}${detectedScamWords.length > 1 ? ` (+${detectedScamWords.length - 1} more)` : ""}`,
        );

        const dangerAlert = document.getElementById("dangerAlert");
        if (dangerAlert) {
          dangerAlert.style.display = "block";
          if (currentScamScore >= 70) {
            dangerAlert.innerHTML =
              '<strong><i class="fas fa-skull-crossbones"></i> CRITICAL SCAM! HANG UP NOW!</strong>';
          } else if (currentScamScore >= 50) {
            dangerAlert.innerHTML =
              '<strong><i class="fas fa-exclamation-triangle"></i> HIGH RISK! Consider hanging up.</strong>';
          } else {
            dangerAlert.innerHTML =
              '<strong><i class="fas fa-exclamation-triangle"></i> SCAM INDICATORS - Be careful.</strong>';
          }
        }

        if (currentScamScore >= 70) {
          showToast("CRITICAL SCAM DETECTED! HANG UP NOW!", "danger");
        }
      } else {
        consecutiveScamPhrases = Math.max(0, consecutiveScamPhrases - 0.3);
        updateScamMeter(currentScamScore * 0.95);
      }
    }
  };

  speechRecognition.onerror = (event) => {
    console.error("Speech error:", event.error);
    if (event.error === "not-allowed") {
      addRealtimeAlert(
        "danger",
        "Microphone denied. Please allow permissions.",
      );
      stopCallMonitoring();
    }
  };

  speechRecognition.onend = () => {
    if (isMonitoring && speechRecognitionActive) {
      setTimeout(() => {
        if (isMonitoring && speechRecognitionActive && speechRecognition) {
          try {
            speechRecognition.start();
            const interimDiv = document.getElementById("interimTranscript");
            if (interimDiv)
              interimDiv.innerHTML =
                '<span class="text-success">🎤 Listening...</span>';
          } catch (e) {
            speechRecognitionActive = false;
          }
        }
      }, 500);
    }
  };

  return true;
}

async function startCallMonitoring() {
  console.log("Start monitoring");
  try {
    fullCallTranscript = "";
    consecutiveScamPhrases = 0;
    currentScamScore = 0;
    detectedPatterns = [];
    callStartTime = Date.now();

    createLiveTranscriptDisplay();

    if (window.timerInterval) clearInterval(window.timerInterval);
    window.timerInterval = setInterval(updateCallTimer, 1000);

    await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      },
    });

    const startBtn = document.getElementById("startCallMonitorBtn");
    const stopBtn = document.getElementById("stopCallMonitorBtn");
    const monitorStatus = document.getElementById("monitorStatus");

    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
    if (monitorStatus)
      monitorStatus.innerHTML =
        '<span class="badge bg-success animate-pulse">🎙️ LIVE</span>';

    const speechSupported = initSpeechRecognition();

    if (speechSupported && speechRecognition) {
      speechRecognitionActive = true;
      isMonitoring = true;
      setTimeout(() => {
        if (speechRecognition && speechRecognitionActive) {
          try {
            speechRecognition.start();
            addRealtimeAlert("success", "🎤 Call monitoring active!");
            showToast("Call monitoring active!", "success");
          } catch (e) {
            console.error("Start error:", e);
            speechRecognitionActive = false;
            isMonitoring = false;
          }
        }
      }, 500);
    }
  } catch (error) {
    console.error("Microphone error:", error);
    showToast("Could not access microphone.", "danger");
    const startBtn = document.getElementById("startCallMonitorBtn");
    if (startBtn) startBtn.disabled = false;
  }
}

// FIXED: stopCallMonitoring now uses FormData and calls updateStatsInstant
async function stopCallMonitoring() {
  console.log("Stop monitoring clicked");

  isMonitoring = false;
  speechRecognitionActive = false;

  if (window.timerInterval) {
    clearInterval(window.timerInterval);
    window.timerInterval = null;
  }

  if (speechRecognition) {
    try {
      speechRecognition.stop();
    } catch (e) {}
    speechRecognition = null;
  }

  // ============================================================
  // FIXED: Save using FormData (same as manual analysis)
  // ============================================================
  if (fullCallTranscript && fullCallTranscript.trim().length > 20) {
    try {
      const formData = new FormData();
      formData.append("transcript", fullCallTranscript);
      formData.append(
        "phone_number",
        document.getElementById("callerNumber")?.value || "",
      );

      const response = await fetch("/api/detect-call/", {
        method: "POST",
        headers: { "X-CSRFToken": getCSRFToken() },
        credentials: "same-origin",
        body: formData,
      });

      const result = await response.json();
      console.log("✅ Call saved to database:", result);

      // FIXED: Update stats after save
      await updateStatsInstant();

      const summaryMsg = `📞 Call ended. Risk Score: ${result.score || currentScamScore}%. ${result.score >= 50 ? "⚠️ Scam call detected!" : "✅ No scam detected."}`;
      addRealtimeAlert(result.score >= 50 ? "danger" : "success", summaryMsg);
      showToast(summaryMsg, result.score >= 50 ? "danger" : "success");

      if (detectedPatterns.length > 0) {
        const uniquePatterns = [...new Set(detectedPatterns)];
        addRealtimeAlert(
          "info",
          `📊 Detected: ${uniquePatterns.slice(0, 5).join(", ")}${uniquePatterns.length > 5 ? ` +${uniquePatterns.length - 5} more` : ""}`,
        );
      }
    } catch (error) {
      console.error("Error saving call:", error);
      addRealtimeAlert("danger", "Failed to save call analysis.");
    }
  }

  // Reset state
  consecutiveScamPhrases = 0;
  detectedPatterns = [];
  callStartTime = null;
  fullCallTranscript = "";
  currentScamScore = 0;

  // Reset UI
  const startBtn = document.getElementById("startCallMonitorBtn");
  const stopBtn = document.getElementById("stopCallMonitorBtn");
  const monitorStatus = document.getElementById("monitorStatus");
  const dangerAlert = document.getElementById("dangerAlert");

  if (startBtn) startBtn.disabled = false;
  if (stopBtn) stopBtn.disabled = true;
  if (monitorStatus)
    monitorStatus.innerHTML =
      '<span class="badge bg-secondary">⚪ Not monitoring</span>';
  if (dangerAlert) {
    dangerAlert.style.display = "none";
  }

  updateScamMeter(0);

  const interimDiv = document.getElementById("interimTranscript");
  if (interimDiv) interimDiv.innerHTML = "";

  // Final stats update
  await updateStatsInstant();
}

function initRealtimeCallDetection() {
  const startBtn = document.getElementById("startCallMonitorBtn");
  const stopBtn = document.getElementById("stopCallMonitorBtn");
  if (startBtn) startBtn.addEventListener("click", startCallMonitoring);
  if (stopBtn) stopBtn.addEventListener("click", stopCallMonitoring);
}

// ============================================================
// ADD CSS ANIMATIONS
// ============================================================

const styleSheet = document.createElement("style");
styleSheet.textContent = `
    @keyframes flash { 0% { opacity: 1; } 50% { opacity: 0.5; background-color: #ff4444; } 100% { opacity: 1; } }
    .animate-pulse { animation: pulse 1.5s ease-in-out infinite; }
    @keyframes pulse { 0% { opacity: 0.6; } 50% { opacity: 1; } 100% { opacity: 0.6; } }
    #scamMeterBar { transition: width 0.3s ease, background-color 0.3s ease; }
`;
document.head.appendChild(styleSheet);

// ============================================================
// INITIALIZATION (DOMContentLoaded)
// ============================================================

document.addEventListener("DOMContentLoaded", function () {
  console.log("DOM loaded, initializing...");

  initCharts();
setTimeout(() => loadEnhancedStats(), 100);
  // Stats tab refresh
  const statsTabBtn = document.querySelector('[data-tab="stats"]');
  if (statsTabBtn) {
    statsTabBtn.addEventListener("click", () =>
      setTimeout(loadEnhancedStats, 100),
    );
  }

  // Sidebar navigation
document.querySelectorAll('.side-link').forEach(link => {
    link.addEventListener('click', function(e) {
        e.preventDefault();
        const tabName = this.getAttribute('data-tab');
        if (tabName) {
            switchTab(tabName);
            // Update active state
            document.querySelectorAll('.side-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        }
    });
});

// Also keep tab buttons working - sync sidebar with tabs
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.getAttribute('data-tab');
        document.querySelectorAll('.side-link').forEach(l => {
            l.classList.remove('active');
            if (l.getAttribute('data-tab') === tabName) l.classList.add('active');
        });
    });
});

  // SMS Form
  const smsForm = document.getElementById("smsForm");
  if (smsForm) {
    smsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const smsText = document.getElementById("smsText").value;
      if (!smsText.trim()) {
        showToast("Please enter SMS text", "warning");
        return;
      }
      const spinner = document.getElementById("smsSpinner");
      const resultDiv = document.getElementById("smsResult");
      spinner.classList.add("show");
      resultDiv.classList.remove("show");
      try {
        const formData = new FormData();
        formData.append("sms_text", smsText);
        const res = await fetch("/api/detect-sms/", {
          method: "POST",
          headers: { "X-CSRFToken": getCSRFToken() },
          credentials: "same-origin",
          body: formData,
        });
        displayResult(await res.json(), "smsResult", "smsSpinner");
        loadEnhancedStats();
      } catch (e) {
        showToast("Network error", "danger");
      } finally {
        spinner.classList.remove("show");
      }
    });
  }

  // Email Form
  const emailForm = document.getElementById("emailForm");
  if (emailForm) {
    emailForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const emailText = document.getElementById("emailText").value;
      if (!emailText.trim()) {
        showToast("Please enter email content", "warning");
        return;
      }
      const spinner = document.getElementById("emailSpinner");
      const resultDiv = document.getElementById("emailResult");
      spinner.classList.add("show");
      resultDiv.classList.remove("show");
      try {
        const formData = new FormData();
        formData.append("email_text", emailText);
        const res = await fetch("/api/detect-email/", {
          method: "POST",
          headers: { "X-CSRFToken": getCSRFToken() },
          credentials: "same-origin",
          body: formData,
        });
        displayResult(await res.json(), "emailResult", "emailSpinner");
        loadEnhancedStats();
        showToast("✅ Email analyzed safely", "success");
      } catch (e) {
        showToast("Network error", "danger");
      } finally {
        spinner.classList.remove("show");
      }
    });
  }

  // WhatsApp Form
  const whatsappForm = document.getElementById("whatsappForm");
  if (whatsappForm) {
    whatsappForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const chatText = document.getElementById("whatsappText").value;
      if (!chatText.trim()) {
        showToast("Please paste WhatsApp chat", "warning");
        return;
      }
      const spinner = document.getElementById("whatsappSpinner");
      const resultDiv = document.getElementById("whatsappResult");
      spinner.classList.add("show");
      resultDiv.classList.remove("show");
      try {
        const formData = new FormData();
        formData.append("chat_text", chatText);
        const res = await fetch("/api/detect-whatsapp/", {
          method: "POST",
          headers: { "X-CSRFToken": getCSRFToken() },
          credentials: "same-origin",
          body: formData,
        });
        displayResult(await res.json(), "whatsappResult", "whatsappSpinner");
        loadEnhancedStats();
      } catch (e) {
        showToast(e.message, "danger");
      } finally {
        spinner.classList.remove("show");
      }
    });
  }

  // URL Form
  const urlForm = document.getElementById("urlForm");
  if (urlForm) {
    urlForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const url = document.getElementById("urlInput").value.trim();
      if (!url) {
        showToast("Please enter a URL", "warning");
        return;
      }
      const spinner = document.getElementById("urlSpinner");
      const resultDiv = document.getElementById("urlResult");
      spinner.classList.add("show");
      resultDiv.classList.remove("show");
      try {
        const res = await fetch("/api/check-url/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCSRFToken(),
          },
          body: JSON.stringify({ url }),
        });
        displayResult(await res.json(), "urlResult", "urlSpinner");
        loadEnhancedStats();
      } catch (e) {
        showToast("Network error", "danger");
      } finally {
        spinner.classList.remove("show");
      }
    });

    
  // Telegram Form
  const telegramForm = document.getElementById('telegramForm');
  if (telegramForm) {
      telegramForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const telegramText = document.getElementById('telegramText').value;
          if (!telegramText.trim()) {
              showToast('Please enter Telegram message to analyze', 'warning');
              return;
          }
          const spinner = document.getElementById('telegramSpinner');
          const resultDiv = document.getElementById('telegramResult');
          spinner.classList.add('show'); resultDiv.classList.remove('show');
          try {
              const formData = new FormData();
              formData.append('telegram_text', telegramText);
              const res = await fetch('/api/detect-telegram/', {
                  method: 'POST',
                  headers: { 'X-CSRFToken': getCSRFToken() },
                  credentials: 'same-origin',
                  body: formData
              });
              displayResult(await res.json(), 'telegramResult', 'telegramSpinner');
              loadEnhancedStats();
          } catch(e) { showToast('Network error', 'danger'); }
          finally { spinner.classList.remove('show'); }
      });
  }
  }

  // Screenshot OCR
  const dropZone = document.getElementById("dropZone");
  const screenshotInput = document.getElementById("screenshotInput");
  const previewDiv = document.getElementById("screenshotPreview");
  const previewImage = document.getElementById("previewImage");
  const analyzeScreenshotBtn = document.getElementById("analyzeScreenshotBtn");
  let currentImageFile = null;

  if (dropZone) {
    dropZone.addEventListener("click", () => screenshotInput.click());
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "#764ba2";
    });
    dropZone.addEventListener("dragleave", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "#667eea";
    });
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "#667eea";
      const file = e.dataTransfer.files[0];
      if (file && file.type.startsWith("image/")) handleImageFile(file);
      else showToast("Please upload an image", "warning");
    });
  }
  if (screenshotInput)
    screenshotInput.addEventListener("change", (e) => {
      if (e.target.files[0]) handleImageFile(e.target.files[0]);
    });

  function handleImageFile(file) {
    if (file.size > 5 * 1024 * 1024)
      return showToast("File too large. Max 5MB", "warning");
    currentImageFile = file;
    const reader = new FileReader();
    reader.onload = (e) => {
      previewImage.src = e.target.result;
      previewDiv.style.display = "block";
    };
    reader.readAsDataURL(file);
  }

  if (analyzeScreenshotBtn) {
    analyzeScreenshotBtn.addEventListener("click", async () => {
      if (!currentImageFile) return;
      const spinner = document.getElementById("screenshotSpinner");
      const resultDiv = document.getElementById("screenshotResult");
      spinner.classList.add("show");
      resultDiv.classList.remove("show");
      try {
        const worker = await Tesseract.createWorker("eng");
        const {
          data: { text },
        } = await worker.recognize(currentImageFile);
        await worker.terminate();
        const res = await fetch("/api/detect-screenshot-text/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text }),
        });
        displayResult(
          await res.json(),
          "screenshotResult",
          "screenshotSpinner",
        );
        loadEnhancedStats();
      } catch (e) {
        resultDiv.innerHTML = `<div class="alert alert-danger">OCR failed: ${e.message}</div>`;
        resultDiv.classList.add("show");
      } finally {
        spinner.classList.remove("show");
      }
    });
  }

  // Manual Call Analysis
  const analyzeCallBtn = document.getElementById("analyzeCallBtn");
  if (analyzeCallBtn) {
    analyzeCallBtn.addEventListener("click", async () => {
      const transcript = document.getElementById("callTranscript").value;
      if (!transcript.trim()) {
        showToast("Please enter call transcript", "warning");
        return;
      }
      const spinner = document.getElementById("callSpinner");
      const resultDiv = document.getElementById("callResult");
      spinner.style.display = "flex";
      resultDiv.classList.remove("show");
      try {
        const formData = new FormData();
        formData.append("transcript", transcript);
        const res = await fetch("/api/detect-call/", {
          method: "POST",
          headers: { "X-CSRFToken": getCSRFToken() },
          credentials: "same-origin",
          body: formData,
        });
        const data = await res.json();
        displayCallResult(data, "callResult");
        loadEnhancedStats();
        showToast(
          data.score >= 50 ? "🚨 SCAM CALL DETECTED!" : "Analysis complete",
          data.score >= 50 ? "danger" : "success",
        );
      } catch (e) {
        showToast("Network error", "danger");
      } finally {
        spinner.style.display = "none";
      }
    });
  }

  // Phone Number Check
  const checkNumberBtn = document.getElementById("checkNumberBtn");
  if (checkNumberBtn) {
    checkNumberBtn.addEventListener("click", async () => {
      const phoneNumber = document.getElementById("callerNumber").value;
      if (!phoneNumber.trim()) {
        showToast("Please enter a phone number", "warning");
        return;
      }
      const resultDiv = document.getElementById("numberCheckResult");
      resultDiv.innerHTML =
        '<div class="spinner-border spinner-border-sm"></div> Checking...';
      try {
        const res = await fetch("/api/check-phone/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCSRFToken(),
          },
          body: JSON.stringify({ phone_number: phoneNumber }),
        });
        const data = await res.json();
        const riskColor =
          data.color === "danger"
            ? "#dc3545"
            : data.color === "warning"
              ? "#ffc107"
              : "#28a745";
        resultDiv.innerHTML = `<div class="card mt-2" style="border-left:3px solid ${riskColor}"><div class="card-body p-3">
                    <strong>📞 ${escapeHtml(data.phone || phoneNumber)}</strong><br>
                    <span class="badge bg-${data.color}">${escapeHtml(data.risk_level || "UNKNOWN")}</span><br>
                    ${escapeHtml(data.message || "")}
                    ${data.recommendation ? `<br><small>${escapeHtml(data.recommendation)}</small>` : ""}
                </div></div>`;
      } catch (e) {
        resultDiv.innerHTML = `<div class="alert alert-danger">Error</div>`;
      }
    });
  }

  // Example buttons
  document.querySelectorAll(".example-btn").forEach((btn) => {
    btn.addEventListener("click", () =>
      loadExample(btn.dataset.type, btn.dataset.example),
    );
  });

  // Tab buttons
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.tab) switchTab(btn.dataset.tab);
    });
  });

  // Initialize Real-Time Call Detection
  initRealtimeCallDetection();

  // Auto-refresh stats every 30s
  setInterval(() => {
    if (document.getElementById("statsTab")?.classList.contains("active"))
      loadEnhancedStats();
  }, 30000);
});

async function loadActivityFeed() {
  try {
    const response = await fetch("/api/recent-activity/");
    const data = await response.json();
    const feed = document.getElementById("activityFeed");
    if (feed && data.activities && data.activities.length > 0) {
      feed.innerHTML = data.activities.map(a => `
        <div class="activity-item d-flex align-items-center mb-2 p-2" style="border-left:3px solid ${a.color}">
          <span class="activity-icon">${a.icon}</span>
          <div style="flex:1"><small style="color:${a.color};font-weight:600">${a.type}</small>
          <div class="activity-preview">${escapeHtml(a.preview||'')}</div>
          <small class="activity-time">${a.time}</small></div>
          <span class="badge ${a.score>=70?'bg-danger':a.score>=40?'bg-warning':'bg-success'}">${a.score}%</span>
        </div>`).join('');
    } else {
      feed.innerHTML = '<div class="text-center text-muted py-4">No recent activity</div>';
    }
  } catch(e) { console.error('Activity feed error:', e); }
}

// Export for global access
window.exportReports = exportReports;
window.updateStatsInstant = updateStatsInstant;
window.switchTab = switchTab;
window.loadExample = loadExample;
