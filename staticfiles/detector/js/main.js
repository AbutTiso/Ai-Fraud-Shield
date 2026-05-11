// detector/static/detector/js/main.js - COMPLETE UPDATED VERSION

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

// Chart instances
let scamTypeChart = null;
let riskDistributionChart = null;
let trendChart = null;

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
            <div class="toast-body">
                ${message}
            </div>
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

// Export reports as CSV
async function exportReports() {
  try {
    showToast("📥 Preparing export...", "info");
    const response = await fetch("/api/export/", {
      headers: {
        "X-CSRFToken": getCSRFToken(),
      },
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
  document.querySelectorAll(".tab-content").forEach((tab) => {
    tab.classList.remove("active");
  });

  const activeTab = document.getElementById(`${tabName}Tab`);
  if (activeTab) {
    activeTab.classList.add("active");
  }

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.remove("active");
    if (btn.getAttribute("data-tab") === tabName) {
      btn.classList.add("active");
    }
  });

  if (tabName === "stats") {
    setTimeout(() => {
      loadStats();
      loadActivityFeed();
      refreshCharts();
    }, 100);
  }
}

// Refresh charts (resize/update)
function refreshCharts() {
  if (scamTypeChart) scamTypeChart.update();
  if (riskDistributionChart) riskDistributionChart.update();
  if (trendChart) trendChart.update();
}

// Create Scam Type Pie Chart
function createScamTypeChart(stats) {
  const ctx = document.getElementById("scamTypeChart");
  if (!ctx) return;

  if (scamTypeChart) scamTypeChart.destroy();

  scamTypeChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: ["SMS", "Email", "WhatsApp", "Phone Calls", "URLs", "Telegram"],
      datasets: [
        {
          data: [
            stats.sms_count || 0,
            stats.email_count || 0,
            stats.whatsapp_count || 0,
            stats.call_count || 0,
            stats.url_count || 0,
            stats.telegram_count || 0 
          ],
          backgroundColor: [
            "#3b82f6",
            "#ef4444",
            "#10b981",
            "#f59e0b",
            "#8b5cf6",
            '#0088cc',
          ],
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { position: "bottom", labels: { color: "#f3f4f6" } },
      },
    },
  });
}

// Create Risk Distribution Bar Chart
function createRiskChart(stats) {
  const ctx = document.getElementById("riskDistributionChart");
  if (!ctx) return;

  if (riskDistributionChart) riskDistributionChart.destroy();

  riskDistributionChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["High Risk (70-100)", "Medium Risk (40-69)", "Low Risk (0-39)"],
      datasets: [
        {
          label: "Number of Reports",
          data: [
            stats.high_risk_count || 0,
            stats.medium_risk_count || 0,
            stats.low_risk_count || 0,
          ],
          backgroundColor: ["#ef4444", "#f59e0b", "#10b981"],
          borderRadius: 8,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      scales: {
        y: {
          beginAtZero: true,
          ticks: { color: "#9ca3af" },
          grid: { color: "#374151" },
        },
        x: { ticks: { color: "#9ca3af" }, grid: { color: "#374151" } },
      },
      plugins: {
        legend: { labels: { color: "#f3f4f6" } },
      },
    },
  });
}

// Create Weekly Trend Line Chart
function createTrendChart(stats) {
  const ctx = document.getElementById("trendChart");
  if (!ctx) return;

  if (trendChart) trendChart.destroy();

  trendChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: stats.weekly_labels || [
        "Mon",
        "Tue",
        "Wed",
        "Thu",
        "Fri",
        "Sat",
        "Sun",
      ],
      datasets: [
        {
          label: "Scam Reports",
          data: stats.weekly_trend || [0, 0, 0, 0, 0, 0, 0],
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59, 130, 246, 0.1)",
          tension: 0.4,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { labels: { color: "#f3f4f6" } },
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: { color: "#9ca3af" },
          grid: { color: "#374151" },
        },
        x: { ticks: { color: "#9ca3af" }, grid: { color: "#374151" } },
      },
    },
  });
}

// Update all charts with new data
function updateCharts(stats) {
  if (scamTypeChart) {
    scamTypeChart.data.datasets[0].data = [
      stats.sms_count || 0,
      stats.email_count || 0,
      stats.whatsapp_count || 0,
      stats.call_count || 0,
      stats.url_count || 0,
      stats.telegram_count || 0,
    ];
    scamTypeChart.update();
  } else {
    createScamTypeChart(stats);
  }

  if (riskDistributionChart) {
    riskDistributionChart.data.datasets[0].data = [
      stats.high_risk_count || 0,
      stats.medium_risk_count || 0,
      stats.low_risk_count || 0,
    ];
    riskDistributionChart.update();
  } else {
    createRiskChart(stats);
  }

  if (trendChart) {
    trendChart.data.datasets[0].data = stats.weekly_trend || [
      0, 0, 0, 0, 0, 0, 0,
    ];
    if (stats.weekly_labels) trendChart.data.labels = stats.weekly_labels;
    trendChart.update();
  } else {
    createTrendChart(stats);
  }
}

// Update recent scams table
function updateRecentScamsTable(recentScams) {
  const tbody = document.getElementById("recentScamsBody");
  if (!tbody) return;

  if (!recentScams || recentScams.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="5" class="text-center">No scam reports yet</td></tr>';
    return;
  }

  tbody.innerHTML = recentScams
    .map(
      (scam) => `
        <tr>
            <td>${escapeHtml(scam.date || "")}</td>
            <td><span class="badge bg-secondary">${escapeHtml(scam.type || "Unknown")}</span></td>
            <td>${escapeHtml(scam.preview || scam.content || "No content").substring(0, 80)}${(scam.preview || scam.content || "").length > 80 ? "..." : ""}</td>
            <td><span class="badge ${getRiskBadgeClass(scam.score)}">${scam.score || 0}</span></td>
            <td><span class="badge ${getRiskLevelClass(scam.level)}">${scam.level || "Unknown"}</span></td>
        </tr>
    `,
    )
    .join("");
}

function getRiskBadgeClass(score) {
  if (score >= 70) return "bg-danger";
  if (score >= 40) return "bg-warning text-dark";
  return "bg-success";
}

function getRiskLevelClass(level) {
  if (level === "HIGH") return "bg-danger";
  if (level === "MEDIUM") return "bg-warning text-dark";
  return "bg-success";
}

// Load statistics (ENHANCED VERSION)
async function loadStats() {
  try {
    const response = await fetch("/api/stats/", {
      headers: {
        "X-CSRFToken": getCSRFToken(),
      },
      credentials: "same-origin",
    });
    const data = await response.json();

    // Check if we have the new stats structure (with success and stats objects)
    let stats;
    if (data.success && data.stats) {
      stats = data.stats;
    } else if (data.status === "success") {
      // Old format fallback
      stats = data;
    } else {
      stats = data;
    }

    // Update stats cards on main page (top row)
    const totalReportsEl = document.getElementById("totalReports");
    if (totalReportsEl) totalReportsEl.textContent = stats.total_reports || 0;

    const highRiskEl = document.getElementById("highRisk");
    if (highRiskEl) highRiskEl.textContent = stats.high_risk_count || 0;

    const smsCountEl = document.getElementById("smsCount");
    if (smsCountEl) smsCountEl.textContent = stats.sms_count || 0;

    const emailCountEl = document.getElementById("emailCount");
    if (emailCountEl) emailCountEl.textContent = stats.email_count || 0;

    const whatsappCountEl = document.getElementById("whatsappCount");
    if (whatsappCountEl)
      whatsappCountEl.textContent = stats.whatsapp_count || 0;

    const callCountEl = document.getElementById("callCount");
    if (callCountEl) callCountEl.textContent = stats.call_count || 0;

    const telegramCountEl = document.getElementById("telegramCount");
    if (telegramCountEl)
      telegramCountEl.textContent = stats.telegram_count || 0;

    const avgRiskScoreEl = document.getElementById("avgRiskScore");
    if (avgRiskScoreEl)
      avgRiskScoreEl.textContent = stats.average_risk_score || 0;

    // Update stats tab (Dashboard tab) cards
    const statTotalReports = document.getElementById("statTotalReports");
    if (statTotalReports)
      statTotalReports.textContent = stats.total_reports || 0;

    const statHighRisk = document.getElementById("statHighRisk");
    if (statHighRisk) statHighRisk.textContent = stats.high_risk_count || 0;

    const statAvgScore = document.getElementById("statAvgScore");
    if (statAvgScore) statAvgScore.textContent = stats.average_risk_score || 0;

    // Update recent scams list on main page (old location)
    const recentDiv = document.getElementById("recentScams");
    if (recentDiv) {
      const recentScams = stats.recent_scams || [];
      if (recentScams.length === 0) {
        recentDiv.innerHTML =
          '<p class="text-muted">No reports yet. Start detecting scams!</p>';
      } else {
        recentDiv.innerHTML = recentScams
          .map(
            (scam) => `
                    <div class="scam-item">
                        <strong>[${escapeHtml(scam.type)}]</strong> 
                        <span class="badge ${scam.score >= 70 ? "bg-danger" : scam.score >= 40 ? "bg-warning" : "bg-success"}">
                            Score: ${scam.score}/100
                        </span><br>
                        <small>${escapeHtml(scam.date)}</small><br>
                        <small class="text-muted">${escapeHtml((scam.preview || scam.content || "No content").substring(0, 80))}...</small>
                    </div>
                `,
          )
          .join("");
      }
    }

    // Update recent scams table (in Dashboard tab)
    if (stats.recent_scams) {
      updateRecentScamsTable(stats.recent_scams);
    }

        // Update charts
    updateCharts(stats);
    
    // Trigger enhanced dashboard charts (in dashboard.js)
    if (typeof updateEnhancedStats === 'function') {
        updateEnhancedStats(stats);
    }
  } catch (error) {
    console.error("Error loading stats:", error);
    const recentDiv = document.getElementById("recentScams");
    if (recentDiv) {
      recentDiv.innerHTML =
        '<p class="text-danger">Error loading statistics. Make sure the server is running.</p>';
    }
  }
}




function escapeHtml(text) {
  if (!text) return "";
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Enhanced Email Result Display (Shows links as NON-clickable text)
function displayEmailResult(data, resultDivId) {
  const resultDiv = document.getElementById(resultDivId);

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
      '<h6 class="mt-3">🔗 Links Found in This Email (Analyzed as TEXT - NOT Clickable):</h6>';
    urlHtml +=
      '<div class="alert alert-secondary" style="font-size: 0.85rem; background: #f8f9fa;">';
    urlHtml +=
      "<strong>⚠️ Important:</strong> These links are shown as PLAIN TEXT for your safety. ";
    urlHtml +=
      "Do NOT type them into your browser unless you are 100% sure they are safe.<br><br>";

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
                    <div class="url-text-display">
                        <strong>URL (TEXT only - not clickable):</strong><br>
                        <span style="color: #666;">${escapeHtml(url.url)}</span>
                    </div>
                    <div style="margin-top: 5px;"><strong>Domain:</strong> ${escapeHtml(url.domain)}</div>
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
    recommendationsHtml = '<h6 class="mt-3">💡 What To Do:</h6>';
    recommendationsHtml +=
      '<div style="background: #f8f9fa; padding: 12px; border-radius: 8px;">';
    data.recommendations.forEach((rec) => {
      recommendationsHtml += `<div style="margin-bottom: 8px;">✓ ${escapeHtml(rec)}</div>`;
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
                <small style="color: #856404;">
                    <strong>⚠️ REMEMBER:</strong> The links above are shown as TEXT only. 
                    Do NOT copy them into your browser unless you have verified they are safe. 
                    Legitimate companies will never ask for your PIN, password, or M-Pesa code via email.
                </small>
            </div>
        </div>
    `;

  resultDiv.classList.add("show");
  resultDiv.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Display SMS/URL/General results
function displayGeneralResult(data, resultDivId) {
  const resultDiv = document.getElementById(resultDivId);

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
                    <div class="alert alert-secondary">
                        <strong>🌐 Domain:</strong><br>
                        <code>${escapeHtml(data.domain || "Unknown")}</code>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="alert ${data.has_https ? "alert-success" : "alert-warning"}">
                        <strong>🔒 HTTPS:</strong><br>
                        ${data.has_https ? "✅ Secure connection" : "⚠️ Not using HTTPS (insecure)"}
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
                ? `
            <div class="risk-score">Risk Score: <span style="color: ${headerClass === "danger" ? "#dc3545" : headerClass === "warning" ? "#ffc107" : "#28a745"};">${data.score}</span> / 100</div>
            <div class="progress risk-progress"><div class="progress-bar bg-${headerClass}" style="width: ${data.score}%;"></div></div>
            `
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

  const scorePercent = data.score;
  let headerClass = "success";
  if (scorePercent >= 50) headerClass = "danger";
  else if (scorePercent >= 25) headerClass = "warning";

  let suspiciousHtml = "";
  if (data.suspicious_messages && data.suspicious_messages.length > 0) {
    suspiciousHtml = `
            <div class="mt-3">
                <strong>Suspicious messages detected:</strong>
                <ul class="mt-2">
                    ${data.suspicious_messages.map((msg) => `<li class="text-danger">"${escapeHtml(msg)}..."</li>`).join("")}
                </ul>
            </div>
        `;
  }

  const reasonsHtml = data.reasons
    ? data.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")
    : "<li>No specific indicators found</li>";

  resultDiv.innerHTML = `
        <div class="result-header ${data.color || headerClass}">
            <h3>${data.emoji} ${data.risk_level}</h3>
            <div class="score-circle">
                <div class="score-value">${scorePercent}%</div>
                <div class="score-label">Risk Score</div>
            </div>
        </div>
        <div class="result-body">
            <div class="alert alert-${data.color === "danger" ? "danger" : data.color === "warning" ? "warning" : "success"}">
                <strong>${escapeHtml(data.message)}</strong>
            </div>
            
            ${data.recommendation ? `<div class="alert alert-info"><strong>Recommendation:</strong> ${escapeHtml(data.recommendation)}</div>` : ""}
            
            <div class="row mb-3">
                <div class="col-md-6">
                    <strong>📊 Statistics:</strong>
                    <ul class="mt-2">
                        <li>Messages analyzed: ${data.message_count || 0}</li>
                        <li>Unique senders: ${data.unique_senders || "N/A"}</li>
                        ${data.grammar_issues ? `<li>Grammar issues: ${data.grammar_issues}</li>` : ""}
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

  resultDiv.classList.add("show");
  resultDiv.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Unified display result function
function displayResult(data, resultDivId, spinnerId) {
  const resultDiv = document.getElementById(resultDivId);
  const spinner = document.getElementById(spinnerId);

  if (spinner) spinner.classList.remove("show");

  if (!data || data.error) {
    resultDiv.innerHTML = `
            <div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 10px;">
                <h3>⚠️ Error</h3>
                <p>${escapeHtml(data?.error || "An error occurred during analysis")}</p>
            </div>
        `;
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

// Load example texts
function loadExample(type, exampleType) {
  const examples = {
    sms: {
      scam: "URGENT: Your M-Pesa account has been suspended due to suspicious activity. Click http://mpesa-update.co.ke to verify your details immediately or your account will be deactivated.",
      prize:
        "CONGRATULATIONS! You have won Ksh 250,000 in our Safaricom promotion. Click https://bit.ly/claim-prize to claim your prize now!",
      safe: "Safaricom: Your M-Pesa transaction of Ksh 500 to John Mwangi on 25/04/2026 was successful. New balance: Ksh 2,450. Thank you for using M-Pesa.",
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
    scam: 'URGENT: Your M-Pesa account has been suspended. Send your PIN to 0712345678 immediately to verify and restore access.',
    prize: 'CONGRATULATIONS! You have been selected as winner of our Telegram promotion! Send Ksh 500 to claim your iPhone 15 Pro.',
    safe: 'Hey, are we still meeting for lunch at 1pm? Let me know if you can make it.',
},
  };

  const textarea = document.getElementById(`${type}Text`);
  if (textarea && examples[type] && examples[type][exampleType]) {
    textarea.value = examples[type][exampleType];
    const resultDiv = document.getElementById(`${type}Result`);
    if (resultDiv) resultDiv.classList.remove("show");
  }
}

// Initialize all event listeners when DOM is ready
document.addEventListener("DOMContentLoaded", function () {
  // SMS Form Handler
  const smsForm = document.getElementById("smsForm");
  if (smsForm) {
    smsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const smsText = document.getElementById("smsText").value;
      if (!smsText.trim()) {
        showToast("Please enter SMS text to analyze", "warning");
        return;
      }

      const spinner = document.getElementById("smsSpinner");
      const analyzeBtn = e.target.querySelector(".btn-analyze");

      spinner.classList.add("show");
      analyzeBtn.disabled = true;
      document.getElementById("smsResult").classList.remove("show");

      try {
        const formData = new FormData();
        formData.append("sms_text", smsText);

        const response = await fetch("/api/detect-sms/", {
          method: "POST",
          headers: {
            "X-CSRFToken": getCSRFToken(),
            "X-Requested-With": "XMLHttpRequest",
          },
          credentials: "same-origin",
          body: formData,
        });

        const data = await response.json();
        displayResult(data, "smsResult", "smsSpinner");
        loadStats();
      } catch (error) {
        console.error("Error:", error);
        showToast(
          "Network error. Please check if the server is running.",
          "danger",
        );
      } finally {
        spinner.classList.remove("show");
        analyzeBtn.disabled = false;
      }
    });
  }

  // Email Form Handler
  const emailForm = document.getElementById("emailForm");
  if (emailForm) {
    emailForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const emailText = document.getElementById("emailText").value;
      if (!emailText.trim()) {
        showToast("Please enter email content to analyze", "warning");
        return;
      }

      const spinner = document.getElementById("emailSpinner");
      const analyzeBtn = e.target.querySelector(".btn-analyze");

      spinner.classList.add("show");
      analyzeBtn.disabled = true;
      document.getElementById("emailResult").classList.remove("show");

      try {
        const formData = new FormData();
        formData.append("email_text", emailText);

        const response = await fetch("/api/detect-email/", {
          method: "POST",
          headers: {
            "X-CSRFToken": getCSRFToken(),
            "X-Requested-With": "XMLHttpRequest",
          },
          credentials: "same-origin",
          body: formData,
        });

        const data = await response.json();
        displayResult(data, "emailResult", "emailSpinner");
        loadStats();
        showToast(
          "✅ Email analyzed safely - no links were clicked!",
          "success",
        );
      } catch (error) {
        console.error("Error:", error);
        showToast(
          "Network error. Please check if the server is running.",
          "danger",
        );
      } finally {
        spinner.classList.remove("show");
        analyzeBtn.disabled = false;
      }
    });
  }

  // WhatsApp Form Handler
  const whatsappForm = document.getElementById("whatsappForm");
  if (whatsappForm) {
    whatsappForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const chatText = document.getElementById("whatsappText").value;
      if (!chatText.trim()) {
        showToast("Please paste WhatsApp chat content", "warning");
        return;
      }

      const spinner = document.getElementById("whatsappSpinner");
      const analyzeBtn = e.target.querySelector(".btn-analyze");

      spinner.classList.add("show");
      analyzeBtn.disabled = true;
      document.getElementById("whatsappResult").classList.remove("show");

      const formData = new FormData();
      formData.append("chat_text", chatText);

      try {
        const response = await fetch("/api/detect-whatsapp/", {
          method: "POST",
          headers: {
            "X-CSRFToken": getCSRFToken(),
            "X-Requested-With": "XMLHttpRequest",
          },
          credentials: "same-origin",
          body: formData,
        });

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`Server error: ${response.status}`);
        }

        const data = await response.json();
        displayResult(data, "whatsappResult", "whatsappSpinner");
        loadStats();
        showToast("✅ Analysis complete!", "success");
      } catch (error) {
        console.error("Error:", error);
        showToast(error.message, "danger");
        document.getElementById("whatsappResult").innerHTML = `
                    <div class="alert alert-danger">
                        <strong>❌ Error:</strong> ${escapeHtml(error.message)}<br>
                        <small>Please check that you've pasted valid WhatsApp chat content and the server is running.</small>
                    </div>
                `;
        document.getElementById("whatsappResult").classList.add("show");
      } finally {
        spinner.classList.remove("show");
        analyzeBtn.disabled = false;
      }
    });
  }

  // URL Checker Handler
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
        const response = await fetch("/api/check-url/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCSRFToken(),
          },
          body: JSON.stringify({ url: url }),
        });

        const data = await response.json();
        displayResult(data, "urlResult", "urlSpinner");
        loadStats();
      } catch (error) {
        showToast("Network error: " + error.message, "danger");
        spinner.classList.remove("show");
      } finally {
        spinner.classList.remove("show");
      }
    });
  }

  
// Telegram Form Handler
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
        const analyzeBtn = e.target.querySelector('.btn-analyze');
        
        spinner.classList.add('show');
        analyzeBtn.disabled = true;
        document.getElementById('telegramResult').classList.remove('show');
        
        try {
            const formData = new FormData();
            formData.append('telegram_text', telegramText);
            
            const response = await fetch('/api/detect-telegram/', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': getCSRFToken(),
                    'X-Requested-With': 'XMLHttpRequest',
                },
                credentials: 'same-origin',
                body: formData
            });
            
            const data = await response.json();
            displayResult(data, 'telegramResult', 'telegramSpinner');
            loadStats();
        } catch (error) {
            showToast('Network error', 'danger');
        } finally {
            spinner.classList.remove('show');
            analyzeBtn.disabled = false;
        }
    });
}

  // Screenshot OCR Handler
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
      dropZone.style.backgroundColor = "#f0f0ff";
    });

    dropZone.addEventListener("dragleave", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "#667eea";
      dropZone.style.backgroundColor = "transparent";
    });

    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "#667eea";
      dropZone.style.backgroundColor = "transparent";
      const file = e.dataTransfer.files[0];
      if (file && file.type.startsWith("image/")) {
        handleImageFile(file);
      } else {
        showToast("Please upload an image file", "warning");
      }
    });
  }

  if (screenshotInput) {
    screenshotInput.addEventListener("change", (e) => {
      if (e.target.files[0]) handleImageFile(e.target.files[0]);
    });
  }

  function handleImageFile(file) {
    if (file.size > 5 * 1024 * 1024) {
      showToast("File too large. Maximum 5MB", "warning");
      return;
    }
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
        // Check if Tesseract is loaded
        if (typeof Tesseract === "undefined") {
          throw new Error(
            "Tesseract OCR library not loaded. Please refresh the page.",
          );
        }

        const worker = await Tesseract.createWorker("eng");
        const {
          data: { text },
        } = await worker.recognize(currentImageFile);
        await worker.terminate();

        const response = await fetch("/api/detect-screenshot-text/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: text }),
        });

        const data = await response.json();
        displayResult(data, "screenshotResult", "screenshotSpinner");
        loadStats();
      } catch (error) {
        console.error("OCR Error:", error);
        resultDiv.innerHTML = `<div class="alert alert-danger">OCR failed: ${error.message}</div>`;
        resultDiv.classList.add("show");
        spinner.classList.remove("show");
      } finally {
        spinner.classList.remove("show");
      }
    });
  }

  // Example buttons handler
  document.querySelectorAll(".example-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const type = btn.getAttribute("data-type");
      const example = btn.getAttribute("data-example");
      if (type && example) {
        loadExample(type, example);
      }
    });
  });

  // Tab buttons handler
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tabName = btn.getAttribute("data-tab");
      if (tabName) {
        switchTab(tabName);
      }
    });
  });

  // Call Monitor Functionality
  const startCallMonitorBtn = document.getElementById("startCallMonitorBtn");
  const stopCallMonitorBtn = document.getElementById("stopCallMonitorBtn");
  const monitorStatus = document.getElementById("monitorStatus");
  const realtimeAlerts = document.getElementById("realtimeAlerts");
  const dangerAlert = document.getElementById("dangerAlert");
  const liveTranscriptContainer = document.getElementById(
    "liveTranscriptContainer",
  );

  let recognition = null;
  let isMonitoring = false;

  if (startCallMonitorBtn && "webkitSpeechRecognition" in window) {
    recognition = new webkitSpeechRecognition();
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.lang = "en-US";

    recognition.onstart = () => {
      isMonitoring = true;
      monitorStatus.innerHTML =
        '<span class="badge bg-success">🔴 LIVE - Monitoring in progress</span>';
      startCallMonitorBtn.disabled = true;
      stopCallMonitorBtn.disabled = false;
      if (realtimeAlerts)
        realtimeAlerts.innerHTML =
          '<div class="text-success">🎤 Listening... Speak during the call.</div>';
    };

    recognition.onerror = (event) => {
      console.error("Recognition error:", event.error);
      if (realtimeAlerts)
        realtimeAlerts.innerHTML = `<div class="text-danger">Error: ${event.error}</div>`;
    };

    recognition.onend = () => {
      if (isMonitoring) {
        isMonitoring = false;
        monitorStatus.innerHTML =
          '<span class="badge bg-secondary">⚪ Not monitoring</span>';
        startCallMonitorBtn.disabled = false;
        stopCallMonitorBtn.disabled = true;
      }
    };

    recognition.onresult = (event) => {
      let interimTranscript = "";
      let finalTranscript = "";

      for (let i = event.resultIndex; i < event.results.length; i++) {
        const transcript = event.results[i][0].transcript;
        if (event.results[i].isFinal) {
          finalTranscript += transcript;
        } else {
          interimTranscript += transcript;
        }
      }

      if (finalTranscript) {
        // Show live transcript
        if (liveTranscriptContainer) {
          liveTranscriptContainer.innerHTML = `
                        <div class="alert alert-info mt-2">
                            <small><i class="fas fa-microphone-alt"></i> Live: ${escapeHtml(finalTranscript)}</small>
                        </div>
                    `;
        }
        analyzeTranscriptForScams(finalTranscript);
      }
    };

    startCallMonitorBtn.addEventListener("click", () => {
      try {
        recognition.start();
      } catch (e) {
        console.error("Start error:", e);
      }
    });

    stopCallMonitorBtn.addEventListener("click", () => {
      if (recognition) {
        recognition.stop();
        isMonitoring = false;
        monitorStatus.innerHTML =
          '<span class="badge bg-secondary">⚪ Monitoring stopped</span>';
        startCallMonitorBtn.disabled = false;
        stopCallMonitorBtn.disabled = true;
        if (liveTranscriptContainer) liveTranscriptContainer.innerHTML = "";
      }
    });
  } else if (startCallMonitorBtn) {
    startCallMonitorBtn.disabled = true;
    startCallMonitorBtn.title =
      "Speech recognition not supported in this browser";
    if (monitorStatus)
      monitorStatus.innerHTML =
        '<span class="badge bg-warning">⚠️ Not supported in this browser. Use Chrome for call monitoring.</span>';
  }

  async function analyzeTranscriptForScams(transcript) {
    const lowerText = transcript.toLowerCase();
    let isScam = false;
    let alertMessage = "";

    const scamPatterns = [
      {
        pattern: /pin|mpin|password|otp|code/,
        message: "❌ Asking for PIN/Password - HANG UP!",
      },
      {
        pattern: /send money|tuma pesa/,
        message: "💰 Requesting money - Scam!",
      },
      {
        pattern: /suspended|blocked|locked/,
        message: "🚫 Account suspension threat - Scam tactic!",
      },
      {
        pattern: /urgent|immediately|asap/,
        message: "⏰ Urgency pressure - Classic scam!",
      },
      {
        pattern: /mpesa|safaricom|bank/,
        message: "🏦 Impersonating company - Verify!",
      },
      {
        pattern: /verify|confirm|update/,
        message: "🔐 Verification scam - Don't share info!",
      },
      {
        pattern: /winner|prize|congratulations/,
        message: "🎁 Prize scam - You didn't win anything!",
      },
      {
        pattern: /limited time|offer ends/,
        message: "⏳ Time pressure - Scare tactic!",
      },
    ];

    for (const pattern of scamPatterns) {
      if (pattern.pattern.test(lowerText)) {
        isScam = true;
        alertMessage = pattern.message;
        break;
      }
    }

    if (isScam) {
      if (dangerAlert) dangerAlert.style.display = "block";
      if (realtimeAlerts) {
        realtimeAlerts.innerHTML = `<div class="alert alert-danger mt-2"><strong>⚠️ SCAM ALERT!</strong> ${alertMessage}</div>`;
      }
      if (monitorStatus)
        monitorStatus.innerHTML =
          '<span class="badge bg-danger">🔴 SCAM DETECTED - HANG UP!</span>';
    } else {
      if (dangerAlert) dangerAlert.style.display = "none";
      if (realtimeAlerts) {
        realtimeAlerts.innerHTML = `<div class="alert alert-success mt-2"><strong>✅ No scam patterns detected</strong> - Stay vigilant.</div>`;
      }
    }
  }

  const checkNumberBtn = document.getElementById("checkNumberBtn");
  const callerNumber = document.getElementById("callerNumber");
  const numberCheckResult = document.getElementById("numberCheckResult");

  if (checkNumberBtn) {
    checkNumberBtn.addEventListener("click", async () => {
      const number = callerNumber.value.trim();
      if (!number) {
        showToast("Please enter a phone number", "warning");
        return;
      }

      numberCheckResult.innerHTML =
        '<div class="spinner-border text-primary spinner-border-sm"></div> Checking...';

      try {
        const response = await fetch("/api/check-phone/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCSRFToken(),
          },
          body: JSON.stringify({ phone_number: number }),
        });
        const data = await response.json();

        if (data.is_known_scam) {
          numberCheckResult.innerHTML = `
                        <div class="alert alert-danger mt-2">
                            <strong>⚠️ SCAM NUMBER!</strong><br>
                            Risk Score: ${data.risk_score}%<br>
                            Reports: ${data.reports_count}<br>
                            <strong>DO NOT ANSWER OR CALL BACK!</strong>
                        </div>
                    `;
        } else if (data.risk_score > 30) {
          numberCheckResult.innerHTML = `
                        <div class="alert alert-warning mt-2">
                            <strong>⚠️ Suspicious Number</strong><br>
                            Risk Score: ${data.risk_score}%<br>
                            Reports: ${data.reports_count}<br>
                            Exercise caution.
                        </div>
                    `;
        } else {
          numberCheckResult.innerHTML = `
                        <div class="alert alert-success mt-2">
                            <strong>✅ Number appears safe</strong><br>
                            Risk Score: ${data.risk_score || 0}%<br>
                            Reports: ${data.reports_count || 0}
                        </div>
                    `;
        }
      } catch (error) {
        numberCheckResult.innerHTML = `<div class="alert alert-danger mt-2">Error checking number. Please try again.</div>`;
      }
    });
  }

  // Load stats on page load
  loadStats();

  // Auto-refresh stats every 30 seconds
  setInterval(() => {
    const statsTab = document.getElementById("statsTab");
    if (statsTab && statsTab.classList.contains("active")) {
      loadStats();
    }
  }, 30000);
});

async function loadActivityFeed() {
  try {
    const response = await fetch("/api/recent-activity/");
    const data = await response.json();
    const feed = document.getElementById("activityFeed");
    if (feed && data.activities && data.activities.length > 0) {
      feed.innerHTML = data.activities
        .map(
          (a) => `
                <div class="activity-item d-flex align-items-center mb-2 p-2" style="border-left: 3px solid ${a.color}; border-radius: 4px;">
                    <span class="activity-icon">${a.icon}</span>
                    <div style="flex: 1;">
                        <small style="color: ${a.color}; font-weight: 600;">${a.type}</small>
                        <div class="activity-preview">${a.preview}</div>
                        <small class="activity-time">${a.time}</small>
                    </div>
                    <span class="badge ${a.score >= 70 ? "bg-danger" : a.score >= 40 ? "bg-warning" : "bg-success"}">${a.score}%</span>
                </div>
            `,
        )
        .join("");
    } else {
      feed.innerHTML =
        '<div class="text-center text-muted py-4">No recent activity</div>';
    }
  } catch (e) {
    console.error("Activity feed error:", e);
  }
}
// Make functions globally available
window.exportReports = exportReports;
window.refreshStats = loadStats;
