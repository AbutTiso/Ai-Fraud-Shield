// Get CSRF token from cookies (for Django backend)
function getCSRFToken() {
  return (
    document.cookie
      .split("; ")
      .find((row) => row.startsWith("csrftoken="))
      ?.split("=")[1] || ""
  );
}

// ============================================================
// SINGLE DOMContentLoaded - Handles everything
// ============================================================
document.addEventListener("DOMContentLoaded", function () {
  // Load dark mode setting
  chrome.storage.sync.get(["darkModeEnabled"], (settings) => {
    const darkModeToggle = document.getElementById("darkModeToggle");
    if (darkModeToggle) {
      darkModeToggle.checked = settings.darkModeEnabled || false;

      darkModeToggle.addEventListener("change", async (e) => {
        chrome.storage.sync.set({ darkModeEnabled: e.target.checked });
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });
        if (tab && tab.id) {
          chrome.tabs
            .sendMessage(tab.id, { action: "toggleDarkMode" })
            .catch(() => {});
        }
      });
    }
  });

  // Check page button
  document
    .getElementById("checkPageBtn")
    .addEventListener("click", async () => {
      const loading = document.getElementById("loading");
      const resultDiv = document.getElementById("result");

      loading.classList.add("show");
      resultDiv.classList.remove("show");

      try {
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });

        if (tab.url.startsWith("chrome://") || tab.url.startsWith("edge://")) {
          displayError("Cannot analyze browser internal pages");
          loading.classList.remove("show");
          return;
        }

        chrome.tabs.sendMessage(
          tab.id,
          { action: "analyzePage" },
          async (response) => {
            if (chrome.runtime.lastError) {
              displayError("Please refresh the page and try again");
              loading.classList.remove("show");
              return;
            }

            if (response && response.content) {
              try {
                const analysis = await analyzeWithBackend(
                  response.content,
                  response.url,
                );
                displayResult(analysis);
              } catch (error) {
                const fallbackAnalysis = analyzeLocally(
                  response.content,
                  response.url,
                );
                displayResult(fallbackAnalysis, true);
              }
            } else {
              displayError("Could not extract page content");
            }
            loading.classList.remove("show");
          },
        );
      } catch (error) {
        displayError("Error analyzing page.");
        loading.classList.remove("show");
      }
    });

  // Show current page risk score when popup opens
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (tabs[0]) {
      chrome.tabs.sendMessage(
        tabs[0].id,
        { action: "getRiskScore" },
        function (response) {
          if (response && response.score !== undefined) {
            const resultDiv = document.getElementById("result");
            const riskColor =
              response.score >= 50
                ? "#dc3545"
                : response.score >= 25
                  ? "#f5a623"
                  : "#10b981";
            const emoji = response.isScam
              ? "🚨"
              : response.score >= 25
                ? "⚠️"
                : "✅";
            resultDiv.innerHTML = `
                        <div style="padding:10px;border-left:3px solid ${riskColor};background:white;border-radius:6px;">
                            <strong>${emoji} Page Risk: ${response.score}/100</strong>
                            <small style="color:#6b7280;display:block;">Click "Check Page" for details</small>
                        </div>
                    `;
          }
        },
      );
    }
  });
});

// ============================================================
// ANALYSIS FUNCTIONS
// ============================================================

async function analyzeWithBackend(content, url) {
  const response = await fetch("http://localhost:8000/api/detect-web/", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": getCSRFToken(),
    },
    credentials: "include",
    body: JSON.stringify({
      url: url,
      content: content.text,
      links: content.links,
      forms: content.forms,
      title: content.title,
    }),
  });

  if (!response.ok) throw new Error("Backend analysis failed");
  return await response.json();
}

function analyzeLocally(content, url) {
  const scamKeywords = [
    "urgent",
    "verify",
    "account suspended",
    "win",
    "prize",
    "click here",
    "send money",
    "mpesa",
    "congratulations",
    "limited time",
    "act now",
    "verify your account",
  ];

  let score = 0;
  let reasons = [];
  const text = content.text.toLowerCase();

  scamKeywords.forEach((keyword) => {
    if (text.includes(keyword)) {
      score += 15;
      reasons.push(`⚠️ Found: "${keyword}"`);
    }
  });

  const suspiciousUrls = content.links.filter(
    (link) =>
      link.includes("secure-") ||
      link.includes("verify-") ||
      link.includes("login-"),
  );
  if (suspiciousUrls.length > 0) {
    score += 20;
    reasons.push(`🔗 ${suspiciousUrls.length} suspicious link(s)`);
  }
  if (content.forms > 0 && score > 30) {
    score += 10;
    reasons.push(`📝 Page has forms`);
  }

  score = Math.min(score, 100);

  return {
    score: score,
    risk_level:
      score >= 60 ? "HIGH RISK" : score >= 30 ? "MEDIUM RISK" : "LOW RISK",
    color: score >= 60 ? "danger" : score >= 30 ? "warning" : "success",
    emoji: score >= 60 ? "🔴" : score >= 30 ? "⚠️" : "✅",
    message: `Analysis of: ${content.title?.substring(0, 50) || "Page"}`,
    reasons: reasons.length ? reasons : ["✅ No scam indicators found"],
    warnings: reasons,
  };
}

function displayResult(data, isLocal = false) {
  const resultDiv = document.getElementById("result");
  const riskColor =
    data.color === "danger"
      ? "#dc3545"
      : data.color === "warning"
        ? "#f5a623"
        : "#10b981";

  let reasonsHtml = '<ul style="margin:10px 0 0 20px;">';
  (data.reasons || data.warnings || []).slice(0, 5).forEach((r) => {
    reasonsHtml += `<li style="margin:5px 0;">${r}</li>`;
  });
  reasonsHtml += "</ul>";

  const localNote = isLocal
    ? '<div style="background:#fef3d5;padding:5px 10px;border-radius:6px;margin-bottom:8px;font-size:11px;">📡 Local analysis (offline mode)</div>'
    : "";

  resultDiv.innerHTML = `
        ${localNote}
        <div style="display:flex;align-items:center;justify-content:space-between;">
            <strong>${data.emoji} ${data.risk_level}</strong>
            <span style="font-size:18px;font-weight:700;color:${riskColor};">${data.score}/100</span>
        </div>
        <div style="background:#e5e7eb;border-radius:4px;height:8px;margin:10px 0;">
            <div style="background:${riskColor};width:${data.score}%;height:8px;border-radius:4px;"></div>
        </div>
        <p style="font-size:13px;">${data.message}</p>
        ${reasonsHtml}
        <hr>
        <small style="color:#666;display:block;text-align:center;">⚠️ Never share passwords, PINs, or send money to unknown sites</small>
    `;
  resultDiv.classList.add("show");
}

function displayError(message) {
  const resultDiv = document.getElementById("result");
  resultDiv.innerHTML = `
        <strong style="color:#dc3545;">⚠️ Error</strong><br>
        ${message}<br><br>
        <small>• Make sure you're on a regular webpage<br>• Try refreshing the page</small>
    `;
  resultDiv.classList.add("show");
}
