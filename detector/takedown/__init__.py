{% extends 'base.html' %}
{% block title %}Corporate Shield - AI Fraud Shield{% endblock %}
{% block extra_css %}
<style>
  body { background: linear-gradient(135deg, #002855, #001a3f); }
  .corp-container { max-width: 1400px; margin: 20px auto; padding: 20px; color: white; }
  .corp-header { text-align: center; margin-bottom: 30px; }
  .corp-header h2 { color: #f5a623; }
  .corp-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
  .corp-card { background: white; border-radius: 14px; padding: 20px; color: #002855; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
  .corp-card h5 { border-bottom: 2px solid #f5a623; padding-bottom: 10px; }
  .stat-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #f1f5f9; }
  .btn-corp { background: #f5a623; color: #002855; padding: 10px 20px; border-radius: 50px; border: none; font-weight: 700; cursor: pointer; margin: 5px; }
  textarea { width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #ddd; font-family: monospace; }
  pre { background: #1e293b; color: #e2e8f0; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.75rem; }
</style>
{% endblock %}
{% block content %}
<div class="corp-container">
  <a href="/" style="color:#f5a623;">← Back to Dashboard</a>
  <div class="corp-header">
    <h2>🏢 Corporate Shield</h2>
    <p>Enterprise scam protection for your organization</p>
  </div>
  
  <div class="corp-grid">
    <!-- Stats Card -->
    <div class="corp-card">
      <h5>📊 Company Stats</h5>
      <div id="corpStats">Loading...</div>
    </div>
    
    <!-- Bulk Verify -->
    <div class="corp-card">
      <h5>📋 Bulk Number Verification</h5>
      <p class="small text-muted">Paste phone numbers (one per line)</p>
      <textarea id="bulkNumbers" rows="6" placeholder="0712345678&#10;0722333444&#10;0733555666"></textarea>
      <button class="btn-corp" onclick="bulkVerify()">Verify Numbers</button>
      <div id="bulkResult" class="mt-2"></div>
    </div>
    
    <!-- API Key -->
    <div class="corp-card">
      <h5>🔑 API Access</h5>
      <p class="small text-muted">Integrate with your systems</p>
      <button class="btn-corp" onclick="generateAPIKey()">Generate API Key</button>
      <div id="apiKeyResult" class="mt-2"></div>
    </div>
    
    <!-- Widget -->
    <div class="corp-card">
      <h5>🔌 Website Widget</h5>
      <p class="small text-muted">Embed scam checker on your site</p>
      <button class="btn-corp" onclick="getWidgetCode()">Get Widget Code</button>
      <div id="widgetResult" class="mt-2"></div>
    </div>
  </div>
</div>

<script>
async function loadCorporateDashboard() {
  try {
    const res = await fetch('/api/corporate/');
    const data = await res.json();
    if (data.success) {
      document.getElementById('corpStats').innerHTML = `
        <div class="stat-row"><span>Plan</span><strong>${data.corporate.plan}</strong></div>
        <div class="stat-row"><span>Total Scans</span><strong>${data.stats.total_scans}</strong></div>
        <div class="stat-row"><span>High Risk</span><strong style="color:#dc3545;">${data.stats.high_risk}</strong></div>
        <div class="stat-row"><span>Staff Protected</span><strong>${data.stats.total_staff}</strong></div>
        <div class="stat-row"><span>Bulk Verifications</span><strong>${data.corporate.bulk_verifications}/${data.corporate.bulk_limit}</strong></div>
      `;
    }
  } catch(e) { console.error(e); }
}

async function bulkVerify() {
  const numbers = document.getElementById('bulkNumbers').value;
  const res = await fetch('/api/bulk-verify/', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRFToken': getCSRFToken()},
    body: JSON.stringify({numbers})
  });
  const data = await res.json();
  document.getElementById('bulkResult').innerHTML = data.success 
    ? `<div class="alert alert-success">✅ ${data.total} numbers checked: <span style="color:#dc3545;">${data.scam_found} scams</span>, ${data.clean} clean</div>`
    : `<div class="alert alert-danger">${data.error}</div>`;
}

async function generateAPIKey() {
  const res = await fetch('/api/generate-api-key/', {method:'POST', headers:{'X-CSRFToken':getCSRFToken()}});
  const data = await res.json();
  document.getElementById('apiKeyResult').innerHTML = data.success
    ? `<div class="alert alert-success">🔑 API Key: <code>${data.api_key}</code></div>`
    : `<div class="alert alert-danger">${data.error}</div>`;
}

async function getWidgetCode() {
  const res = await fetch('/api/widget-code/');
  const data = await res.json();
  document.getElementById('widgetResult').innerHTML = data.success
    ? `<p class="small">Copy this code into your website:</p><pre>${data.widget_code.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>`
    : `<div class="alert alert-danger">${data.error}</div>`;
}

function getCSRFToken() {
  return document.cookie.split('; ').find(r => r.startsWith('csrftoken='))?.split('=')[1] || '';
}

loadCorporateDashboard();
</script>
{% endblock %}