pub const LANDING_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>EphemeralML Receipt Verifier</title>
  <style>
    @import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap");
    *{margin:0;padding:0;box-sizing:border-box}
    :root{
      --blue:#3b82f6;--blue-light:#60a5fa;--blue-dim:rgba(59,130,246,0.15);
      --emerald:#10b981;--emerald-dim:rgba(16,185,129,0.15);
      --rose:#f43f5e;--rose-dim:rgba(244,63,94,0.15);
      --amber:#f59e0b;--amber-dim:rgba(245,158,11,0.15);
      --bg-primary:#0b0f1a;--bg-secondary:#111827;--bg-card:#1f2937;
      --border:#374151;--border-light:#4b5563;
      --text-primary:#f9fafb;--text-secondary:#9ca3af;--text-muted:#6b7280;
    }
    body{font-family:"Inter",-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;min-height:100vh}
    .mono{font-family:"JetBrains Mono",monospace}
    .container{max-width:760px;margin:0 auto;padding:2rem 1.5rem}
    header{text-align:center;margin-bottom:2.5rem}
    header h1{font-size:1.75rem;font-weight:700;letter-spacing:-0.02em}
    header p{color:var(--text-secondary);margin-top:0.5rem;font-size:0.95rem}
    .tabs{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:1.5rem}
    .tab{padding:0.75rem 1.5rem;cursor:pointer;color:var(--text-muted);font-weight:500;border-bottom:2px solid transparent;transition:all 0.2s}
    .tab:hover{color:var(--text-secondary)}
    .tab.active{color:var(--blue-light);border-bottom-color:var(--blue)}
    .tab-content{display:none}
    .tab-content.active{display:block}
    label{display:block;font-size:0.85rem;font-weight:500;color:var(--text-secondary);margin-bottom:0.4rem;margin-top:1rem}
    textarea,input[type="text"]{width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:0.75rem;color:var(--text-primary);font-size:0.9rem;resize:vertical}
    textarea{min-height:180px;font-family:"JetBrains Mono",monospace;font-size:0.8rem}
    textarea:focus,input:focus{outline:none;border-color:var(--blue)}
    input[type="file"]{color:var(--text-secondary);font-size:0.85rem;margin-top:0.25rem}
    input[type="file"]::file-selector-button{background:var(--bg-card);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:0.4rem 0.8rem;cursor:pointer;margin-right:0.5rem;font-size:0.8rem}
    .btn{display:inline-block;padding:0.75rem 2rem;background:var(--blue);color:#fff;border:none;border-radius:8px;font-size:0.95rem;font-weight:600;cursor:pointer;margin-top:1.5rem;transition:background 0.2s}
    .btn:hover{background:var(--blue-light)}
    .btn:disabled{opacity:0.5;cursor:not-allowed}
    .btn-outline{background:transparent;border:1px solid var(--border);color:var(--text-secondary);font-size:0.85rem;padding:0.5rem 1rem}
    .btn-outline:hover{border-color:var(--text-secondary)}
    #result{margin-top:2rem;display:none}
    .result-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;position:relative}
    .banner{padding:0.75rem 1rem;border-radius:8px;font-weight:700;font-size:1.1rem;text-align:center;margin-bottom:1.25rem;letter-spacing:0.02em}
    .banner.verified{background:var(--emerald-dim);color:var(--emerald);border:1px solid rgba(16,185,129,0.3)}
    .banner.invalid{background:var(--rose-dim);color:var(--rose);border:1px solid rgba(244,63,94,0.3)}
    .meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:0.6rem 1.5rem;margin-bottom:1.25rem;font-size:0.85rem}
    .meta-grid dt{color:var(--text-muted)}
    .meta-grid dd{color:var(--text-primary);font-weight:500}
    .checks{border-top:1px solid var(--border);padding-top:1rem}
    .check-row{display:flex;justify-content:space-between;align-items:center;padding:0.4rem 0;font-size:0.9rem}
    .badge{padding:0.15rem 0.5rem;border-radius:4px;font-size:0.75rem;font-weight:600;text-transform:uppercase;font-family:"JetBrains Mono",monospace}
    .badge.pass{background:var(--emerald-dim);color:var(--emerald)}
    .badge.fail{background:var(--rose-dim);color:var(--rose)}
    .badge.skip{background:var(--amber-dim);color:var(--amber)}
    .issues{margin-top:1rem;font-size:0.85rem}
    .issues h4{color:var(--text-secondary);margin-bottom:0.4rem}
    .issues li{color:var(--text-muted);margin-left:1.2rem;margin-bottom:0.2rem}
    .actions{margin-top:1.25rem;display:flex;gap:0.75rem}
    .spinner{display:none;margin-top:1.5rem;text-align:center;color:var(--text-muted);font-size:0.9rem}
    @media print{
      body{background:#fff;color:#000}
      .container{max-width:100%}
      .tabs,.tab-content,#pasteForm,#uploadForm,.actions,.btn{display:none!important}
      #result{display:block!important}
      .result-card{border:1px solid #ccc;box-shadow:none}
      .banner.verified{background:#d1fae5;color:#065f46;border-color:#065f46}
      .banner.invalid{background:#ffe4e6;color:#9f1239;border-color:#9f1239}
      .badge.pass{background:#d1fae5;color:#065f46}
      .badge.fail{background:#ffe4e6;color:#9f1239}
      .badge.skip{background:#fef3c7;color:#92400e}
      .meta-grid dt{color:#666}
      .meta-grid dd{color:#000}
      .check-row{color:#000}
      .issues li{color:#333}
      header p{color:#666}
    }
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1>EphemeralML Receipt Verifier</h1>
    <p>Verify cryptographic receipts from confidential AI inference sessions</p>
  </header>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('paste')">Paste JSON</div>
    <div class="tab" onclick="switchTab('upload')">Upload File</div>
  </div>

  <div id="pasteTab" class="tab-content active">
    <form id="pasteForm" onsubmit="verifyPaste(event)">
      <label for="receiptJson">Receipt JSON</label>
      <textarea id="receiptJson" placeholder='{"receipt_id":"...","model_id":"...","signature":"...",...}'></textarea>
      <label for="publicKeyHex">Public Key (hex, 64 chars)</label>
      <input type="text" id="publicKeyHex" placeholder="e.g. a1b2c3d4..." class="mono"/>
      <button type="submit" class="btn">Verify</button>
    </form>
  </div>

  <div id="uploadTab" class="tab-content">
    <form id="uploadForm" onsubmit="verifyUpload(event)">
      <label>Receipt File (.json or .cbor)</label>
      <input type="file" id="receiptFile" accept=".json,.cbor"/>
      <label>Public Key (hex)</label>
      <input type="text" id="uploadKeyHex" placeholder="64 hex chars" class="mono"/>
      <label>Or upload key file (.bin, 32 bytes)</label>
      <input type="file" id="publicKeyFile" accept=".bin"/>
      <button type="submit" class="btn">Verify</button>
    </form>
  </div>

  <div class="spinner" id="spinner">Verifying...</div>

  <div id="result">
    <div class="result-card">
      <div id="banner" class="banner"></div>
      <dl class="meta-grid" id="meta"></dl>
      <div class="checks" id="checks"></div>
      <div class="issues" id="issues"></div>
      <div class="actions">
        <button class="btn btn-outline" onclick="window.print()">Print Report</button>
        <button class="btn btn-outline" onclick="copyJson()">Copy JSON</button>
      </div>
    </div>
  </div>
</div>

<script>
let lastResponse = null;

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  if (tab === 'paste') {
    document.querySelectorAll('.tab')[0].classList.add('active');
    document.getElementById('pasteTab').classList.add('active');
  } else {
    document.querySelectorAll('.tab')[1].classList.add('active');
    document.getElementById('uploadTab').classList.add('active');
  }
}

async function verifyPaste(e) {
  e.preventDefault();
  const receipt = document.getElementById('receiptJson').value.trim();
  const key = document.getElementById('publicKeyHex').value.trim();
  if (!receipt || !key) return alert('Please provide both receipt JSON and public key.');
  let parsed;
  try { parsed = JSON.parse(receipt); } catch { return alert('Invalid JSON in receipt field.'); }
  showSpinner(true);
  try {
    const resp = await fetch('/api/v1/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({receipt: parsed, public_key: key})
    });
    const data = await resp.json();
    if (!resp.ok && data.error) { alert('Error: ' + data.error); return; }
    showResult(data);
  } catch (err) { alert('Request failed: ' + err.message); }
  finally { showSpinner(false); }
}

async function verifyUpload(e) {
  e.preventDefault();
  const fileInput = document.getElementById('receiptFile');
  const keyHex = document.getElementById('uploadKeyHex').value.trim();
  const keyFile = document.getElementById('publicKeyFile');
  if (!fileInput.files.length) return alert('Please select a receipt file.');
  if (!keyHex && !keyFile.files.length) return alert('Please provide a public key (hex or file).');
  const form = new FormData();
  form.append('receipt_file', fileInput.files[0]);
  if (keyHex) form.append('public_key', keyHex);
  else if (keyFile.files.length) form.append('public_key_file', keyFile.files[0]);
  showSpinner(true);
  try {
    const resp = await fetch('/api/v1/verify/upload', {method: 'POST', body: form});
    const data = await resp.json();
    if (!resp.ok && data.error) { alert('Error: ' + data.error); return; }
    showResult(data);
  } catch (err) { alert('Request failed: ' + err.message); }
  finally { showSpinner(false); }
}

function showSpinner(on) {
  document.getElementById('spinner').style.display = on ? 'block' : 'none';
}

function showResult(data) {
  lastResponse = data;
  const el = document.getElementById('result');
  el.style.display = 'block';
  const banner = document.getElementById('banner');
  banner.textContent = data.verified ? 'VERIFIED' : 'INVALID';
  banner.className = 'banner ' + (data.verified ? 'verified' : 'invalid');

  const meta = document.getElementById('meta');
  meta.innerHTML = `
    <dt>Receipt ID</dt><dd class="mono">${esc(data.receipt_id||'')}</dd>
    <dt>Model</dt><dd>${esc(data.model_id||'')} v${esc(data.model_version||'')}</dd>
    <dt>Platform</dt><dd>${esc(data.measurement_type||'')}</dd>
    <dt>Sequence</dt><dd>#${data.sequence_number||0}</dd>
    <dt>Timestamp</dt><dd>${data.execution_timestamp ? new Date(data.execution_timestamp*1000).toISOString() : 'N/A'}</dd>
    <dt>Verified at</dt><dd>${data.verified_at ? new Date(data.verified_at*1000).toISOString() : 'N/A'}</dd>
  `;

  const checks = document.getElementById('checks');
  const c = data.checks || {};
  checks.innerHTML = '<h4 style="margin-bottom:0.5rem;color:var(--text-secondary)">Checks</h4>' +
    checkRow('Signature (Ed25519)', c.signature) +
    checkRow('Model ID match', c.model_match) +
    checkRow('Measurement type', c.measurement_type) +
    checkRow('Timestamp freshness', c.timestamp_fresh) +
    checkRow('Measurements present', c.measurements_present);

  const issues = document.getElementById('issues');
  let html = '';
  if (data.errors && data.errors.length) {
    html += '<h4 style="color:var(--rose)">Errors</h4><ul>';
    data.errors.forEach(e => html += '<li>' + esc(e) + '</li>');
    html += '</ul>';
  }
  if (data.warnings && data.warnings.length) {
    html += '<h4 style="color:var(--amber);margin-top:0.5rem">Warnings</h4><ul>';
    data.warnings.forEach(w => html += '<li>' + esc(w) + '</li>');
    html += '</ul>';
  }
  issues.innerHTML = html;
  el.scrollIntoView({behavior:'smooth'});
}

function checkRow(label, status) {
  const s = (status||'skip').toLowerCase();
  return `<div class="check-row"><span>${esc(label)}</span><span class="badge ${s}">${s}</span></div>`;
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function copyJson() {
  if (lastResponse) navigator.clipboard.writeText(JSON.stringify(lastResponse, null, 2));
}
</script>
</body>
</html>
"##;
