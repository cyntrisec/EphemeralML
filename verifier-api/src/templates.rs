pub const LANDING_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Cyntrisec Trust Center</title>
  <style>
    @import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap");
    *{margin:0;padding:0;box-sizing:border-box}
    :root{
      --blue:#3b82f6;--blue-light:#60a5fa;--blue-dim:rgba(59,130,246,0.12);
      --emerald:#10b981;--emerald-dim:rgba(16,185,129,0.12);
      --rose:#f43f5e;--rose-dim:rgba(244,63,94,0.12);
      --amber:#f59e0b;--amber-dim:rgba(245,158,11,0.12);
      --slate:#64748b;--slate-dim:rgba(100,116,139,0.12);
      --bg-primary:#0b0f1a;--bg-secondary:#111827;--bg-card:#1f2937;--bg-card-alt:#1a2332;
      --border:#374151;--border-light:#4b5563;
      --text-primary:#f9fafb;--text-secondary:#9ca3af;--text-muted:#6b7280;
    }
    body{font-family:"Inter",-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;min-height:100vh}
    .mono{font-family:"JetBrains Mono",monospace}
    .container{max-width:800px;margin:0 auto;padding:2rem 1.5rem}

    /* Header */
    header{text-align:center;margin-bottom:2rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border)}
    .brand{display:flex;align-items:center;justify-content:center;gap:0.75rem;margin-bottom:0.5rem}
    .brand-icon{width:32px;height:32px;background:var(--blue);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;font-weight:700;color:#fff}
    header h1{font-size:1.6rem;font-weight:700;letter-spacing:-0.02em}
    header .subtitle{color:var(--text-secondary);font-size:0.9rem;margin-top:0.25rem}

    /* Tabs */
    .tabs{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:1.5rem}
    .tab{padding:0.65rem 1.25rem;cursor:pointer;color:var(--text-muted);font-weight:500;font-size:0.9rem;border-bottom:2px solid transparent;transition:all 0.2s}
    .tab:hover{color:var(--text-secondary)}
    .tab.active{color:var(--blue-light);border-bottom-color:var(--blue)}
    .tab-content{display:none}
    .tab-content.active{display:block}

    /* Form */
    label{display:block;font-size:0.8rem;font-weight:500;color:var(--text-secondary);margin-bottom:0.3rem;margin-top:0.9rem;text-transform:uppercase;letter-spacing:0.04em}
    textarea,input[type="text"]{width:100%;background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;padding:0.7rem;color:var(--text-primary);font-size:0.85rem;resize:vertical}
    textarea{min-height:160px;font-family:"JetBrains Mono",monospace;font-size:0.78rem}
    textarea:focus,input:focus{outline:none;border-color:var(--blue)}
    input[type="file"]{color:var(--text-secondary);font-size:0.8rem;margin-top:0.2rem}
    input[type="file"]::file-selector-button{background:var(--bg-card);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:0.35rem 0.7rem;cursor:pointer;margin-right:0.5rem;font-size:0.78rem}
    .btn{display:inline-block;padding:0.65rem 1.75rem;background:var(--blue);color:#fff;border:none;border-radius:8px;font-size:0.9rem;font-weight:600;cursor:pointer;margin-top:1.25rem;transition:background 0.2s}
    .btn:hover{background:var(--blue-light)}
    .btn:disabled{opacity:0.5;cursor:not-allowed}
    .btn-outline{background:transparent;border:1px solid var(--border);color:var(--text-secondary);font-size:0.8rem;padding:0.4rem 0.85rem;border-radius:6px}
    .btn-outline:hover{border-color:var(--text-secondary);color:var(--text-primary)}
    .btn-sm{padding:0.35rem 0.7rem;font-size:0.78rem;margin-top:0}
    .spinner{display:none;margin-top:1.5rem;text-align:center;color:var(--text-muted);font-size:0.85rem}

    /* Samples bar */
    .samples{margin-bottom:1.25rem;padding:0.75rem 1rem;background:var(--bg-card-alt);border:1px solid var(--border);border-radius:8px;display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap}
    .samples-label{font-size:0.78rem;color:var(--text-muted);font-weight:500;text-transform:uppercase;letter-spacing:0.04em}
    .sample-btn{background:var(--bg-secondary);border:1px solid var(--border);color:var(--text-secondary);font-size:0.78rem;padding:0.3rem 0.65rem;border-radius:5px;cursor:pointer;transition:all 0.2s;font-family:inherit}
    .sample-btn:hover{border-color:var(--blue);color:var(--blue-light)}

    /* Result */
    #result{margin-top:2rem;display:none}

    /* Verdict banner */
    .verdict-banner{padding:1rem 1.25rem;border-radius:10px;margin-bottom:1.25rem;display:flex;align-items:center;gap:0.75rem}
    .verdict-banner.verified{background:var(--emerald-dim);border:1px solid rgba(16,185,129,0.25)}
    .verdict-banner.invalid{background:var(--rose-dim);border:1px solid rgba(244,63,94,0.25)}
    .verdict-icon{font-size:1.5rem}
    .verdict-text h3{font-size:1.1rem;font-weight:700;letter-spacing:0.01em}
    .verdict-text p{font-size:0.8rem;margin-top:0.1rem}
    .verdict-banner.verified .verdict-text h3{color:var(--emerald)}
    .verdict-banner.verified .verdict-text p{color:rgba(16,185,129,0.8)}
    .verdict-banner.invalid .verdict-text h3{color:var(--rose)}
    .verdict-banner.invalid .verdict-text p{color:rgba(244,63,94,0.8)}

    /* Section cards */
    .section{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:1.25rem;margin-bottom:1rem}
    .section-title{font-size:0.78rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:0.75rem}

    /* Receipt summary */
    .meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:0.5rem 1.25rem;font-size:0.82rem}
    .meta-grid dt{color:var(--text-muted)}
    .meta-grid dd{color:var(--text-primary);font-weight:500;word-break:break-all}
    @media(max-width:500px){.meta-grid{grid-template-columns:1fr}}

    /* Checks */
    .check-row{display:flex;justify-content:space-between;align-items:center;padding:0.35rem 0;font-size:0.85rem}
    .check-row+.check-row{border-top:1px solid rgba(55,65,81,0.5)}
    .check-label{display:flex;align-items:center;gap:0.5rem}
    .check-layer{font-size:0.65rem;padding:0.1rem 0.35rem;border-radius:3px;background:var(--slate-dim);color:var(--slate);font-weight:500;text-transform:uppercase;font-family:"JetBrains Mono",monospace}
    .badge{padding:0.12rem 0.45rem;border-radius:4px;font-size:0.72rem;font-weight:600;text-transform:uppercase;font-family:"JetBrains Mono",monospace}
    .badge.pass{background:var(--emerald-dim);color:var(--emerald)}
    .badge.fail{background:var(--rose-dim);color:var(--rose)}
    .badge.skip{background:var(--amber-dim);color:var(--amber)}

    /* Issues */
    .issues li{color:var(--text-muted);margin-left:1.2rem;margin-bottom:0.2rem;font-size:0.82rem}

    /* Limitations */
    .limitations{background:var(--bg-card-alt);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;margin-bottom:1rem}
    .limitations .section-title{color:var(--amber)}
    .limitations ul{list-style:none;padding:0}
    .limitations li{font-size:0.8rem;color:var(--text-muted);padding:0.2rem 0;padding-left:1.1rem;position:relative}
    .limitations li::before{content:"\2022";position:absolute;left:0;color:var(--amber)}

    /* Actions */
    .actions{display:flex;gap:0.6rem;flex-wrap:wrap;margin-top:0.25rem}

    /* Print */
    @media print{
      body{background:#fff;color:#000}
      .container{max-width:100%;padding:1rem}
      header{border-bottom-color:#ddd}
      .tabs,.tab-content,.samples,.spinner,.actions,.btn:not(.print-hide){display:none!important}
      #result{display:block!important}
      .section,.limitations{border-color:#ddd;background:#fafafa}
      .verdict-banner.verified{background:#ecfdf5;border-color:#065f46}
      .verdict-banner.verified .verdict-text h3{color:#065f46}
      .verdict-banner.verified .verdict-text p{color:#047857}
      .verdict-banner.invalid{background:#fff1f2;border-color:#9f1239}
      .verdict-banner.invalid .verdict-text h3{color:#9f1239}
      .verdict-banner.invalid .verdict-text p{color:#be123c}
      .badge.pass{background:#ecfdf5;color:#065f46}
      .badge.fail{background:#fff1f2;color:#9f1239}
      .badge.skip{background:#fffbeb;color:#92400e}
      .meta-grid dt{color:#666}
      .meta-grid dd{color:#000}
      .check-row{color:#000}
      .limitations{background:#fffbeb;border-color:#d97706}
      .print-header{display:block!important;text-align:right;font-size:0.75rem;color:#666;margin-bottom:0.5rem}
    }
    .print-header{display:none}
  </style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <div class="brand-icon">C</div>
      <h1>Cyntrisec Trust Center</h1>
    </div>
    <p class="subtitle">Verify signed receipts from confidential AI inference</p>
  </header>

  <div class="samples">
    <span class="samples-label">Try a sample:</span>
    <button class="sample-btn" onclick="loadSample('valid')">Valid AIR v1</button>
    <button class="sample-btn" onclick="loadSample('tampered')">Tampered AIR v1</button>
    <button class="sample-btn" onclick="loadSample('legacy')">Legacy receipt</button>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('paste')">Paste JSON</div>
    <div class="tab" onclick="switchTab('upload')">Upload File</div>
  </div>

  <div id="pasteTab" class="tab-content active">
    <form id="pasteForm" onsubmit="verifyPaste(event)">
      <label for="receiptJson">Receipt (JSON or base64)</label>
      <textarea id="receiptJson" placeholder='Paste receipt JSON or base64-encoded AIR v1 CBOR...'></textarea>
      <label for="publicKeyHex">Public key (64 hex chars)</label>
      <input type="text" id="publicKeyHex" placeholder="Ed25519 public key hex" class="mono"/>
      <button type="submit" class="btn">Verify Receipt</button>
    </form>
  </div>

  <div id="uploadTab" class="tab-content">
    <form id="uploadForm" onsubmit="verifyUpload(event)">
      <label>Receipt file (.json or .cbor)</label>
      <input type="file" id="receiptFile" accept=".json,.cbor,.bin"/>
      <label>Public key (hex)</label>
      <input type="text" id="uploadKeyHex" placeholder="64 hex chars" class="mono"/>
      <label>Or upload key file (.bin, 32 bytes)</label>
      <input type="file" id="publicKeyFile" accept=".bin,.key"/>
      <button type="submit" class="btn">Verify Receipt</button>
    </form>
  </div>

  <div class="spinner" id="spinner">Verifying receipt...</div>

  <div id="result">
    <div class="print-header" id="printHeader"></div>

    <!-- Block 1: Verdict -->
    <div id="verdictBanner" class="verdict-banner"></div>

    <!-- Block 2: Receipt Summary -->
    <div class="section">
      <div class="section-title">Receipt Summary</div>
      <dl class="meta-grid" id="meta"></dl>
    </div>

    <!-- Block 3: Verification Checks -->
    <div class="section">
      <div class="section-title">Verification Checks</div>
      <div id="checks"></div>
      <div id="issues" style="margin-top:0.75rem"></div>
    </div>

    <!-- Block 4: Limitations -->
    <div class="limitations" id="limitations">
      <div class="section-title">What this verification does not prove</div>
      <ul>
        <li>This verification confirms the receipt artifact is correctly signed and structurally valid.</li>
        <li>It does not independently verify the attestation document or hardware measurements referenced in the receipt.</li>
        <li>It does not prove data was deleted after processing.</li>
        <li>It does not constitute a compliance determination under any regulatory framework.</li>
        <li>Receipt fields may support evidence workflows relevant to compliance, but verification alone is not a legal conclusion.</li>
      </ul>
    </div>

    <!-- Actions -->
    <div class="actions">
      <button class="btn-outline" onclick="window.print()">Print Report</button>
      <button class="btn-outline" onclick="copyJson()">Copy JSON</button>
    </div>
  </div>
</div>

<script>
let lastResponse = null;

/* ── Samples ───────────────────────────────────────── */
async function loadSample(name) {
  try {
    if (name === 'legacy') {
      // Legacy JSON receipt
      const resp = await fetch('/api/v1/samples/legacy');
      const data = await resp.json();
      switchTab('paste');
      document.getElementById('receiptJson').value = JSON.stringify(data.receipt, null, 2);
      document.getElementById('publicKeyHex').value = data.public_key;
    } else {
      // AIR v1 (valid or tampered)
      const resp = await fetch('/api/v1/samples/valid');
      const data = await resp.json();
      switchTab('paste');
      if (name === 'tampered') {
        // Corrupt a few bytes in the middle of the base64 to break the signature.
        // This produces a real tamper-detection demo rather than just renaming a field.
        let b64 = data.receipt_base64;
        const mid = Math.floor(b64.length / 2);
        b64 = b64.substring(0, mid) + 'TAMPERED' + b64.substring(mid + 8);
        document.getElementById('receiptJson').value = b64;
      } else {
        document.getElementById('receiptJson').value = data.receipt_base64;
      }
      document.getElementById('publicKeyHex').value = data.public_key;
    }
  } catch (err) { alert('Failed to load sample: ' + err.message); }
}

/* ── Tabs ──────────────────────────────────────────── */
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

/* ── Verify (paste) ───────────────────────────────── */
async function verifyPaste(e) {
  e.preventDefault();
  const receipt = document.getElementById('receiptJson').value.trim();
  const key = document.getElementById('publicKeyHex').value.trim();
  if (!receipt || !key) return alert('Please provide both receipt and public key.');
  let receiptValue;
  try { receiptValue = JSON.parse(receipt); } catch {
    // Not valid JSON — treat as raw base64 string.
    receiptValue = receipt;
  }
  showSpinner(true);
  try {
    const resp = await fetch('/api/v1/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({receipt: receiptValue, public_key: key})
    });
    const data = await resp.json();
    if (!resp.ok && data.error) { alert('Error: ' + data.error); return; }
    showResult(data);
  } catch (err) { alert('Request failed: ' + err.message); }
  finally { showSpinner(false); }
}

/* ── Verify (upload) ──────────────────────────────── */
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

/* ── Render result ────────────────────────────────── */
function showResult(data) {
  lastResponse = data;
  const el = document.getElementById('result');
  el.style.display = 'block';

  // Print header
  document.getElementById('printHeader').textContent =
    'Cyntrisec Trust Center — Verification Report — ' + new Date().toISOString();

  // Block 1: Verdict banner
  const vb = document.getElementById('verdictBanner');
  const isVerified = data.verified;
  vb.className = 'verdict-banner ' + (isVerified ? 'verified' : 'invalid');
  const fmtLabel = data.format === 'air_v1' ? 'AIR v1' : 'Legacy';
  vb.innerHTML = `
    <div class="verdict-icon">${isVerified ? '\u2705' : '\u274C'}</div>
    <div class="verdict-text">
      <h3>${isVerified ? 'VERIFIED' : 'VERIFICATION FAILED'}</h3>
      <p>${fmtLabel} receipt \u2022 Verified ${new Date(data.verified_at * 1000).toISOString()}</p>
    </div>`;

  // Block 2: Receipt summary
  const r = data.receipt || {};
  const meta = document.getElementById('meta');
  let metaHtml = '';
  if (r.receipt_id) metaHtml += `<dt>Receipt ID</dt><dd class="mono">${esc(r.receipt_id)}</dd>`;
  if (r.model_id) metaHtml += `<dt>Model</dt><dd>${esc(r.model_id)}${r.model_version ? ' v' + esc(r.model_version) : ''}</dd>`;
  if (r.platform) metaHtml += `<dt>Platform</dt><dd>${esc(r.platform)}</dd>`;
  if (r.issuer) metaHtml += `<dt>Issuer</dt><dd>${esc(r.issuer)}</dd>`;
  if (r.security_mode) metaHtml += `<dt>Security mode</dt><dd>${esc(r.security_mode)}</dd>`;
  if (r.execution_time_ms != null) metaHtml += `<dt>Execution time</dt><dd>${r.execution_time_ms} ms</dd>`;
  if (r.sequence_number != null) metaHtml += `<dt>Sequence</dt><dd>#${r.sequence_number}</dd>`;
  if (r.issued_at) metaHtml += `<dt>Issued at</dt><dd>${new Date(r.issued_at*1000).toISOString()}</dd>`;
  metaHtml += `<dt>Format</dt><dd>${esc(fmtLabel)}</dd>`;
  meta.innerHTML = metaHtml;

  // Block 3: Checks
  const checksEl = document.getElementById('checks');
  const arr = Array.isArray(data.checks) ? data.checks : [];
  let checksHtml = '';
  arr.forEach(c => {
    const s = (c.status || 'skip').toLowerCase();
    const layerBadge = c.layer ? `<span class="check-layer">${esc(c.layer)}</span>` : '';
    checksHtml += `<div class="check-row">
      <span class="check-label">${layerBadge}<span>${esc(c.label || c.id)}</span></span>
      <span class="badge ${s}">${s}</span>
    </div>`;
    if (c.detail && s === 'fail') {
      checksHtml += `<div style="padding:0.15rem 0 0.3rem 2rem;font-size:0.78rem;color:var(--text-muted)">${esc(c.detail)}</div>`;
    }
  });
  checksEl.innerHTML = checksHtml;

  // Issues
  const issuesEl = document.getElementById('issues');
  let issHtml = '';
  if (data.errors && data.errors.length) {
    issHtml += '<div style="margin-bottom:0.5rem"><strong style="color:var(--rose);font-size:0.82rem">Errors</strong><ul>';
    data.errors.forEach(e => issHtml += '<li style="color:var(--rose)">' + esc(e) + '</li>');
    issHtml += '</ul></div>';
  }
  if (data.warnings && data.warnings.length) {
    issHtml += '<div><strong style="color:var(--amber);font-size:0.82rem">Warnings</strong><ul>';
    data.warnings.forEach(w => issHtml += '<li>' + esc(w) + '</li>');
    issHtml += '</ul></div>';
  }
  issuesEl.innerHTML = issHtml;

  el.scrollIntoView({behavior:'smooth'});
}

/* ── Helpers ──────────────────────────────────────── */
function esc(s) { const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }

function copyJson() {
  if (lastResponse) {
    navigator.clipboard.writeText(JSON.stringify(lastResponse, null, 2))
      .then(() => { /* copied */ })
      .catch(() => { /* fallback: noop */ });
  }
}
</script>
</body>
</html>
"##;
