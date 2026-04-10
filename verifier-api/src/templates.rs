pub const LANDING_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Cyntrisec Trust Center</title>
  <meta name="description" content="Verify AIR v1 and legacy receipts from confidential AI inference. Checks signed claims, hash bindings, and attestation-linked execution evidence."/>
  <meta property="og:title" content="Cyntrisec Trust Center"/>
  <meta property="og:description" content="Verify AIR v1 and legacy receipts from confidential AI inference. Checks signed claims, hash bindings, and attestation-linked execution evidence."/>
  <meta property="og:type" content="website"/>
  <meta name="theme-color" content="#000000"/>
  <link rel="icon" href="https://cyntrisec.com/logo-mark-64.png" type="image/png"/>
  <style>
    @import url("https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap");
    *{margin:0;padding:0;box-sizing:border-box}
    :root{
      --bg:#000000;--bg-raised:#030303;--bg-input:#030303;
      --border:rgba(255,255,255,0.06);--border-focus:#06b6d4;
      --text:#f0f0f0;--text-dim:#888;--text-faint:#555;
      --cyan:#06b6d4;--green:#10b981;--red:#ef4444;--amber:#f59e0b;
      --green-bg:rgba(16,185,129,0.05);--red-bg:rgba(239,68,68,0.05);--amber-bg:rgba(245,158,11,0.05);
      --sans:"Outfit",system-ui,sans-serif;--mono:"JetBrains Mono","Menlo",monospace;
    }
    body{background:var(--bg);color:var(--text);font:400 14px/1.6 var(--sans);-webkit-font-smoothing:antialiased;min-height:100vh}
    .mono{font-family:var(--mono)}

    /* Layout */
    .page{max-width:680px;margin:0 auto;padding:48px 20px 80px}
    header{display:flex;align-items:center;justify-content:space-between;margin-bottom:40px;padding-bottom:16px;border-bottom:1px solid var(--border)}
    .brand{display:flex;align-items:center;gap:12px;text-decoration:none;color:var(--text)}
    .brand img{width:28px;height:28px}
    .brand span{font-weight:600;font-size:13px;letter-spacing:0.02em}
    .brand em{font-style:normal;color:var(--text-faint);font-weight:400;margin-left:2px}
    header nav{display:flex;gap:16px;font-size:12px;color:var(--text-dim)}
    header nav a{color:var(--text-dim);text-decoration:none;transition:color .15s}
    header nav a:hover{color:var(--text)}

    /* Sections */
    .field-group{margin-bottom:24px}
    .field-label{display:block;font:500 11px/1 var(--mono);color:var(--text-faint);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px}
    textarea,input[type="text"]{width:100%;background:var(--bg-input);border:1px solid var(--border);color:var(--text);padding:10px 12px;font-size:13px;border-radius:4px;transition:border-color .15s}
    textarea{min-height:140px;font-family:var(--mono);font-size:12px;line-height:1.5;resize:vertical}
    textarea:focus,input[type="text"]:focus{outline:none;border-color:var(--border-focus)}
    input[type="file"]{font-size:12px;color:var(--text-dim)}
    input[type="file"]::file-selector-button{background:var(--bg-raised);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:3px;cursor:pointer;font-size:11px;margin-right:8px}

    /* Tabs */
    .tab-bar{display:flex;gap:0;margin-bottom:20px;border-bottom:1px solid var(--border)}
    .tab-btn{padding:8px 16px;font:500 12px/1 var(--mono);color:var(--text-faint);background:none;border:none;border-bottom:2px solid transparent;cursor:pointer;transition:color .15s,border-color .15s;margin-bottom:-1px}
    .tab-btn:hover{color:var(--text-dim)}
    .tab-btn.on{color:var(--cyan);border-bottom-color:var(--cyan)}
    .tab-pane{display:none}.tab-pane.on{display:block}

    /* Samples */
    .sample-row{display:flex;align-items:center;gap:8px;margin-bottom:20px;flex-wrap:wrap}
    .sample-row span{font:500 11px/1 var(--mono);color:var(--text-faint);text-transform:uppercase;letter-spacing:0.06em}
    .sample-btn{background:none;border:1px solid var(--border);color:var(--text-dim);font:400 12px/1 var(--mono);padding:5px 10px;border-radius:3px;cursor:pointer;transition:color .15s,border-color .15s}
    .sample-btn:hover{color:var(--text);border-color:var(--text-dim)}

    /* Buttons */
    .btn-verify{display:block;width:100%;padding:10px;background:var(--text);color:var(--bg);border:none;font:600 13px/1 var(--sans);letter-spacing:0.01em;cursor:pointer;border-radius:4px;transition:opacity .15s;margin-top:8px}
    .btn-verify:hover{opacity:0.85}
    .btn-verify:disabled{opacity:0.4;cursor:default}
    .btn-sm{background:none;border:1px solid var(--border);color:var(--text-dim);font:400 12px/1 var(--mono);padding:6px 12px;border-radius:3px;cursor:pointer;transition:color .15s,border-color .15s}
    .btn-sm:hover{color:var(--text);border-color:var(--text-dim)}

    /* Spinner */
    .spinner{display:none;padding:16px 0;font:400 12px/1 var(--mono);color:var(--text-dim)}

    /* Result */
    #result{display:none;margin-top:32px;padding-top:32px;border-top:1px solid var(--border)}

    /* Verdict */
    .verdict{padding:16px 20px;border-left:3px solid var(--border);margin-bottom:24px}
    .verdict.pass{border-left-color:var(--green);background:var(--green-bg)}
    .verdict.fail{border-left-color:var(--red);background:var(--red-bg)}
    .verdict h2{font-size:16px;font-weight:600;margin-bottom:2px}
    .verdict.pass h2{color:var(--green)}
    .verdict.fail h2{color:var(--red)}
    .verdict p{font-size:12px;color:var(--text-dim)}

    /* Meta table */
    .meta-tbl{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px}
    .meta-tbl td{padding:5px 0;vertical-align:top}
    .meta-tbl td:first-child{width:130px;font:500 11px/1.8 var(--mono);color:var(--text-faint);text-transform:uppercase;letter-spacing:0.06em}
    .meta-tbl td:last-child{color:var(--text);word-break:break-all}
    .meta-tbl tr+tr td{border-top:1px solid var(--border)}

    /* Checks */
    .checks-hd{font:500 11px/1 var(--mono);color:var(--text-faint);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:10px}
    .ck{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:8px 0;font-size:13px}
    .ck+.ck{border-top:1px solid var(--border)}
    .ck-info{display:flex;flex-direction:column;gap:3px;min-width:0}
    .ck-name{color:var(--text);font-weight:500}
    .ck-layer{font:500 10px/1 var(--mono);color:var(--text-faint);text-transform:uppercase;letter-spacing:0.06em}
    .ck-detail{font-size:12px;color:var(--text-dim);line-height:1.5}
    .tag{font:600 10px/1 var(--mono);text-transform:uppercase;letter-spacing:0.04em;padding:3px 7px;border-radius:2px;flex-shrink:0}
    .tag-pass{color:var(--green);background:var(--green-bg)}
    .tag-fail{color:var(--red);background:var(--red-bg)}
    .tag-skip{color:var(--amber);background:var(--amber-bg)}

    /* Issues */
    .issues-section{margin-top:24px}
    .issue-hd{font:500 11px/1 var(--mono);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px}
    .issue-hd.err{color:var(--red)}.issue-hd.wrn{color:var(--amber)}
    .issue-li{font-size:12px;line-height:1.6;color:var(--text-dim);padding-left:14px;position:relative;margin-bottom:2px}
    .issue-li::before{content:"\203A";position:absolute;left:0;font-family:var(--mono);color:inherit}
    .issue-li.err{color:#ff8a8a}

    /* Limitations */
    .lim{margin-top:24px;padding:14px 16px;border:1px dashed var(--border);font-size:12px;color:var(--text-dim);line-height:1.7}
    .lim strong{color:var(--amber);font-weight:600;display:block;font:500 11px/1 var(--mono);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px}
    .lim ul{list-style:none;margin:0;padding:0}
    .lim li{padding-left:12px;position:relative;margin-bottom:4px}
    .lim li::before{content:"\2013";position:absolute;left:0;color:var(--text-faint)}

    /* Actions */
    .act-row{display:flex;gap:8px;margin-top:20px}

    /* Footer */
    footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;font-size:11px;color:var(--text-faint)}
    footer a{color:var(--text-faint);text-decoration:none}
    footer a:hover{color:var(--text-dim)}

    .print-header{display:none}
    @media(max-width:540px){
      .page{padding:24px 16px 48px}
      .meta-tbl td:first-child{width:100px}
      .verdict{padding:12px 14px}
    }
    @media print{
      body{background:#fff;color:#111}
      .page{max-width:100%;padding:0}
      header nav,.sample-row,.tab-bar,.tab-pane,form,.spinner,.act-row,footer{display:none!important}
      #result{display:block!important;border-top:none;margin-top:0}
      .verdict{border:1px solid #ccc}
      .verdict.pass{background:#ecfdf5;border-left-color:#16a34a}
      .verdict.fail{background:#fff1f2;border-left-color:#e11d48}
      .tag-pass{background:#ecfdf5;color:#166534}
      .tag-fail{background:#fff1f2;color:#9f1239}
      .tag-skip{background:#fffbeb;color:#854d0e}
      .meta-tbl tr+tr td,.ck+.ck{border-top-color:#e5e5e5}
      .lim{border-color:#d4d4d4}
      .print-header{display:block!important;text-align:right;font-size:11px;color:#888;margin-bottom:12px}
    }
  </style>
</head>
<body>
<div class="page">
  <header>
    <a class="brand" href="https://cyntrisec.com">
      <img src="https://cyntrisec.com/logo-ikeda.svg" alt="" width="28" height="28"/>
      <span>Cyntrisec <em>/ Trust Center</em></span>
    </a>
    <nav class="mono">
      <a href="https://cyntrisec.com/docs">Docs</a>
      <a href="https://github.com/cyntrisec/EphemeralML">GitHub</a>
    </nav>
  </header>

  <div class="sample-row">
    <span class="mono">Samples</span>
    <button class="sample-btn" onclick="loadSample('valid')">Valid AIR v1</button>
    <button class="sample-btn" onclick="loadSample('tampered')">Tampered AIR v1</button>
    <button class="sample-btn" onclick="loadSample('legacy')">Legacy</button>
  </div>

  <div class="tab-bar">
    <button class="tab-btn on" onclick="switchTab('paste')">Paste</button>
    <button class="tab-btn" onclick="switchTab('upload')">Upload</button>
  </div>

  <div id="pasteTab" class="tab-pane on">
    <form id="pasteForm" onsubmit="verifyPaste(event)">
      <div class="field-group">
        <label class="field-label" for="receiptJson">Receipt (JSON or base64)</label>
        <textarea id="receiptJson" placeholder="Paste receipt JSON or base64-encoded CBOR"></textarea>
      </div>
      <div class="field-group">
        <label class="field-label" for="publicKeyHex">Public key (64 hex chars)</label>
        <input type="text" id="publicKeyHex" placeholder="Ed25519 public key hex" class="mono"/>
      </div>
      <button type="submit" class="btn-verify">Verify</button>
    </form>
  </div>

  <div id="uploadTab" class="tab-pane">
    <form id="uploadForm" onsubmit="verifyUpload(event)">
      <div class="field-group">
        <label class="field-label">Receipt file (.json / .cbor)</label>
        <input type="file" id="receiptFile" accept=".json,.cbor,.bin"/>
      </div>
      <div class="field-group">
        <label class="field-label">Public key (hex)</label>
        <input type="text" id="uploadKeyHex" placeholder="64 hex chars" class="mono"/>
      </div>
      <div class="field-group">
        <label class="field-label">Or key file (.bin, 32 bytes)</label>
        <input type="file" id="publicKeyFile" accept=".bin,.key"/>
      </div>
      <div class="field-group">
        <label class="field-label">Or attestation file (.cbor / .bin)</label>
        <input type="file" id="attestationFile" accept=".cbor,.bin"/>
      </div>
      <button type="submit" class="btn-verify">Verify</button>
    </form>
  </div>

  <div class="spinner" id="spinner">Verifying...</div>

  <div id="result">
    <div class="print-header" id="printHeader"></div>
    <div id="verdictBanner" class="verdict"></div>
    <table class="meta-tbl" id="meta"></table>
    <div class="checks-hd">Verification checks</div>
    <div id="checks"></div>
    <div id="issues" class="issues-section"></div>
    <div class="lim" id="limitations">
      <strong>Limitations</strong>
      <ul>
        <li>Confirms the receipt is correctly signed and structurally valid.</li>
        <li>Can derive the receipt key from a supplied attestation document, but does not enforce deployment-specific measurement policy by itself.</li>
        <li>Does not prove data was deleted after processing.</li>
        <li>Does not constitute a compliance determination.</li>
        <li>Deployment-specific trust policy depends on expected measurements, model allowlist, and freshness inputs.</li>
      </ul>
    </div>
    <div class="act-row">
      <button class="btn-sm" onclick="window.print()">Print</button>
      <button class="btn-sm" onclick="copyJson()">Copy JSON</button>
    </div>
  </div>

  <div style="margin-top:32px;font-size:11px;color:var(--text-faint);line-height:1.6">
    <strong style="color:var(--text-dim)">Privacy:</strong>
    Uploaded receipts are processed in memory and not stored. IP addresses are used for rate limiting only and discarded within minutes. No analytics or tracking. Source: <a href="https://github.com/cyntrisec/EphemeralML" style="color:var(--text-dim)">github.com/cyntrisec/EphemeralML</a>
  </div>

  <footer>
    <span>&copy; 2026 Cyntrisec</span>
    <span class="mono">AIR v1 + legacy</span>
  </footer>
</div>

<script>
let lastResponse = null;

async function loadSample(name) {
  try {
    if (name === 'legacy') {
      const resp = await fetch('/api/v1/samples/legacy');
      const data = await resp.json();
      switchTab('paste');
      document.getElementById('receiptJson').value = JSON.stringify(data.receipt, null, 2);
      document.getElementById('publicKeyHex').value = data.public_key;
    } else {
      const resp = await fetch('/api/v1/samples/valid');
      const data = await resp.json();
      switchTab('paste');
      if (name === 'tampered') {
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

function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('on'));
  document.querySelectorAll('.tab-pane').forEach(t => t.classList.remove('on'));
  if (tab === 'paste') {
    document.querySelectorAll('.tab-btn')[0].classList.add('on');
    document.getElementById('pasteTab').classList.add('on');
  } else {
    document.querySelectorAll('.tab-btn')[1].classList.add('on');
    document.getElementById('uploadTab').classList.add('on');
  }
}

async function verifyPaste(e) {
  e.preventDefault();
  const receipt = document.getElementById('receiptJson').value.trim();
  const key = document.getElementById('publicKeyHex').value.trim();
  if (!receipt || !key) return alert('Provide both receipt and public key.');
  let receiptValue;
  try { receiptValue = JSON.parse(receipt); } catch { receiptValue = receipt; }
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

async function verifyUpload(e) {
  e.preventDefault();
  const fileInput = document.getElementById('receiptFile');
  const keyHex = document.getElementById('uploadKeyHex').value.trim();
  const keyFile = document.getElementById('publicKeyFile');
  const attestationFile = document.getElementById('attestationFile');
  if (!fileInput.files.length) return alert('Select a receipt file.');
  if (!keyHex && !keyFile.files.length && !attestationFile.files.length) {
    return alert('Provide a public key or attestation file.');
  }
  const form = new FormData();
  form.append('receipt_file', fileInput.files[0]);
  if (keyHex) form.append('public_key', keyHex);
  else if (keyFile.files.length) form.append('public_key_file', keyFile.files[0]);
  else if (attestationFile.files.length) form.append('attestation_file', attestationFile.files[0]);
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
  document.getElementById('printHeader').textContent =
    'Cyntrisec Trust Center — ' + new Date().toISOString();

  const isOk = data.verified === true || data.verdict === 'verified';
  const isAir = data.format === 'air_v1';
  const fmt = isAir ? 'AIR v1' : 'Legacy';
  const fmtNote = isAir
    ? 'Standards-based receipt (COSE/CWT/EAT) with signed claims and attestation linkage'
    : 'Product-specific receipt format for compatibility';
  const vb = document.getElementById('verdictBanner');
  vb.className = 'verdict ' + (isOk ? 'pass' : 'fail');
  vb.innerHTML = `<h2>${isOk ? 'Verified' : 'Failed'}</h2><p>${esc(fmt)} receipt &middot; ${data.verified_at ? new Date(data.verified_at*1000).toISOString() : ''}</p><p style="margin-top:4px;font-size:11px;color:var(--text-faint)">${esc(fmtNote)}</p>`;

  const r = data.receipt || {};
  const meta = document.getElementById('meta');
  let rows = '';
  const add = (k, v) => { if (v != null && v !== '') rows += `<tr><td>${esc(k)}</td><td>${esc(String(v))}</td></tr>`; };
  add('Receipt ID', r.receipt_id);
  add('Model', r.model_id ? r.model_id + (r.model_version ? ' v' + r.model_version : '') : null);
  add('Platform', r.platform);
  add('Issuer', r.issuer);
  add('Security', r.security_mode);
  add('Exec time', r.execution_time_ms != null ? r.execution_time_ms + ' ms' : null);
  add('Sequence', r.sequence_number != null ? '#' + r.sequence_number : null);
  add('Issued', r.issued_at ? new Date(r.issued_at*1000).toISOString() : null);
  add('Format', fmt);
  if (r.model_hash_scheme) {
    add('Hash scheme', r.model_hash_scheme);
    // TODO: Replace with first-class model_identity_coverage from the API
    // instead of inferring from hash scheme in the frontend. Track in
    // view_model.rs when the coverage map is added to ReceiptSummary.
    const isManifest = r.model_hash_scheme === 'sha256-manifest';
    const coverage = isManifest
      ? 'weights: bound, tokenizer: bound, config: bound, adapters: not bound'
      : 'weights: bound';
    add('Model coverage', coverage);
  }
  meta.innerHTML = rows;

  const checksEl = document.getElementById('checks');
  const arr = Array.isArray(data.checks) ? data.checks : [];
  let ch = '';
  arr.forEach(c => {
    const s = (c.status||'skip').toLowerCase();
    const cls = s === 'pass' ? 'tag-pass' : s === 'fail' ? 'tag-fail' : 'tag-skip';
    const layer = c.layer ? `<span class="ck-layer">${esc(c.layer)}</span>` : '';
    const detail = c.detail && s === 'fail' ? `<span class="ck-detail">${esc(c.detail)}</span>` : '';
    ch += `<div class="ck"><div class="ck-info">${layer}<span class="ck-name">${esc(c.label||c.id)}</span>${detail}</div><span class="tag ${cls}">${s}</span></div>`;
  });
  checksEl.innerHTML = ch || '<div style="color:var(--text-faint);font-size:12px">No checks returned.</div>';

  const issuesEl = document.getElementById('issues');
  let ih = '';
  if (data.errors && data.errors.length) {
    ih += '<div class="issue-hd err">Errors</div>';
    data.errors.forEach(e => ih += '<div class="issue-li err">' + esc(e) + '</div>');
  }
  if (data.warnings && data.warnings.length) {
    ih += '<div class="issue-hd wrn" style="margin-top:10px">Warnings</div>';
    data.warnings.forEach(w => ih += '<div class="issue-li">' + esc(w) + '</div>');
  }
  issuesEl.innerHTML = ih;
  el.scrollIntoView({behavior:'smooth', block:'start'});
}

function esc(s) { const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }

function copyJson() {
  if (lastResponse) navigator.clipboard.writeText(JSON.stringify(lastResponse, null, 2)).catch(() => {});
}
</script>
</body>
</html>
"##;
