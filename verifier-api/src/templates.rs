pub const LANDING_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Cyntrisec Trust Center</title>
  <style>
    @import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap");
    *{margin:0;padding:0;box-sizing:border-box}
    :root{
      --bg-0:#050505;--bg-1:#0a0a0a;--bg-2:#111111;--bg-3:#181818;--bg-card:#0c0c0c;
      --border:#1a1a1a;--border-hi:#252525;
      --text-0:#ffffff;--text-1:#e0e0e0;--text-2:#888888;--text-3:#555555;--text-muted:#717171;
      --accent:#00d4ff;--accent-dim:rgba(0,212,255,0.08);--accent-mid:rgba(0,212,255,0.16);
      --green:#00cc88;--green-dim:rgba(0,204,136,0.11);--red:#ff3355;--red-dim:rgba(255,51,85,0.11);
      --amber:#ffaa00;--amber-dim:rgba(255,170,0,0.11);
      --mono:"JetBrains Mono",monospace;--sans:"Inter",-apple-system,BlinkMacSystemFont,sans-serif;
      --shadow:0 24px 80px rgba(0,0,0,0.32);
    }
    html{scroll-behavior:smooth}
    body{
      min-height:100vh;
      background:
        radial-gradient(circle at 12% 0%, rgba(0,212,255,0.12), transparent 26%),
        radial-gradient(circle at 88% 10%, rgba(0,204,136,0.06), transparent 20%),
        linear-gradient(180deg, #060606 0%, #050505 34%, #030303 100%);
      color:var(--text-1);font-family:var(--sans);line-height:1.6;overflow-x:hidden;-webkit-font-smoothing:antialiased;
    }
    body::before{
      content:"";position:fixed;inset:0;pointer-events:none;opacity:.22;
      background-image:linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px),linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
      background-size:40px 40px;mask-image:linear-gradient(to bottom, rgba(0,0,0,0.48), transparent 78%);
    }
    body::after{
      content:"";position:fixed;inset:0;pointer-events:none;opacity:.025;
      background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.82' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
      background-size:256px;
    }
    .mono{font-family:var(--mono)}
    .container{width:min(1240px, calc(100vw - 2rem));margin:0 auto;padding:1.35rem 0 3rem;position:relative;z-index:1}
    .signal-bar{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;padding:.2rem 0;color:var(--text-3);font-size:.68rem;letter-spacing:.14em;text-transform:uppercase}
    .signal-bar strong{color:var(--accent);font-weight:700}
    .workspace-shell,.section,.limitations,.control-card{background:linear-gradient(180deg, rgba(15,15,15,0.95), rgba(8,8,8,0.94));border:1px solid var(--border);box-shadow:var(--shadow);position:relative;overflow:hidden}
    .workspace-shell::before,.section::before,.limitations::before,.control-card::before{content:"";position:absolute;inset:0 auto auto 0;width:100%;height:1px;background:linear-gradient(90deg, rgba(0,212,255,0.55), rgba(0,212,255,0), rgba(0,204,136,0.12));pointer-events:none}
    .workspace-shell{border-radius:26px;padding:1.4rem;margin-bottom:1.25rem}
    .workspace-grid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(360px,0.95fr);gap:1.2rem;align-items:start}
    .intro-panel{min-height:100%;padding:.25rem .2rem .2rem}
    .brand-row{display:flex;align-items:center;gap:.95rem;margin-bottom:1.2rem}
    .brand-mark{width:48px;height:48px;border-radius:14px;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg, var(--accent), #19bdf0 58%, #5ce9ff);color:#00131b;font-family:var(--mono);font-weight:800;letter-spacing:-.06em;box-shadow:0 0 30px rgba(0,212,255,0.16)}
    .brand-copy small{display:block;color:var(--text-3);font-size:.7rem;letter-spacing:.14em;text-transform:uppercase;margin-bottom:.15rem}
    .brand-copy h1{color:var(--text-0);font-size:1.02rem;letter-spacing:-.03em;font-weight:700}
    .eyebrow{color:var(--accent);font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;margin-bottom:.9rem}
    .headline{max-width:12ch;color:var(--text-0);font-size:clamp(2.6rem, 5vw, 4.9rem);line-height:.96;letter-spacing:-.08em;font-weight:800;margin-bottom:1rem}
    .lede{max-width:44rem;color:var(--text-2);font-size:1rem;line-height:1.78;margin-bottom:1.2rem}
    .hero-strip{display:inline-flex;align-items:center;gap:.65rem;padding:.42rem .78rem;border-radius:999px;border:1px solid rgba(0,212,255,0.18);background:rgba(0,212,255,0.05);color:var(--text-2);font-size:.76rem;margin-bottom:1.2rem}
    .hero-strip strong{color:var(--text-0);font-weight:600}
    .fact-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.85rem;margin-bottom:1rem}
    .fact-card{min-height:100%;border:1px solid var(--border);background:linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));border-radius:18px;padding:.9rem}
    .fact-card .fact-label{color:var(--text-3);font-size:.67rem;letter-spacing:.12em;text-transform:uppercase;margin-bottom:.55rem}
    .fact-card strong{display:block;color:var(--text-0);font-size:.96rem;letter-spacing:-.03em;margin-bottom:.25rem}
    .fact-card p{color:var(--text-2);font-size:.82rem;line-height:1.6}
    .frame-note{border:1px dashed rgba(255,170,0,0.2);border-radius:18px;padding:.9rem 1rem;background:linear-gradient(180deg, rgba(255,170,0,0.08), rgba(255,255,255,0.02));color:var(--text-2);font-size:.87rem;line-height:1.7}
    .frame-note strong{color:var(--amber);font-weight:700}
    .control-card{border-radius:22px;padding:1.15rem;align-self:stretch}
    .control-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap;margin-bottom:1rem}
    .control-head h2{color:var(--text-0);font-size:1.3rem;font-weight:700;letter-spacing:-.04em;margin-bottom:.2rem}
    .control-head p{color:var(--text-2);font-size:.9rem;max-width:26rem}
    .micro-note{padding:.35rem .62rem;border-radius:999px;border:1px solid var(--border-hi);background:rgba(255,255,255,0.02);color:var(--text-3);font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
    .samples{display:grid;grid-template-columns:auto 1fr;gap:.9rem;align-items:start;margin-bottom:1rem;padding:.95rem 1rem;border:1px dashed var(--border-hi);border-radius:18px;background:rgba(255,255,255,0.02)}
    .samples-label{color:var(--text-3);font-size:.68rem;letter-spacing:.12em;text-transform:uppercase;padding-top:.2rem}
    .sample-buttons{display:flex;gap:.55rem;flex-wrap:wrap}
    .sample-btn{padding:.5rem .82rem;border-radius:999px;border:1px solid var(--border-hi);background:var(--bg-1);color:var(--text-2);font-family:var(--mono);font-size:.74rem;cursor:pointer;transition:border-color .2s,color .2s,transform .2s,box-shadow .2s}
    .sample-btn:hover{color:var(--text-0);border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,0.08);transform:translateY(-1px)}
    .tabs{display:inline-flex;gap:.3rem;padding:.24rem;margin-bottom:1rem;border-radius:999px;border:1px solid var(--border);background:var(--bg-1)}
    .tab{padding:.48rem .88rem;border-radius:999px;color:var(--text-3);font-family:var(--mono);font-size:.74rem;letter-spacing:.08em;text-transform:uppercase;font-weight:600;cursor:pointer;transition:background .2s,color .2s,box-shadow .2s}
    .tab:hover{color:var(--text-1)}
    .tab.active{background:var(--accent);color:#00131b;box-shadow:0 0 28px rgba(0,212,255,0.16)}
    .tab-content{display:none}.tab-content.active{display:block}
    form{display:grid;gap:.82rem}
    label{display:block;color:var(--text-3);font-size:.7rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;font-family:var(--mono);margin-bottom:.38rem}
    textarea,input[type="text"]{width:100%;border:1px solid var(--border-hi);border-radius:16px;background:var(--bg-0);color:var(--text-0);padding:.9rem .95rem;font-size:.92rem;transition:border-color .2s,box-shadow .2s}
    textarea{min-height:200px;resize:vertical;font-family:var(--mono);font-size:.8rem;line-height:1.58}
    textarea:focus,input[type="text"]:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,0.08)}
    input[type="file"]{color:var(--text-2);font-size:.84rem;margin-top:.2rem}
    input[type="file"]::file-selector-button{margin-right:.65rem;padding:.45rem .78rem;border-radius:999px;border:1px solid var(--border-hi);background:var(--bg-2);color:var(--text-0);cursor:pointer;font-family:var(--mono);font-size:.72rem}
    .btn,.btn-outline{display:inline-flex;align-items:center;justify-content:center;gap:.45rem;cursor:pointer;transition:all .2s;text-decoration:none}
    .btn{border:1px solid var(--text-0);border-radius:999px;padding:.85rem 1.4rem;background:var(--text-0);color:var(--bg-0);font-family:var(--mono);font-size:.78rem;letter-spacing:.08em;text-transform:uppercase;font-weight:700}
    .btn:hover{background:transparent;color:var(--text-0);box-shadow:0 0 24px rgba(255,255,255,0.06)}
    .btn:disabled{opacity:.5;cursor:not-allowed}
    .btn-outline{border:1px solid var(--border-hi);border-radius:999px;padding:.62rem .95rem;background:transparent;color:var(--text-2);font-family:var(--mono);font-size:.74rem;letter-spacing:.05em;text-transform:uppercase;font-weight:600}
    .btn-outline:hover{color:var(--text-0);border-color:var(--accent)}
    .spinner{display:none;margin-top:1rem;color:var(--text-2);font-family:var(--mono);font-size:.78rem}
    #result{display:none;margin-top:1rem}
    .report-shell{display:grid;gap:1rem}
    .verdict-banner{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:1rem;align-items:center;border-radius:24px;padding:1.15rem 1.2rem;border:1px solid var(--border);background:linear-gradient(180deg, rgba(15,15,15,0.96), rgba(10,10,10,0.94));box-shadow:var(--shadow);position:relative;overflow:hidden}
    .verdict-banner.verified{background:linear-gradient(135deg, rgba(0,204,136,0.13), rgba(255,255,255,0.02)),linear-gradient(180deg, rgba(15,15,15,0.96), rgba(10,10,10,0.94));border-color:rgba(0,204,136,0.22)}
    .verdict-banner.invalid{background:linear-gradient(135deg, rgba(255,51,85,0.13), rgba(255,255,255,0.02)),linear-gradient(180deg, rgba(15,15,15,0.96), rgba(10,10,10,0.94));border-color:rgba(255,51,85,0.22)}
    .verdict-banner::after{content:"";position:absolute;right:-60px;top:-80px;width:220px;height:220px;border-radius:50%;background:radial-gradient(circle, rgba(255,255,255,0.08), transparent 68%);pointer-events:none}
    .verdict-icon{width:56px;height:56px;border-radius:18px;display:flex;align-items:center;justify-content:center;font-size:1.35rem;background:rgba(255,255,255,0.04);flex:0 0 auto}
    .verdict-kicker{color:var(--text-3);font-size:.68rem;letter-spacing:.12em;text-transform:uppercase;margin-bottom:.25rem}
    .verdict-text h3{color:var(--text-0);font-size:1.45rem;letter-spacing:-.04em;font-weight:800;margin-bottom:.2rem}
    .verdict-text p{color:var(--text-2);font-size:.84rem;max-width:46rem}
    .verdict-meta{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;justify-content:flex-end}
    .report-chip{padding:.35rem .62rem;border-radius:999px;border:1px solid rgba(255,255,255,0.08);background:rgba(255,255,255,0.03);color:var(--text-2);font-size:.7rem;line-height:1;white-space:nowrap}
    .report-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(300px,0.8fr);gap:1rem;align-items:start}
    .report-main,.report-side{display:grid;gap:1rem}
    .section,.limitations{border-radius:22px;padding:1.15rem}
    .section-title{color:var(--text-0);font-size:.78rem;font-family:var(--mono);letter-spacing:.14em;text-transform:uppercase;margin-bottom:.4rem}
    .section-subtitle{color:var(--text-2);font-size:.86rem;margin-bottom:1rem}
    .meta-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.9rem 1rem}
    .meta-grid dt{color:var(--text-3);font-size:.66rem;letter-spacing:.12em;text-transform:uppercase;font-family:var(--mono);margin-bottom:.22rem}
    .meta-grid dd{color:var(--text-0);font-size:.95rem;font-weight:600;letter-spacing:-.02em;word-break:break-word}
    .check-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.9rem;padding:.82rem 0;align-items:start}
    .check-row+.check-row{border-top:1px solid rgba(255,255,255,0.05)}
    .check-stack{display:grid;gap:.36rem;min-width:0}
    .check-topline{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap;min-width:0}
    .check-label{color:var(--text-1);font-size:.92rem;font-weight:600;letter-spacing:-.01em;word-break:break-word}
    .check-layer{padding:.2rem .42rem;border-radius:999px;background:rgba(255,255,255,0.04);color:var(--text-3);font-family:var(--mono);font-size:.63rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
    .check-detail{color:var(--text-muted);font-size:.8rem;line-height:1.6}
    .badge{padding:.24rem .55rem;border-radius:999px;font-family:var(--mono);font-size:.67rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
    .badge.pass{background:var(--green-dim);color:var(--green)} .badge.fail{background:var(--red-dim);color:var(--red)} .badge.skip{background:var(--amber-dim);color:var(--amber)}
    .issues-panel{min-height:100%}
    .issues-empty{color:var(--text-muted);font-size:.82rem}
    .issue-block+.issue-block{margin-top:.9rem}
    .issue-title{font-family:var(--mono);font-size:.72rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:.45rem}
    .issue-title.error{color:var(--red)} .issue-title.warning{color:var(--amber)}
    .issue-list{list-style:none;display:grid;gap:.38rem}
    .issue-list li{color:var(--text-2);font-size:.82rem;line-height:1.55;padding-left:.85rem;position:relative}
    .issue-list li::before{content:">";position:absolute;left:0;color:currentColor;font-family:var(--mono)}
    .issue-list li.error-item{color:#ff7a91} .issue-list li.warning-item{color:#ffc24a}
    .limitations{background:linear-gradient(180deg, rgba(255,170,0,0.08), rgba(255,255,255,0.02)),linear-gradient(180deg, rgba(15,15,15,0.96), rgba(10,10,10,0.94));border-color:rgba(255,170,0,0.17)}
    .limitations .section-title{color:var(--amber)}
    .limitations ul{list-style:none;display:grid;gap:.46rem}
    .limitations li{position:relative;padding-left:1rem;color:var(--text-2);font-size:.82rem;line-height:1.62}
    .limitations li::before{content:"/";position:absolute;left:0;top:0;color:var(--amber);font-family:var(--mono)}
    .actions{display:flex;gap:.7rem;flex-wrap:wrap}
    .empty-state{color:var(--text-muted);font-size:.82rem}
    .print-header{display:none}
    @media(max-width:1040px){.workspace-grid,.report-grid{grid-template-columns:1fr}}
    @media(max-width:760px){
      .container{width:min(100vw - 1rem, 100%);padding-top:.9rem;padding-bottom:1.5rem}
      .workspace-shell,.section,.limitations,.control-card,.verdict-banner{border-radius:18px}
      .workspace-shell,.control-card,.section,.limitations{padding:1rem}
      .headline{font-size:2.4rem;max-width:none}
      .fact-grid,.meta-grid{grid-template-columns:1fr}
      .samples{grid-template-columns:1fr}
      .verdict-banner{grid-template-columns:1fr;justify-items:start}
      .verdict-meta{justify-content:flex-start}
    }
    @media print{
      body{background:#fff;color:#000}
      body::before,body::after,.signal-bar,.workspace-shell,.actions,.spinner{display:none!important}
      .container{width:100%;margin:0;padding:0}
      #result{display:block!important}
      .verdict-banner,.section,.limitations{background:#fff!important;box-shadow:none!important;border-color:#d4d4d4!important}
      .verdict-banner.verified{background:#ecfdf5!important;border-color:#16a34a!important}
      .verdict-banner.invalid{background:#fff1f2!important;border-color:#e11d48!important}
      .report-grid,.meta-grid{grid-template-columns:1fr}
      .print-header{display:block!important;margin-bottom:.75rem;text-align:right;color:#666;font-size:.75rem}
    }
  </style>
</head>
<body>
<div class="container">
  <div class="signal-bar mono">
    <span><strong>Public verifier</strong> / trust the artifact, not the dashboard</span>
    <span>AIR v1 + legacy compatibility</span>
  </div>

  <section class="workspace-shell">
    <div class="workspace-grid">
      <section class="intro-panel">
        <div class="brand-row">
          <div class="brand-mark">C</div>
          <div class="brand-copy">
            <small>Cyntrisec / Trust Center</small>
            <h1>Independent receipt verification</h1>
          </div>
        </div>

        <p class="eyebrow mono">Portable evidence for confidential AI</p>
        <h2 class="headline">Verify the receipt, not the story around it.</h2>
        <div class="hero-strip mono">
          <span>Output:</span>
          <strong>signed artifact verification</strong>
        </div>
        <p class="lede">
          Inspect signed AI inference receipts without ongoing access to the original system.
          This surface checks signature integrity, receipt structure, and policy-relevant fields
          across AIR v1 and legacy formats.
        </p>

        <div class="fact-grid">
          <article class="fact-card">
            <div class="fact-label mono">Independent</div>
            <strong>No operator dashboard required</strong>
            <p>Bring the receipt and public key. Verify the artifact on its own terms.</p>
          </article>
          <article class="fact-card">
            <div class="fact-label mono">Portable</div>
            <strong>One artifact, multiple audiences</strong>
            <p>Use the same receipt for engineering review, buyer demos, or audit-oriented workflows.</p>
          </article>
          <article class="fact-card">
            <div class="fact-label mono">Tamper visible</div>
            <strong>Integrity failures show up fast</strong>
            <p>Corrupted or mismatched receipts fail verification and surface which layer broke.</p>
          </article>
        </div>

        <div class="frame-note">
          <strong>Scope guardrail:</strong> this page verifies the receipt artifact. It does not by itself
          prove data deletion, verify external attestation documents, or make legal/compliance conclusions.
        </div>
      </section>

      <section class="control-card">
        <div class="control-head">
          <div>
            <p class="eyebrow mono" style="margin-bottom:.4rem">Input surface</p>
            <h2>Load a receipt</h2>
            <p>Paste JSON or base64, or upload a receipt file plus the verification key.</p>
          </div>
          <div class="micro-note mono">No login required</div>
        </div>

        <div class="samples">
          <span class="samples-label mono">Quick samples</span>
          <div class="sample-buttons">
            <button class="sample-btn" onclick="loadSample('valid')">Valid AIR v1</button>
            <button class="sample-btn" onclick="loadSample('tampered')">Tampered AIR v1</button>
            <button class="sample-btn" onclick="loadSample('legacy')">Legacy receipt</button>
          </div>
        </div>

        <div class="tabs">
          <div class="tab active" onclick="switchTab('paste')">Paste receipt</div>
          <div class="tab" onclick="switchTab('upload')">Upload file</div>
        </div>

        <div id="pasteTab" class="tab-content active">
          <form id="pasteForm" onsubmit="verifyPaste(event)">
            <div>
              <label for="receiptJson">Receipt (JSON or base64)</label>
              <textarea id="receiptJson" placeholder='Paste receipt JSON or base64-encoded AIR v1 CBOR...'></textarea>
            </div>
            <div>
              <label for="publicKeyHex">Public key (64 hex chars)</label>
              <input type="text" id="publicKeyHex" placeholder="Ed25519 public key hex" class="mono"/>
            </div>
            <button type="submit" class="btn">Verify receipt</button>
          </form>
        </div>

        <div id="uploadTab" class="tab-content">
          <form id="uploadForm" onsubmit="verifyUpload(event)">
            <div>
              <label>Receipt file (.json or .cbor)</label>
              <input type="file" id="receiptFile" accept=".json,.cbor,.bin"/>
            </div>
            <div>
              <label>Public key (hex)</label>
              <input type="text" id="uploadKeyHex" placeholder="64 hex chars" class="mono"/>
            </div>
            <div>
              <label>Or upload key file (.bin, 32 bytes)</label>
              <input type="file" id="publicKeyFile" accept=".bin,.key"/>
            </div>
            <button type="submit" class="btn">Verify receipt</button>
          </form>
        </div>

        <div class="spinner" id="spinner">Verifying receipt...</div>
      </section>
    </div>
  </section>

  <div id="result">
    <div class="print-header" id="printHeader"></div>

    <div id="verdictBanner" class="verdict-banner"></div>

    <div class="report-shell">
      <div class="report-grid">
        <div class="report-main">
          <section class="section">
            <div class="section-title">Receipt summary</div>
            <div class="section-subtitle">Core metadata extracted from the signed artifact.</div>
            <dl class="meta-grid" id="meta"></dl>
          </section>

          <section class="section">
            <div class="section-title">Verification checks</div>
            <div class="section-subtitle">Checks are grouped by layer so failures are easier to interpret.</div>
            <div id="checks"></div>
          </section>
        </div>

        <div class="report-side">
          <aside class="limitations" id="limitations">
            <div class="section-title">What this verification does not prove</div>
            <ul>
              <li>This verification confirms the receipt artifact is correctly signed and structurally valid.</li>
              <li>It does not independently verify the attestation document or hardware measurements referenced in the receipt.</li>
              <li>It does not prove data was deleted after processing.</li>
              <li>It does not constitute a compliance determination under any regulatory framework.</li>
              <li>Receipt fields may support evidence workflows relevant to compliance, but verification alone is not a legal conclusion.</li>
            </ul>
          </aside>

          <section class="section issues-panel">
            <div class="section-title">Issues and notes</div>
            <div class="section-subtitle">Errors and warnings returned by the verifier.</div>
            <div id="issues" class="issues-empty">No issues reported.</div>
          </section>

          <div class="actions">
            <button class="btn-outline" onclick="window.print()">Print report</button>
            <button class="btn-outline" onclick="copyJson()">Copy JSON</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let lastResponse = null;

/* ── Samples ───────────────────────────────────────── */
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

  document.getElementById('printHeader').textContent =
    'Cyntrisec Trust Center — Verification Report — ' + new Date().toISOString();

  const vb = document.getElementById('verdictBanner');
  const isVerified = data.verified === true || data.verdict === 'verified';
  const fmtLabel = data.format === 'air_v1' ? 'AIR v1' : 'Legacy';
  const verifiedAt = data.verified_at ? new Date(data.verified_at * 1000).toISOString() : 'Unknown time';
  vb.className = 'verdict-banner ' + (isVerified ? 'verified' : 'invalid');
  vb.innerHTML = `
    <div class="verdict-icon">${isVerified ? '\u2705' : '\u274C'}</div>
    <div class="verdict-text">
      <div class="verdict-kicker mono">${esc(fmtLabel)} receipt</div>
      <h3>${isVerified ? 'Verified artifact' : 'Verification failed'}</h3>
      <p>${isVerified ? 'The supplied public key validated this receipt and its verification checks completed.' : 'The supplied public key and/or receipt contents did not validate. Review the failing layers below.'}</p>
    </div>
    <div class="verdict-meta">
      <span class="report-chip mono">${esc(fmtLabel)}</span>
      <span class="report-chip mono">${esc(verifiedAt)}</span>
    </div>`;

  const r = data.receipt || {};
  const meta = document.getElementById('meta');
  let metaHtml = '';
  if (r.receipt_id) metaHtml += `<div><dt>Receipt ID</dt><dd class="mono">${esc(r.receipt_id)}</dd></div>`;
  if (r.model_id) metaHtml += `<div><dt>Model</dt><dd>${esc(r.model_id)}${r.model_version ? ' v' + esc(r.model_version) : ''}</dd></div>`;
  if (r.platform) metaHtml += `<div><dt>Platform</dt><dd>${esc(r.platform)}</dd></div>`;
  if (r.issuer) metaHtml += `<div><dt>Issuer</dt><dd>${esc(r.issuer)}</dd></div>`;
  if (r.security_mode) metaHtml += `<div><dt>Security mode</dt><dd>${esc(r.security_mode)}</dd></div>`;
  if (r.execution_time_ms != null) metaHtml += `<div><dt>Execution time</dt><dd>${r.execution_time_ms} ms</dd></div>`;
  if (r.sequence_number != null) metaHtml += `<div><dt>Sequence</dt><dd>#${r.sequence_number}</dd></div>`;
  if (r.issued_at) metaHtml += `<div><dt>Issued at</dt><dd>${new Date(r.issued_at * 1000).toISOString()}</dd></div>`;
  metaHtml += `<div><dt>Format</dt><dd>${esc(fmtLabel)}</dd></div>`;
  meta.innerHTML = metaHtml || '<div><dt>Status</dt><dd>No receipt metadata available.</dd></div>';

  const checksEl = document.getElementById('checks');
  const arr = Array.isArray(data.checks) ? data.checks : [];
  let checksHtml = '';
  arr.forEach(c => {
    const s = (c.status || 'skip').toLowerCase();
    const layerBadge = c.layer ? `<span class="check-layer">${esc(c.layer)}</span>` : '';
    const detail = c.detail && s === 'fail'
      ? `<div class="check-detail">${esc(c.detail)}</div>`
      : '';
    checksHtml += `<div class="check-row">
      <div class="check-stack">
        <div class="check-topline">
          ${layerBadge}
          <span class="check-label">${esc(c.label || c.id)}</span>
        </div>
        ${detail}
      </div>
      <span class="badge ${s}">${s}</span>
    </div>`;
  });
  checksEl.innerHTML = checksHtml || '<div class="empty-state">No verification checks returned.</div>';

  const issuesEl = document.getElementById('issues');
  let issHtml = '';
  if (data.errors && data.errors.length) {
    issHtml += '<div class="issue-block"><div class="issue-title error">Errors</div><ul class="issue-list">';
    data.errors.forEach(e => issHtml += '<li class="error-item">' + esc(e) + '</li>');
    issHtml += '</ul></div>';
  }
  if (data.warnings && data.warnings.length) {
    issHtml += '<div class="issue-block"><div class="issue-title warning">Warnings</div><ul class="issue-list">';
    data.warnings.forEach(w => issHtml += '<li class="warning-item">' + esc(w) + '</li>');
    issHtml += '</ul></div>';
  }
  issuesEl.innerHTML = issHtml || '<div class="issues-empty">No errors or warnings reported.</div>';

  el.scrollIntoView({behavior:'smooth', block:'start'});
}

/* ── Helpers ──────────────────────────────────────── */
function esc(s) { const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }

function copyJson() {
  if (lastResponse) {
    navigator.clipboard.writeText(JSON.stringify(lastResponse, null, 2))
      .then(() => {})
      .catch(() => {});
  }
}
</script>
</body>
</html>
"##;
