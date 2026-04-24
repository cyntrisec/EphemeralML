pub const LANDING_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Cyntrisec Trust Center</title>
  <meta name="description" content="Verify AIR v1 and legacy receipts from confidential AI inference. Checks signatures, receipt structure, and optional caller-supplied policy bindings."/>
  <meta property="og:title" content="Cyntrisec Trust Center"/>
  <meta property="og:description" content="Verify AIR v1 and legacy receipts from confidential AI inference. Checks signatures, receipt structure, and optional caller-supplied policy bindings."/>
  <meta property="og:type" content="website"/>
  <meta name="theme-color" content="#000000"/>
  <link rel="icon" href="https://cyntrisec.com/logo-mark-64.png" type="image/png"/>
  <style>
    @import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap");

    *{margin:0;padding:0;box-sizing:border-box;font-variant-ligatures:none}
    :root{
      --bg:#000;
      --bg-raised:rgba(0,0,0,.72);
      --bg-input:#020202;
      --ink:#fff;
      --ink-dim:rgba(255,255,255,.68);
      --ink-mute:rgba(255,255,255,.50);
      --ink-faint:rgba(255,255,255,.26);
      --rule:rgba(255,255,255,.14);
      --rule-hi:rgba(255,255,255,.28);
      --accent:#ff3838;
      --accent-dim:rgba(255,56,56,.16);
      --info:#8fdcff;
      --info-dim:rgba(143,220,255,.12);
      --green:#39ff7c;
      --green-dim:rgba(57,255,124,.10);
      --red:#ff5a5a;
      --red-dim:rgba(255,90,90,.10);
      --amber:#ffb84a;
      --amber-dim:rgba(255,184,74,.10);
      --font:"IBM Plex Mono","Menlo","Monaco",monospace;
      --max:1200px;
      --pad:20px;
    }

    html{scroll-behavior:smooth;background:var(--bg)}
    body{
      min-height:100vh;
      background:var(--bg);
      color:var(--ink);
      font:400 13px/1.6 var(--font);
      -webkit-font-smoothing:antialiased;
      letter-spacing:.01em;
      overflow-x:hidden;
      position:relative;
    }
    ::selection{background:var(--accent);color:var(--bg)}
    a{color:inherit;text-decoration:none}
    button,input,textarea{font:inherit}
    .mono{font-family:var(--font)}

    .field{
      position:fixed;
      inset:0;
      z-index:0;
      pointer-events:none;
      background:#000;
    }
    .field canvas{position:absolute;inset:0;width:100%;height:100%;display:block;opacity:.92}
    .field::before{
      content:"";
      position:absolute;
      inset:0;
      background:
        radial-gradient(circle at 50% 18%, rgba(143,220,255,.05), transparent 28%),
        radial-gradient(circle at 72% 22%, rgba(255,56,56,.03), transparent 14%),
        linear-gradient(180deg, rgba(0,0,0,.04), rgba(0,0,0,.26) 55%, rgba(0,0,0,.72));
    }
    .field::after{
      content:"";
      position:absolute;
      inset:0;
      background:repeating-linear-gradient(180deg, rgba(255,255,255,0) 0 2px, rgba(255,255,255,.014) 2px 3px);
      mix-blend-mode:overlay;
    }

    .hud{
      position:fixed;
      z-index:20;
      pointer-events:none;
      display:flex;
      gap:1rem;
      padding:.9rem 1.1rem;
      font:500 10px/1.3 var(--font);
      letter-spacing:.18em;
      text-transform:uppercase;
      color:var(--ink-mute);
    }
    .hud.tl{top:0;left:0}
    .hud.tr{top:0;right:0;text-align:right}
    .hud.bl{bottom:0;left:0}
    .hud.br{bottom:0;right:0;text-align:right}
    .hud span{display:inline-flex;align-items:center;gap:.4rem}
    .hud .dot{width:5px;height:5px;background:var(--accent);display:inline-block;animation:pulse 1.4s ease-in-out infinite}
    @keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}
    @media(max-width:760px){.hud{display:none}}

    .page{
      position:relative;
      z-index:5;
      max-width:var(--max);
      margin:0 auto;
      padding:28px var(--pad) 72px;
    }

    header{
      position:sticky;
      top:0;
      z-index:30;
      margin-bottom:28px;
      border-bottom:1px solid var(--rule);
      background:rgba(0,0,0,.74);
      backdrop-filter:blur(10px);
      -webkit-backdrop-filter:blur(10px);
    }
    .hdr{
      max-width:var(--max);
      margin:0 auto;
      padding:0 var(--pad);
      min-height:54px;
      display:grid;
      grid-template-columns:auto 1fr auto;
      gap:1.5rem;
      align-items:center;
    }
    .brand{
      display:inline-flex;
      align-items:center;
      gap:.55rem;
      color:var(--ink);
      font:600 12px/1 var(--font);
      letter-spacing:.18em;
      text-transform:uppercase;
    }
    .brand img{width:20px;height:20px;display:block}
    .brand em{
      font-style:normal;
      font-weight:500;
      color:var(--ink-mute);
      letter-spacing:.16em;
      margin-left:.35rem;
      padding-left:.55rem;
      border-left:1px solid var(--rule);
    }
    header nav{display:flex;gap:.35rem;justify-self:center}
    header nav a{
      padding:.5rem .8rem;
      color:var(--ink-dim);
      border:1px solid transparent;
      font:500 11px/1 var(--font);
      letter-spacing:.16em;
      text-transform:uppercase;
      transition:color .15s ease,border-color .15s ease;
    }
    header nav a:hover{color:var(--ink);border-color:var(--rule-hi)}
    .hdr-meta{
      text-align:right;
      color:var(--ink-mute);
      font:500 10px/1.3 var(--font);
      letter-spacing:.14em;
      text-transform:uppercase;
    }
    .hdr-meta strong{color:var(--ink);font-weight:500}
    @media(max-width:760px){
      .hdr{grid-template-columns:auto 1fr}
      header nav,.hdr-meta{display:none}
    }

    .panel{
      position:relative;
      border-bottom:1px solid var(--rule);
      padding:56px 0;
    }
    .panel-tag,
    .panel-num{
      position:absolute;
      top:14px;
      font:500 10px/1 var(--font);
      letter-spacing:.18em;
      text-transform:uppercase;
    }
    .panel-tag{left:0;color:var(--ink-mute)}
    .panel-num{right:0;color:var(--ink-faint)}
    .eyebrow{
      display:inline-flex;
      align-items:center;
      gap:.7rem;
      color:var(--accent);
      font:500 11px/1 var(--font);
      letter-spacing:.32em;
      text-transform:uppercase;
    }
    .eyebrow::before{content:"";width:32px;height:1px;background:var(--accent)}

    .hero-grid{
      display:grid;
      grid-template-columns:minmax(0,1fr) 320px;
      gap:2.4rem;
      align-items:end;
    }
    .hero h1{
      margin-top:1.3rem;
      font:700 clamp(2.2rem,7vw,4.8rem)/.95 var(--font);
      letter-spacing:-.02em;
      text-transform:uppercase;
      max-width:12ch;
    }
    .hero h1 .stroke{color:transparent;-webkit-text-stroke:1.2px var(--ink)}
    .hero h1 .accent{color:var(--accent)}
    .hero p{
      max-width:44rem;
      margin-top:1rem;
      padding-left:1rem;
      border-left:1px solid var(--accent);
      color:var(--ink-dim);
      font-size:14px;
      line-height:1.7;
    }
    .hero-meta{
      display:flex;
      flex-direction:column;
      gap:.7rem;
      padding:1rem 1.1rem;
      border:1px solid var(--rule);
      background:var(--bg-raised);
      backdrop-filter:blur(8px);
      -webkit-backdrop-filter:blur(8px);
      min-width:0;
    }
    .hero-meta-row{
      display:grid;
      grid-template-columns:auto 1fr;
      gap:.8rem;
      align-items:baseline;
      font:500 11px/1.3 var(--font);
      letter-spacing:.12em;
      text-transform:uppercase;
    }
    .hero-meta-row span:first-child{color:var(--ink-mute)}
    .hero-meta-row strong{color:var(--ink);font-weight:500;text-align:right}
    .hero-meta-row strong.acc{color:var(--accent)}
    @media(max-width:900px){
      .hero-grid{grid-template-columns:1fr}
      .hero-meta{max-width:420px}
    }

    .console{
      border:1px solid var(--rule);
      background:rgba(0,0,0,.62);
      backdrop-filter:blur(10px);
      -webkit-backdrop-filter:blur(10px);
    }
    .console-bar{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:1rem;
      padding:.85rem 1rem;
      border-bottom:1px solid var(--rule);
      font:500 11px/1 var(--font);
      letter-spacing:.14em;
      text-transform:uppercase;
      color:var(--ink-mute);
      flex-wrap:wrap;
    }
    .console-bar .dots{display:flex;gap:6px}
    .console-bar .dots i{width:6px;height:6px;background:var(--rule-hi);display:inline-block}
    .console-bar .dots i:first-child{background:var(--accent)}
    .console-body{padding:1.2rem}

    .sample-row{
      display:flex;
      align-items:center;
      gap:8px;
      margin-bottom:18px;
      flex-wrap:wrap;
    }
    .sample-row span{
      font:500 11px/1 var(--font);
      color:var(--ink-mute);
      text-transform:uppercase;
      letter-spacing:.18em;
    }
    .sample-btn,
    .btn-sm{
      background:none;
      border:1px solid var(--rule-hi);
      color:var(--ink-mute);
      font:500 11px/1 var(--font);
      letter-spacing:.14em;
      text-transform:uppercase;
      padding:7px 11px;
      cursor:pointer;
      transition:color .15s ease,border-color .15s ease,background .15s ease;
    }
    .sample-btn:hover,
    .btn-sm:hover{color:var(--ink);border-color:var(--ink)}

    .tab-bar{
      display:flex;
      gap:0;
      margin-bottom:18px;
      border-bottom:1px solid var(--rule);
    }
    .tab-btn{
      padding:9px 16px;
      font:500 11px/1 var(--font);
      letter-spacing:.18em;
      text-transform:uppercase;
      color:var(--ink-faint);
      background:none;
      border:none;
      border-bottom:2px solid transparent;
      cursor:pointer;
      transition:color .15s ease,border-color .15s ease;
      margin-bottom:-1px;
    }
    .tab-btn:hover{color:var(--ink-mute)}
    .tab-btn.on{color:var(--accent);border-bottom-color:var(--accent)}
    .tab-pane{display:none}
    .tab-pane.on{display:block}

    .field-group{margin-bottom:20px}
    .field-label{
      display:block;
      margin-bottom:8px;
      color:var(--ink-mute);
      font:500 11px/1 var(--font);
      letter-spacing:.18em;
      text-transform:uppercase;
    }
    textarea,
    input[type="text"]{
      width:100%;
      background:var(--bg-input);
      border:1px solid var(--rule);
      color:var(--ink);
      padding:11px 12px;
      border-radius:0;
      transition:border-color .15s ease;
      font:500 12px/1.55 var(--font);
    }
    textarea{min-height:156px;resize:vertical}
    textarea:focus,
    input[type="text"]:focus{outline:none;border-color:var(--accent)}
    input[type="file"]{
      width:100%;
      color:var(--ink-mute);
      font:500 12px/1 var(--font);
    }
    input[type="file"]::file-selector-button{
      margin-right:10px;
      background:rgba(255,255,255,.04);
      border:1px solid var(--rule);
      color:var(--ink);
      padding:8px 12px;
      border-radius:0;
      cursor:pointer;
      font:500 11px/1 var(--font);
      letter-spacing:.12em;
      text-transform:uppercase;
    }

    .verify-actions{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:10px}
    .btn-verify{
      display:inline-flex;
      align-items:center;
      gap:.7rem;
      padding:.95rem 1.25rem;
      border:1px solid var(--ink);
      background:var(--ink);
      color:var(--bg);
      font:600 11px/1 var(--font);
      letter-spacing:.22em;
      text-transform:uppercase;
      cursor:pointer;
      transition:background .15s ease,color .15s ease,border-color .15s ease;
    }
    .btn-verify::before{content:">";color:var(--accent)}
    .btn-verify:hover{background:var(--accent);border-color:var(--accent);color:var(--bg)}
    .btn-verify:hover::before{color:var(--bg)}

    .spinner{
      display:none;
      padding:16px 0 0;
      color:var(--ink-mute);
      font:500 11px/1 var(--font);
      letter-spacing:.18em;
      text-transform:uppercase;
    }

    #result{
      display:none;
      margin-top:28px;
      padding-top:28px;
      border-top:1px solid var(--rule);
    }
    .verdict{
      padding:18px 20px;
      border-left:2px solid var(--rule);
      margin-bottom:24px;
      background:rgba(255,255,255,.02);
    }
    .verdict.pass{border-left-color:var(--green);background:var(--green-dim)}
    .verdict.fail{border-left-color:var(--red);background:var(--red-dim)}
    .verdict h2{
      font:600 18px/1.1 var(--font);
      letter-spacing:.02em;
      text-transform:uppercase;
      margin-bottom:6px;
    }
    .verdict.pass h2{color:var(--green)}
    .verdict.fail h2{color:var(--red)}
    .verdict p{font-size:12px;color:var(--ink-mute)}

    .meta-tbl{
      width:100%;
      border-collapse:collapse;
      margin-bottom:24px;
      font:500 13px/1.55 var(--font);
    }
    .meta-tbl td{padding:8px 0;vertical-align:top}
    .meta-tbl td:first-child{
      width:150px;
      color:var(--ink-faint);
      font:500 11px/1.6 var(--font);
      letter-spacing:.14em;
      text-transform:uppercase;
    }
    .meta-tbl td:last-child{color:var(--ink-dim);word-break:break-all}
    .meta-tbl tr+tr td{border-top:1px solid var(--rule)}

    .checks-hd,
    .issue-hd{
      font:500 11px/1 var(--font);
      letter-spacing:.18em;
      text-transform:uppercase;
      margin-bottom:10px;
    }
    .checks-hd{color:var(--ink-mute)}
    .issue-hd.err{color:var(--red)}
    .issue-hd.wrn{color:var(--amber)}

    .ck{
      display:flex;
      align-items:flex-start;
      justify-content:space-between;
      gap:12px;
      padding:10px 0;
      font-size:13px;
    }
    .ck+.ck{border-top:1px solid var(--rule)}
    .ck-info{display:flex;flex-direction:column;gap:4px;min-width:0}
    .ck-name{color:var(--ink);font-weight:500}
    .ck-layer{
      color:var(--ink-faint);
      font:500 10px/1 var(--font);
      letter-spacing:.14em;
      text-transform:uppercase;
    }
    .ck-detail{font-size:12px;color:var(--ink-mute);line-height:1.5}

    .tag{
      flex-shrink:0;
      padding:4px 8px;
      font:600 10px/1 var(--font);
      letter-spacing:.12em;
      text-transform:uppercase;
    }
    .tag-pass{color:var(--green);background:var(--green-dim)}
    .tag-fail{color:var(--red);background:var(--red-dim)}
    .tag-skip{color:var(--amber);background:var(--amber-dim)}

    .issues-section{margin-top:24px}
    .issue-li{
      position:relative;
      padding-left:14px;
      margin-bottom:4px;
      color:var(--ink-mute);
      font-size:12px;
      line-height:1.6;
    }
    .issue-li::before{
      content:"›";
      position:absolute;
      left:0;
      color:inherit;
      font-family:var(--font);
    }
    .issue-li.err{color:#ff9b9b}

    .lim{
      margin-top:24px;
      padding:16px 18px;
      border:1px dashed var(--rule-hi);
      color:var(--ink-mute);
      font-size:12px;
      line-height:1.7;
    }
    .lim strong{
      display:block;
      margin-bottom:10px;
      color:var(--amber);
      font:500 11px/1 var(--font);
      letter-spacing:.18em;
      text-transform:uppercase;
    }
    .lim ul{list-style:none;margin:0;padding:0}
    .lim li{position:relative;padding-left:12px;margin-bottom:4px}
    .lim li::before{content:"–";position:absolute;left:0;color:var(--ink-faint)}

    .act-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}

    .privacy{
      margin-top:26px;
      padding-top:14px;
      border-top:1px solid var(--rule);
      color:var(--ink-faint);
      font-size:11px;
      line-height:1.7;
    }
    .privacy strong{color:var(--ink-mute);font-weight:500}
    .privacy a{color:var(--ink-mute)}

    footer{
      margin-top:34px;
      padding-top:16px;
      border-top:1px solid var(--rule);
      display:flex;
      justify-content:space-between;
      align-items:center;
      flex-wrap:wrap;
      gap:8px;
      color:var(--ink-faint);
      font:500 10px/1.4 var(--font);
      letter-spacing:.16em;
      text-transform:uppercase;
    }

    .print-header{display:none}
    @media(max-width:760px){
      .page{padding:18px var(--pad) 48px}
      .meta-tbl td:first-child{width:110px}
      .verdict{padding:14px 16px}
    }
    @media print{
      body{background:#fff;color:#111}
      .field,.hud,header,.sample-row,.tab-bar,.tab-pane,form,.spinner,.act-row,footer,.privacy{display:none!important}
      .page{max-width:100%;padding:0}
      #result{display:block!important;border-top:none;margin-top:0}
      .verdict{border:1px solid #ccc}
      .verdict.pass{background:#ecfdf5;border-left-color:#16a34a}
      .verdict.fail{background:#fff1f2;border-left-color:#e11d48}
      .tag-pass{background:#ecfdf5;color:#166534}
      .tag-fail{background:#fff1f2;color:#9f1239}
      .tag-skip{background:#fffbeb;color:#854d0e}
      .meta-tbl tr+tr td,.ck+.ck,.lim,.privacy{border-color:#ddd}
      .print-header{display:block!important;text-align:right;font-size:11px;color:#666;margin-bottom:12px}
    }
    @media(prefers-reduced-motion:reduce){
      html{scroll-behavior:auto}
      .hud .dot{animation:none}
    }
  </style>
</head>
<body>
  <div class="field" aria-hidden="true"><canvas id="trustField"></canvas></div>
  <div class="hud tl"><span><i class="dot"></i>CYNTRISEC</span><span>TRUST CENTER</span></div>
  <div class="hud tr"><span id="hudFrame">FRAME / 0000</span><span id="hudClock">00:00:00.000</span></div>
  <div class="hud bl"><span>RECEIPT / AIR_V1 · LEGACY</span><span>SIG / ED25519</span></div>
  <div class="hud br"><span>VERIFY / OFFLINE</span><span>ATTEST / OPTIONAL</span></div>

<header>
  <div class="hdr">
    <a class="brand" href="https://cyntrisec.com">
      <img src="https://cyntrisec.com/logo-ikeda.svg" alt="" width="20" height="20"/>
      <span>CYNTRISEC <em>// TRUST CENTER</em></span>
    </a>
    <nav>
      <a href="https://cyntrisec.com/docs">Docs</a>
      <a href="https://github.com/cyntrisec/EphemeralML">GitHub</a>
      <a href="https://cyntrisec.com/spec/air/v1/">Spec</a>
    </nav>
    <div class="hdr-meta">VERIFY / RECEIPTS <strong>· AIR_V1</strong></div>
  </div>
</header>

<main class="page">
  <section class="panel hero">
    <span class="panel-tag">// 001 / TRUST CENTER</span>
    <span class="panel-num">001</span>
    <div class="hero-grid">
      <div>
        <div class="eyebrow">RECEIPT VERIFICATION</div>
        <h1>VERIFY<br><span class="stroke">WITHOUT</span><br><span class="accent">TRUSTING US.</span></h1>
        <p>Check AIR v1 and legacy receipts from confidential AI inference. The paste flow validates receipt signatures and structure; API callers can add model, hash, freshness, and platform policy inputs for stricter verdicts.</p>
      </div>
      <div class="hero-meta" aria-label="verification surface">
        <div class="hero-meta-row"><span>Formats</span><strong>AIR_V1 · LEGACY</strong></div>
        <div class="hero-meta-row"><span>Key proof</span><strong class="acc">HEX / FILE / ATTEST</strong></div>
        <div class="hero-meta-row"><span>Signature</span><strong>ED25519</strong></div>
        <div class="hero-meta-row"><span>Output</span><strong>JSON VERDICT</strong></div>
        <div class="hero-meta-row"><span>Policy</span><strong>CALLER-SUPPLIED</strong></div>
      </div>
    </div>
  </section>

  <section class="panel">
    <span class="panel-tag">// 002 / VERIFY</span>
    <span class="panel-num">002</span>
    <div class="console">
      <div class="console-bar">
        <span class="dots"><i></i><i></i><i></i></span>
        <span>ephemeralml-verifier / public trust center</span>
        <span>stateless verdict surface</span>
      </div>
      <div class="console-body">
        <div class="sample-row">
          <span class="mono">Samples</span>
          <button type="button" class="sample-btn" onclick="loadSample('valid')">Valid AIR v1</button>
          <button type="button" class="sample-btn" onclick="loadSample('tampered')">Tampered AIR v1</button>
          <button type="button" class="sample-btn" onclick="loadSample('legacy')">Legacy</button>
        </div>

        <div class="tab-bar">
          <button type="button" class="tab-btn on" onclick="switchTab('paste')">Paste</button>
          <button type="button" class="tab-btn" onclick="switchTab('upload')">Upload</button>
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
            <div class="verify-actions">
              <button type="submit" class="btn-verify">Verify</button>
            </div>
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
            <div class="verify-actions">
              <button type="submit" class="btn-verify">Verify</button>
            </div>
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
            <button type="button" class="btn-sm" onclick="window.print()">Print</button>
            <button type="button" class="btn-sm" onclick="copyJson()">Copy JSON</button>
          </div>
        </div>
      </div>
    </div>
  </section>

  <div class="privacy">
    <strong>Privacy:</strong>
    Uploaded receipts are processed in memory and not stored. IP addresses are used for rate limiting only and discarded within minutes. No analytics or tracking. Source: <a href="https://github.com/cyntrisec/EphemeralML">github.com/cyntrisec/EphemeralML</a>
  </div>

  <footer>
    <span>&copy; 2026 Cyntrisec</span>
    <span class="mono">AIR v1 + legacy</span>
  </footer>
</main>

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
    ? 'Standards-based receipt (COSE/CWT/EAT) with signed claims and attestation reference'
    : 'Product-specific receipt format for compatibility';
  const vb = document.getElementById('verdictBanner');
  vb.className = 'verdict ' + (isOk ? 'pass' : 'fail');
  vb.innerHTML = `<h2>${isOk ? 'Verified' : 'Failed'}</h2><p>${esc(fmt)} receipt &middot; ${data.verified_at ? new Date(data.verified_at*1000).toISOString() : ''}</p><p style="margin-top:4px;font-size:11px;color:var(--ink-faint)">${esc(fmtNote)}</p>`;

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
  add('Assurance', data.assurance_level ? data.assurance_level.replaceAll('_', ' ') : null);
  add('TEE provenance', data.tee_provenance_verified === true ? 'verified' : 'not verified');
  if (r.model_hash_scheme) {
    add('Hash scheme', r.model_hash_scheme);
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
    const detail = c.detail && (s === 'fail' || s === 'skip') ? `<span class="ck-detail">${esc(c.detail)}</span>` : '';
    ch += `<div class="ck"><div class="ck-info">${layer}<span class="ck-name">${esc(c.label||c.id)}</span>${detail}</div><span class="tag ${cls}">${s}</span></div>`;
  });
  checksEl.innerHTML = ch || '<div style="color:var(--ink-faint);font-size:12px">No checks returned.</div>';

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

function esc(s) {
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function copyJson() {
  if (lastResponse) navigator.clipboard.writeText(JSON.stringify(lastResponse, null, 2)).catch(() => {});
}

(function() {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const frameEl = document.getElementById('hudFrame');
  const clockEl = document.getElementById('hudClock');
  let frame = 0;
  function tickHud() {
    frame = (frame + 1) % 99999;
    if (frameEl) frameEl.textContent = 'FRAME / ' + String(frame).padStart(4, '0');
    if (clockEl) {
      const d = new Date();
      clockEl.textContent =
        String(d.getUTCHours()).padStart(2, '0') + ':' +
        String(d.getUTCMinutes()).padStart(2, '0') + ':' +
        String(d.getUTCSeconds()).padStart(2, '0') + '.' +
        String(d.getUTCMilliseconds()).padStart(3, '0');
    }
    requestAnimationFrame(tickHud);
  }
  requestAnimationFrame(tickHud);
})();

(function() {
  const canvas = document.getElementById('trustField');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const dprCap = window.matchMedia('(max-width:760px)').matches ? 1 : 1.5;
  let W = 0, H = 0, visible = true;

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, dprCap);
    W = Math.max(1, Math.floor(window.innerWidth * dpr));
    H = Math.max(1, Math.floor(window.innerHeight * dpr));
    canvas.width = W;
    canvas.height = H;
    canvas.style.width = window.innerWidth + 'px';
    canvas.style.height = window.innerHeight + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function fract(x){return x - Math.floor(x);}
  function hash(x,y){return fract(Math.sin(x*127.1 + y*311.7) * 43758.5453);}
  function vnoise(x,y){
    const ix = Math.floor(x), iy = Math.floor(y);
    const fx = x - ix, fy = y - iy;
    const a = hash(ix,iy), b = hash(ix+1,iy), c = hash(ix,iy+1), d = hash(ix+1,iy+1);
    const ux = fx*fx*(3-2*fx), uy = fy*fy*(3-2*fy);
    return (a + (b-a)*ux)*(1-uy) + (c + (d-c)*ux)*uy;
  }

  const t0 = performance.now();
  function draw() {
    if (!visible) { requestAnimationFrame(draw); return; }
    const t = (performance.now() - t0) * 0.001;
    const w = window.innerWidth, h = window.innerHeight;
    ctx.fillStyle = '#000';
    ctx.fillRect(0,0,w,h);

    ctx.strokeStyle = 'rgba(255,255,255,0.045)';
    ctx.lineWidth = 1;
    const gs = 44;
    for (let x = 0; x <= w; x += gs) {
      ctx.beginPath(); ctx.moveTo(x + 0.5, 0); ctx.lineTo(x + 0.5, h); ctx.stroke();
    }
    for (let y = 0; y <= h; y += gs) {
      ctx.beginPath(); ctx.moveTo(0, y + 0.5); ctx.lineTo(w, y + 0.5); ctx.stroke();
    }

    const sx = ((t * 0.06) % 1) * w;
    ctx.strokeStyle = 'rgba(255,56,56,0.16)';
    ctx.beginPath(); ctx.moveTo(sx + 0.5, 0); ctx.lineTo(sx + 0.5, h); ctx.stroke();

    const grad = ctx.createLinearGradient(sx - 28, 0, sx + 28, 0);
    grad.addColorStop(0, 'rgba(255,56,56,0)');
    grad.addColorStop(0.5, 'rgba(255,56,56,0.035)');
    grad.addColorStop(1, 'rgba(255,56,56,0)');
    ctx.fillStyle = grad;
    ctx.fillRect(sx - 28, 0, 56, h);

    ctx.fillStyle = 'rgba(255,255,255,0.28)';
    for (let i = 0; i < 20; i++) {
      const nx = Math.floor(vnoise(i*1.9 + t*0.03, 2.4) * Math.floor(w/gs)) * gs;
      const ny = Math.floor(vnoise(i*0.8, t*0.025 + i) * Math.floor(h/gs)) * gs;
      ctx.fillRect(nx - 1.2, ny - 1.2, 2.4, 2.4);
    }

    if (!reduceMotion) requestAnimationFrame(draw);
  }

  resize();
  if (reduceMotion) {
    draw();
  } else {
    requestAnimationFrame(draw);
  }
  window.addEventListener('resize', resize, {passive:true});
  document.addEventListener('visibilitychange', function(){ visible = !document.hidden; });
})();
</script>
</body>
</html>
"##;
