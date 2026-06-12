/**
 * CyberShield Website Analyzer - Popup Controller
 * Orchestrates feature extraction, classification, and UI rendering.
 */

/* ============================================================
   ENTRY POINT
   ============================================================ */
document.addEventListener("DOMContentLoaded", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://")) {
      showError("Cannot analyze this page.<br>Please navigate to a website first.");
      return;
    }

    // Inject content scripts (in case they haven't loaded yet)
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["features.js", "content.js"]
      });
    } catch (_) { /* already injected, ignore */ }

    // Request feature extraction from the content script
    let features;
    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: "extractFeatures" });
      if (!response || !response.success) {
        throw new Error(response?.error || "No response");
      }
      features = response.features;
    } catch {
      // Fallback: run extraction in the page context
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          const PHISHING_KEYWORDS = [
            "login","signin","password","verify","verification","bank","banking",
            "secure","security","account","confirm","confirmation","wallet","payment",
            "credit card","debit card","otp","pin","token","authentication","mfa","2fa",
            "update","unlock","locked","suspended","reactivate","claim","reward","bonus",
            "gift","urgent","immediately","action required","click here","reset password",
            "customer service","support team","tax refund","invoice","billing","paypal",
            "visa","mastercard","crypto","bitcoin","withdraw","deposit","transaction",
            "government","irs","customs","delivery","shipment","tracking","package",
            "amazon","microsoft","google","facebook","instagram","linkedin","netflix",
            "icloud","apple id"
          ];
          const SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link",
            ".download",".loan",".win",".bid",".trade",".review",".stream",".men",".work",
            ".party",".date",".faith",".racing",".science"];
          const URL_SHORTENERS = ["bit.ly","tinyurl.com","goo.gl","ow.ly","t.co","is.gd",
            "buff.ly","adf.ly","shorte.st","bc.vc","cutt.ly"];
          const SUSPICIOUS_CHARS = ["@","-","_","%","=","?"];

          const url = window.location.href;
          const f = {};
          f.urlLength = url.length;
          f.suspiciousCharCount = SUSPICIOUS_CHARS.reduce((n,c) => n + (url.split(c).length-1), 0);
          f.hasHttps = url.startsWith("https://");

          try {
            const u = new URL(url);
            const h = u.hostname;
            f.domainLength = h.length;
            f.subdomainCount = Math.max(0, h.split(".").length - 2);
            f.hasIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(h);
            f.isUrlShortener = URL_SHORTENERS.some(s => h.includes(s));
            f.hasSuspiciousTld = SUSPICIOUS_TLDS.some(t => h.endsWith(t));
            f.domain = h;
            f.protocol = u.protocol;
            f.fullPath = u.pathname + u.search;
          } catch {
            f.domainLength = 0; f.subdomainCount = 0;
            f.hasIpAddress = false; f.isUrlShortener = false;
            f.hasSuspiciousTld = false; f.domain = "unknown";
            f.protocol = "unknown"; f.fullPath = "";
          }

          const pageText = (document.body?.innerText || "").toLowerCase();
          const forms = document.querySelectorAll("form");
          const inputs = document.querySelectorAll("input");
          const iframes = document.querySelectorAll("iframe");
          const scripts = document.querySelectorAll("script");
          const allLinks = document.querySelectorAll("a[href]");

          f.formCount = forms.length;
          f.inputFieldCount = inputs.length;
          f.iframeCount = iframes.length;

          let externalLinks = 0;
          allLinks.forEach(a => {
            try { if (new URL(a.href).hostname !== f.domain) externalLinks++; } catch {}
          });
          f.externalLinkCount = externalLinks;

          const sc = Array.from(scripts).map(s => (s.innerText||s.textContent||"")).join(" ").toLowerCase();
          const mr = document.querySelector('meta[http-equiv="refresh"]');
          f.hasJsRedirect = sc.includes("window.location") || sc.includes("location.href") ||
            sc.includes("location.replace") || !!mr;
          f.hasPopup = sc.includes("window.open") || sc.includes("alert(") || sc.includes("confirm(");

          const combined = (url + " " + pageText).toLowerCase();
          const found = PHISHING_KEYWORDS.filter(kw => combined.includes(kw));
          f.phishingKeywordCount = found.length;
          f.foundPhishingKeywords = found.slice(0,10);

          let suspForms = 0;
          forms.forEach(form => {
            if (form.querySelector('input[type="password"]') ||
              (form.querySelector('input[type="text"],input[type="email"]') && f.phishingKeywordCount > 0))
              suspForms++;
          });
          f.suspiciousFormCount = suspForms;
          return f;
        }
      });
      features = result.result;
    }

    if (!features) {
      showError("Unable to extract page features.<br>Try reloading the page.");
      return;
    }

    // Fetch reputation data in the background service worker. API failures do
    // not block local analysis; the classifier degrades conservatively.
    let intelligence = {};
    try {
      const intelResponse = await chrome.runtime.sendMessage({
        action: "analyzeThreatIntelligence",
        url: tab.url,
        domain: features.domain
      });
      if (intelResponse?.success && intelResponse.result) {
        intelligence = intelResponse.result;
      }
    } catch (_) { /* local classifier remains available */ }

    // Run the hybrid classifier (loaded from classifier.js)
    const result = runClassifier(features, intelligence);

    // Store result
    await chrome.runtime.sendMessage({
      action: "storeScanResult",
      tabId: tab.id,
      result: { features, ...result, url: tab.url }
    }).catch(() => {});

    // Render the UI
    renderResults(tab.url, features, result);

  } catch (err) {
    showError("An error occurred during analysis.<br>" + err.message);
  }
});

/* ============================================================
   RENDER
   ============================================================ */
function renderResults(url, features, result) {
  // Hide loader, show results
  document.getElementById("loadingWrap").classList.add("hidden");
  const content = document.getElementById("resultContent");
  content.classList.remove("hidden");
  content.classList.add("result-enter");

  // Update scan indicator
  document.getElementById("scanStatus").textContent = "Scan Complete";
  document.querySelector(".pulse-dot").style.background = getClassColor(result.classification);
  document.querySelector(".pulse-dot").style.boxShadow = `0 0 6px ${getClassColor(result.classification)}`;

  // --- Site Info ---
  document.getElementById("infoDomain").textContent = features.domain;
  document.getElementById("infoProtocol").textContent = features.protocol.replace(":", "").toUpperCase();
  document.getElementById("infoUrl").textContent = truncate(url, 60);
  const httpsEl = document.getElementById("infoHttps");
  httpsEl.textContent = features.hasHttps ? "Secured" : "Not Secured";
  httpsEl.style.color = features.hasHttps ? "var(--safe-color)" : "var(--phish-color)";
  document.getElementById("infoTimestamp").textContent = new Date(result.timestamp).toLocaleTimeString();

  // --- Classification Badge ---
  const cls = result.classification;
  const badge = document.getElementById("classificationBadge");
  badge.className = "classification-badge " + cls.toLowerCase();
  document.getElementById("badgeLabel").textContent =
    cls === "SAFE" ? "Safe" : cls === "SPAM" ? "Spam / Fake" : "Phishing";
  document.getElementById("badgeSub").textContent =
    cls === "SAFE" ? (result.domainTrust.trusted ? "Trusted Domain" : "No threats detected") :
    cls === "SPAM" ? "Suspicious content" : "High-risk site";

  // Badge icon changes
  const iconStroke = document.getElementById("badgeIconStroke");
  const iconPath = document.getElementById("badgeIconPath");
  if (cls === "SAFE") {
    iconStroke.setAttribute("d", "M12 2L4 6v6c0 5.25 3.4 10.15 8 11.5C16.6 22.15 20 17.25 20 12V6L12 2z");
    iconPath.setAttribute("d", "M12 2L4 6v6c0 5.25 3.4 10.15 8 11.5C16.6 22.15 20 17.25 20 12V6L12 2z");
    document.querySelector(".badge-check").setAttribute("d", "M9 12l2 2 4-4");
  } else if (cls === "SPAM") {
    document.querySelector(".badge-check").setAttribute("d", "M12 8v4m0 4h.01");
  } else {
    document.querySelector(".badge-check").setAttribute("d", "M12 8v4m0 4h.01");
  }

  // --- Confidence Circle ---
  const pct = result.confidence;
  const circumference = 201;
  const offset = circumference - (pct / 100) * circumference;
  const circFill = document.getElementById("confidenceCircle");
  circFill.style.strokeDashoffset = offset;
  circFill.style.stroke = getClassColor(cls);
  document.getElementById("confidencePct").textContent = pct + "%";
  document.getElementById("confidencePct").style.color = getClassColor(cls);

  // --- Risk Gauge ---
  const score = result.score;
  document.getElementById("riskScoreVal").textContent = score + " / 100";
  const needle = document.getElementById("gaugeNeedle");
  const fillPct = score + "%";
  needle.style.left = fillPct;
  document.getElementById("gaugeFill").style.width = fillPct;

  const riskBadge = document.getElementById("riskLevelBadge");
  riskBadge.textContent = result.riskLevel;
  riskBadge.className = "risk-level-badge " + result.riskLevel.toLowerCase();

  // --- Feature Grid ---
  const featureGrid = document.getElementById("featureGrid");
  featureGrid.innerHTML = "";
  const featureItems = [
    { name: "URL Length",        value: features.urlLength + " chars",    status: features.urlLength > 75 ? "danger" : "ok" },
    { name: "HTTPS",             value: features.hasHttps ? "Yes" : "No", status: features.hasHttps ? "ok" : "danger" },
    { name: "Forms",             value: features.formCount,               status: features.formCount > 1 ? "warn" : "ok" },
    { name: "Suspicious Chars",  value: features.suspiciousCharCount,     status: features.suspiciousCharCount > 3 ? "warn" : "ok" },
    { name: "Phishing Keywords", value: features.phishingKeywordCount,    status: features.phishingKeywordCount >= 3 ? "danger" : features.phishingKeywordCount > 0 ? "warn" : "ok" },
    { name: "Domain Risk",       value: result.domainRisk + "%",          status: result.domainRisk >= 50 ? "danger" : result.domainRisk > 0 ? "warn" : "ok" },
    { name: "Input Fields",      value: features.inputFieldCount,         status: "ok" },
    { name: "External Links",    value: features.externalLinkCount,       status: features.externalLinkCount > 20 ? "warn" : "ok" },
    { name: "Iframes",           value: features.iframeCount,             status: features.iframeCount > 2 ? "warn" : "ok" },
    { name: "JS Redirect",       value: features.hasJsRedirect ? "Yes" : "No", status: features.hasJsRedirect ? "warn" : "ok" },
    { name: "Popups",            value: features.hasPopup ? "Yes" : "No", status: features.hasPopup ? "warn" : "ok" },
    { name: "IP in URL",         value: features.hasIpAddress ? "Yes" : "No", status: features.hasIpAddress ? "danger" : "ok" },
    { name: "Domain Length",     value: features.domainLength + " chars", status: features.domainLength > 30 ? "warn" : "ok" },
    { name: "Subdomains",        value: features.subdomainCount,          status: features.subdomainCount > 2 ? "warn" : "ok" },
    { name: "Suspicious TLD",    value: features.hasSuspiciousTld ? "Yes" : "No", status: features.hasSuspiciousTld ? "danger" : "ok" },
    { name: "URL Shortener",     value: features.isUrlShortener ? "Yes" : "No", status: features.isUrlShortener ? "warn" : "ok" },
  ];

  featureItems.forEach(item => {
    featureGrid.innerHTML += `
      <div class="feature-item">
        <div class="feature-dot ${item.status}"></div>
        <div class="feature-content">
          <span class="feature-name">${item.name}</span>
          <span class="feature-value">${item.value}</span>
        </div>
      </div>`;
  });

  if (result.domainTrust.trusted) {
    featureGrid.innerHTML += `
      <div class="feature-item trusted-feature">
        <div class="feature-dot ok"></div>
        <div class="feature-content">
          <span class="feature-name">Domain Trust</span>
          <span class="feature-value trusted-badge">Trusted Domain</span>
        </div>
      </div>`;
  }

  // --- Threat Intelligence ---
  const threatEl = document.getElementById("threatIntel");
  const keywords = features.foundPhishingKeywords || [];
  const httpsStatus = features.hasHttps ? "ok" : "danger";
  const httpsText  = features.hasHttps ? "Secure (TLS)" : "No encryption";
  const susForms   = features.suspiciousFormCount;
  const jsRedirect = features.hasJsRedirect;
  const iframes    = features.iframeCount;
  const ipInUrl    = features.hasIpAddress;

  threatEl.innerHTML = `
    <div class="threat-item">
      <span class="threat-label">HTTPS Status</span>
      <span class="threat-value ${httpsStatus}">${httpsText}</span>
    </div>
    <div class="threat-item">
      <span class="threat-label">Suspicious Forms</span>
      <span class="threat-value ${susForms > 0 ? 'danger' : 'ok'}">${susForms} detected</span>
    </div>
    <div class="threat-item">
      <span class="threat-label">JS Redirect</span>
      <span class="threat-value ${jsRedirect ? 'warn' : 'ok'}">${jsRedirect ? "Detected" : "None"}</span>
    </div>
    <div class="threat-item">
      <span class="threat-label">IP in URL</span>
      <span class="threat-value ${ipInUrl ? 'danger' : 'ok'}">${ipInUrl ? "Yes — highly suspicious" : "No"}</span>
    </div>
    <div class="threat-item">
      <span class="threat-label">Iframes</span>
      <span class="threat-value ${iframes > 2 ? 'warn' : 'ok'}">${iframes} found</span>
    </div>
    <div class="threat-item">
      <span class="threat-label">Phishing Keywords</span>
      <span class="threat-value ${keywords.length >= 3 ? 'danger' : keywords.length > 0 ? 'warn' : 'ok'}">
        ${keywords.length > 0 ? keywords.slice(0,5).join(", ") : "None detected"}
      </span>
    </div>
    <div class="threat-item">
      <span class="threat-label">Security Observation</span>
      <span class="threat-value ${cls === 'SAFE' ? 'ok' : cls === 'SPAM' ? 'warn' : 'danger'}">
        ${getObservation(result)}
      </span>
    </div>`;

  renderThreatIntelligenceAnalysis(features, result);
  renderDebugConsole(url, features, result);

  // --- Charts ---
  renderBarChart(result.breakdown);
  renderRadarChart(features, result);
  renderPieChart(result);

  // --- Warning ---
  const warnCard = document.getElementById("warningCard");
  const warnText = document.getElementById("warningText");
  const warnIcon = document.getElementById("warningIcon");
  warnCard.className = "warning-card " + cls.toLowerCase();
  if (cls === "SAFE") {
    warnIcon.textContent = "✓";
    warnText.textContent = "No major security threats detected. This website appears to be safe.";
  } else if (cls === "SPAM") {
    warnIcon.textContent = "⚠";
    warnText.textContent = "This website contains suspicious characteristics. Exercise caution before entering any personal information.";
  } else {
    warnIcon.textContent = "⛔";
    warnText.textContent = "Warning! This website may attempt to steal your sensitive information. Do not enter any credentials or personal data.";
  }

  // --- Footer ---
  document.getElementById("footerStatus").textContent = "Scan completed · " + result.riskLevel + " RISK";
}

/* ============================================================
   BAR CHART
   ============================================================ */
function renderBarChart(breakdown) {
  const container = document.getElementById("barChart");
  if (!breakdown || breakdown.length === 0) {
    container.innerHTML = '<div class="chart-title" style="color:var(--safe-color);padding:4px 0">No risk factors detected</div>';
    return;
  }
  const maxPts = Math.max(...breakdown.map(b => b.points), 1);
  container.innerHTML = breakdown.map(item => {
    const pct = (item.points / maxPts) * 100;
    const color = item.points >= 20 ? "var(--phish-color)" : item.points >= 10 ? "var(--spam-color)" : "var(--neon-blue)";
    return `
      <div class="bar-row">
        <span class="bar-name" title="${item.label}">${item.label}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="bar-pts">+${item.points}</span>
      </div>`;
  }).join("");
}

/* ============================================================
   RADAR CHART (canvas)
   ============================================================ */
function renderRadarChart(features, result) {
  const canvas = document.getElementById("radarCanvas");
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2 + 4;
  const r = Math.min(W, H) / 2 - 20;

  const axes = [
    { label: "URL", value: Math.min(features.urlLength / 200, 1) },
    { label: "HTTPS", value: features.hasHttps ? 0 : 1 },
    { label: "Keywords", value: Math.min(features.phishingKeywordCount / 10, 1) },
    { label: "Forms", value: Math.min(features.formCount / 5, 1) },
    { label: "Domain", value: result.domainRisk / 100 },
    { label: "Redirect", value: features.hasJsRedirect ? 1 : 0 },
  ];

  const n = axes.length;
  const angle = (i) => (Math.PI * 2 * i) / n - Math.PI / 2;

  ctx.clearRect(0, 0, W, H);

  // Grid rings
  for (let ring = 1; ring <= 4; ring++) {
    const rr = (r * ring) / 4;
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
      const a = angle(i);
      const x = cx + rr * Math.cos(a);
      const y = cy + rr * Math.sin(a);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.strokeStyle = "rgba(0,245,255,0.12)";
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  // Axes
  axes.forEach((_, i) => {
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + r * Math.cos(angle(i)), cy + r * Math.sin(angle(i)));
    ctx.strokeStyle = "rgba(0,245,255,0.15)";
    ctx.stroke();
  });

  // Data polygon
  const clsColor = getClassColor(result.classification);
  ctx.beginPath();
  axes.forEach((ax, i) => {
    const rr = r * ax.value;
    const x = cx + rr * Math.cos(angle(i));
    const y = cy + rr * Math.sin(angle(i));
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.closePath();
  ctx.fillStyle = hexToRgba(clsColor, 0.2);
  ctx.fill();
  ctx.strokeStyle = clsColor;
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // Data points
  axes.forEach((ax, i) => {
    const rr = r * ax.value;
    const x = cx + rr * Math.cos(angle(i));
    const y = cy + rr * Math.sin(angle(i));
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = clsColor;
    ctx.fill();
  });

  // Labels
  ctx.font = "9px 'Exo 2', sans-serif";
  ctx.fillStyle = "rgba(90,122,154,0.9)";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  axes.forEach((ax, i) => {
    const labelR = r + 14;
    const x = cx + labelR * Math.cos(angle(i));
    const y = cy + labelR * Math.sin(angle(i));
    ctx.fillText(ax.label, x, y);
  });
}

/* ============================================================
   PIE CHART (canvas)
   ============================================================ */
function renderPieChart(result) {
  const canvas = document.getElementById("pieCanvas");
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2;
  const r = Math.min(W, H) / 2 - 14;

  const score = result.score;
  const safe  = Math.max(0, 29 - Math.min(score, 29));
  const spam  = score >= 30 && score < 60 ? score - 30 : (score >= 60 ? 29 : 0);
  const phish = score >= 60 ? score - 60 : 0;
  const rest  = Math.max(0, 100 - score);

  const segments = [
    { value: rest,   color: "rgba(0,212,170,0.7)",  label: "Safe Zone" },
    { value: spam,   color: "rgba(255,153,0,0.8)",   label: "Spam" },
    { value: phish,  color: "rgba(255,51,85,0.85)",  label: "Phishing" },
  ].filter(s => s.value > 0);

  const total = segments.reduce((sum, s) => sum + s.value, 0) || 1;

  ctx.clearRect(0, 0, W, H);

  let startAngle = -Math.PI / 2;
  segments.forEach(seg => {
    const sweep = (seg.value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, startAngle + sweep);
    ctx.closePath();
    ctx.fillStyle = seg.color;
    ctx.fill();
    ctx.strokeStyle = "rgba(5,13,26,0.9)";
    ctx.lineWidth = 2;
    ctx.stroke();
    startAngle += sweep;
  });

  // Inner circle (donut hole)
  ctx.beginPath();
  ctx.arc(cx, cy, r * 0.52, 0, Math.PI * 2);
  ctx.fillStyle = "#050d1a";
  ctx.fill();

  // Center text
  ctx.font = "bold 13px 'Exo 2', sans-serif";
  ctx.fillStyle = getClassColor(result.classification);
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(score, cx, cy - 6);
  ctx.font = "8px 'Exo 2', sans-serif";
  ctx.fillStyle = "rgba(90,122,154,0.8)";
  ctx.fillText("RISK", cx, cy + 8);

  // Legend
  const legendY = H - 2;
  const legendItems = segments.map(s => `${s.label}`);
  // (kept minimal given space constraints)
}

/* ============================================================
   THREAT INTELLIGENCE ANALYSIS
   ============================================================ */
function renderThreatIntelligenceAnalysis(features, result) {
  const container = document.getElementById("threatIntelAnalysis");
  const assessment = generateIntelligenceAssessment(features, result);

  container.innerHTML = assessment.map(item => `
    <div class="threat-item intelligence-observation">
      <span class="threat-label">${escapeHtml(item.category)}</span>
      <span class="threat-value ${item.status}">${escapeHtml(item.observation)}</span>
    </div>
  `).join("");
}

function generateIntelligenceAssessment(features, result) {
  const classification = result.classification;
  const trusted = result.domainTrust?.trusted;
  const structuralRisks = [
    !features.hasHttps,
    features.urlLength > 75,
    features.suspiciousCharCount > 3,
    features.hasIpAddress,
    features.isUrlShortener,
    features.subdomainCount > 2,
    features.hasJsRedirect
  ].filter(Boolean).length;
  const credentialSignals = features.suspiciousFormCount > 0 &&
    features.phishingKeywordCount > 0;

  let securityPosture;
  if (features.hasHttps && trusted) {
    securityPosture = "HTTPS encryption is active and domain characteristics match a trusted web service.";
  } else if (features.hasHttps) {
    securityPosture = "HTTPS encryption is active; domain identity remains under contextual assessment.";
  } else {
    securityPosture = "Transport encryption is absent, increasing exposure of submitted information.";
  }

  const riskDetails = [];
  if (features.hasIpAddress) riskDetails.push("direct IP addressing");
  if (features.isUrlShortener) riskDetails.push("a shortened destination");
  if (features.urlLength > 75) riskDetails.push("an unusually long URL");
  if (features.suspiciousCharCount > 3) riskDetails.push("irregular URL characters");
  if (features.subdomainCount > 2) riskDetails.push("multiple subdomain levels");
  if (features.phishingKeywordCount > 0 && !trusted) {
    riskDetails.push("login-related language");
  }

  let riskIndicators;
  if (riskDetails.length === 0) {
    riskIndicators = "URL and domain indicators align with normal web activity.";
  } else {
    riskIndicators = `Observed indicators include ${joinNaturalLanguage(riskDetails.slice(0, 3))}.`;
  }

  const behaviorDetails = [];
  if (features.hasJsRedirect) behaviorDetails.push("redirect behavior was identified");
  if (features.formCount > 1) behaviorDetails.push("multiple input forms are present");
  if (features.inputFieldCount > 8) behaviorDetails.push("a high number of input fields is present");
  if (features.iframeCount > 2) behaviorDetails.push("multiple embedded content sources are loaded");
  if (features.externalLinkCount > 20) behaviorDetails.push("the page relies heavily on external links");
  if (credentialSignals) behaviorDetails.push("credential-entry and login-related signals overlap");

  const behavioralObservation = behaviorDetails.length
    ? `${capitalize(joinNaturalLanguage(behaviorDetails.slice(0, 3)))}.`
    : "No suspicious redirects or credential-harvesting behavior was identified.";

  let rationale;
  if (classification === "SAFE") {
    rationale = trusted
      ? "Consistent domain, URL, and behavioral signals support a low-risk classification."
      : "Observed indicators remain limited and consistent with legitimate web activity.";
  } else if (classification === "SPAM") {
    rationale = structuralRisks > 1
      ? "Several moderate-risk signals combine to produce a cautious Spam / Fake assessment."
      : "Content and domain signals are mixed, so the site cannot be assessed as fully trusted.";
  } else {
    rationale = credentialSignals
      ? "Credential-related behavior and multiple structural risk factors support the phishing classification."
      : "Multiple high-risk URL, domain, and behavioral indicators support the phishing classification.";
  }

  const action = classification === "SAFE"
    ? "Normal browsing may continue; remain attentive before sharing sensitive information."
    : classification === "SPAM"
      ? "Proceed cautiously and verify the site before entering personal or payment information."
      : "Leave the site and do not submit credentials, payment details, or personal information.";

  return [
    { category: "Security Posture", observation: securityPosture, status: features.hasHttps ? "ok" : "danger" },
    { category: "Risk Indicators", observation: riskIndicators, status: riskDetails.length ? (classification === "PHISHING" ? "danger" : "warn") : "ok" },
    { category: "Behavioral Observations", observation: behavioralObservation, status: behaviorDetails.length ? (classification === "PHISHING" ? "danger" : "warn") : "ok" },
    { category: "Classification Rationale", observation: rationale, status: classification === "SAFE" ? "ok" : classification === "SPAM" ? "warn" : "danger" },
    { category: "Recommended User Action", observation: action, status: classification === "SAFE" ? "ok" : classification === "SPAM" ? "warn" : "danger" }
  ];
}

function renderDebugConsole(url, features, result) {
  document.getElementById("debugConsole").textContent = [
    `URL scanned: ${url}`,
    `Rule score: ${result.ruleScore}/100`,
    `HTTPS: ${features.hasHttps ? "enabled" : "disabled"}`,
    `URL structure: ${features.urlLength} chars, ${features.suspiciousCharCount} suspicious characters`,
    `Behavioral signals: ${features.formCount} forms, ${features.iframeCount} iframes, ${features.hasJsRedirect ? "redirect detected" : "no redirect"}`,
    `Domain trust: ${result.domainTrust.trusted ? `trusted (${result.domainTrust.matchedDomain})` : "unverified"}`,
    `Hybrid score: ${result.score}/100`,
    `Final classification: ${result.classification}`,
    `Confidence: ${result.confidence}%`
  ].join("\n");
}

/* ============================================================
   HELPERS
   ============================================================ */
function getClassColor(cls) {
  if (cls === "SAFE")     return "#00d4aa";
  if (cls === "SPAM")     return "#ff9900";
  return "#ff3355";
}

function hexToRgba(hex, alpha) {
  if (hex.startsWith("#")) {
    const r = parseInt(hex.slice(1,3),16);
    const g = parseInt(hex.slice(3,5),16);
    const b = parseInt(hex.slice(5,7),16);
    return `rgba(${r},${g},${b},${alpha})`;
  }
  return hex;
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max) + "…" : str;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function joinNaturalLanguage(items) {
  if (items.length <= 1) return items[0] || "";
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
}

function capitalize(value) {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : value;
}

function getObservation(result) {
  if (result.classification === "SAFE") return "No significant threats found.";
  if (result.classification === "SPAM") return "Multiple suspicious signals detected. Treat with caution.";
  return "Site exhibits strong phishing indicators. Avoid entering any data.";
}

function showError(msg) {
  document.getElementById("loadingWrap").classList.add("hidden");
  document.getElementById("scanStatus").textContent = "Error";
  document.getElementById("mainContent").innerHTML =
    `<div class="error-state">${msg}</div>`;
}
