/**
 * CyberShield Website Analyzer - Feature Extraction Module
 * Extracts security-relevant features from the current webpage and URL.
 */

const PHISHING_KEYWORDS = [
  "login","signin","password","verify","verification","bank","banking",
  "secure","security","account","confirm","confirmation","wallet","payment",
  "credit card","debit card","otp","pin","token","authentication","mfa","2fa",
  "update","update account","unlock","locked","suspended","reactivate","claim",
  "reward","bonus","gift","urgent","immediately","action required","click here",
  "reset password","customer service","support team","tax refund","invoice",
  "billing","paypal","visa","mastercard","crypto","bitcoin","withdraw","deposit",
  "transaction","government","irs","customs","delivery","shipment","tracking",
  "package","amazon","microsoft","google","facebook","instagram","linkedin",
  "netflix","icloud","apple id"
];

const SUSPICIOUS_TLDS = [
  ".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link",
  ".download",".loan",".win",".bid",".trade",".review",".stream",".gdn",
  ".men",".work",".party",".date",".faith",".racing",".science"
];

const URL_SHORTENERS = [
  "bit.ly","tinyurl.com","goo.gl","ow.ly","t.co","is.gd","buff.ly",
  "adf.ly","shorte.st","bc.vc","sh.st","clk.sh","rebrand.ly","cutt.ly"
];

const SUSPICIOUS_CHARS = ["@", "-", "_", "%", "=", "?"];

/**
 * Extract all features from the current page and URL.
 * @param {string} url - The current page URL
 * @returns {Object} - Extracted feature set
 */
function extractFeatures(url) {
  const features = {};

  // --- URL-based features ---
  features.urlLength = url.length;

  features.suspiciousCharCount = SUSPICIOUS_CHARS.reduce((count, ch) => {
    return count + (url.split(ch).length - 1);
  }, 0);

  features.hasHttps = url.startsWith("https://");

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;

    features.domainLength = hostname.length;
    features.subdomainCount = hostname.split(".").length - 2;
    if (features.subdomainCount < 0) features.subdomainCount = 0;

    // IP address in hostname
    features.hasIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    // URL shortener
    features.isUrlShortener = URL_SHORTENERS.some(s => hostname.includes(s));

    // Suspicious TLD
    features.hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));

    features.domain = hostname;
    features.protocol = urlObj.protocol;
    features.fullPath = urlObj.pathname + urlObj.search;
  } catch {
    features.domainLength = 0;
    features.subdomainCount = 0;
    features.hasIpAddress = false;
    features.isUrlShortener = false;
    features.hasSuspiciousTld = false;
    features.domain = "unknown";
    features.protocol = "unknown";
    features.fullPath = "";
  }

  // --- DOM-based features ---
  const pageText = (document.body ? document.body.innerText : "").toLowerCase();
  const allLinks = document.querySelectorAll("a[href]");
  const forms = document.querySelectorAll("form");
  const inputs = document.querySelectorAll("input");
  const iframes = document.querySelectorAll("iframe");
  const scripts = document.querySelectorAll("script");

  features.formCount = forms.length;
  features.inputFieldCount = inputs.length;
  features.iframeCount = iframes.length;

  // External link count
  let externalLinks = 0;
  allLinks.forEach(a => {
    try {
      const href = new URL(a.href);
      if (href.hostname !== features.domain) externalLinks++;
    } catch { /* skip malformed */ }
  });
  features.externalLinkCount = externalLinks;

  // JavaScript redirects: look for window.location, location.href, meta refresh
  const scriptContents = Array.from(scripts)
    .map(s => s.innerText || s.textContent || "")
    .join(" ")
    .toLowerCase();
  const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
  features.hasJsRedirect = scriptContents.includes("window.location") ||
    scriptContents.includes("location.href") ||
    scriptContents.includes("location.replace") ||
    !!metaRefresh;

  // Popups
  features.hasPopup = scriptContents.includes("window.open") ||
    scriptContents.includes("alert(") ||
    scriptContents.includes("confirm(");

  // Phishing keywords in page text + URL
  const combined = (url + " " + pageText).toLowerCase();
  const foundKeywords = PHISHING_KEYWORDS.filter(kw => combined.includes(kw));
  features.phishingKeywordCount = foundKeywords.length;
  features.foundPhishingKeywords = foundKeywords.slice(0, 10); // top 10 for display

  // Suspicious forms (forms with password fields)
  let suspiciousForms = 0;
  forms.forEach(form => {
    const hasPassword = form.querySelector('input[type="password"]');
    const hasText = form.querySelector('input[type="text"], input[type="email"]');
    if (hasPassword || (hasText && features.phishingKeywordCount > 0)) suspiciousForms++;
  });
  features.suspiciousFormCount = suspiciousForms;

  return features;
}
