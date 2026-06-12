/**
 * CyberShield Website Analyzer - Hybrid Classification Engine
 * Combines local rules, VirusTotal reputation, and domain trust.
 */

const TRUSTED_DOMAINS = Object.freeze([
  "google.com", "youtube.com", "linkedin.com", "github.com", "microsoft.com",
  "apple.com", "amazon.com", "openai.com", "facebook.com", "instagram.com",
  "x.com", "reddit.com", "wikipedia.org", "stackoverflow.com", "paypal.com",
  "netflix.com"
]);

/**
 * Calculate the weighted risk score from extracted features.
 * @param {Object} features - Feature set from extractFeatures()
 * @returns {Object} - { score, breakdown }
 */
function calculateRiskScore(features) {
  const breakdown = [];
  let score = 0;

  // URL Length > 75 chars
  if (features.urlLength > 75) {
    const points = features.urlLength > 150 ? 20 : 15;
    score += points;
    breakdown.push({ label: "Long URL", points, value: features.urlLength + " chars" });
  }

  // No HTTPS
  if (!features.hasHttps) {
    score += 25;
    breakdown.push({ label: "No HTTPS", points: 25, value: "HTTP only" });
  }

  // IP address in URL
  if (features.hasIpAddress) {
    score += 30;
    breakdown.push({ label: "IP Address in URL", points: 30, value: features.domain });
  }

  // URL shortener
  if (features.isUrlShortener) {
    score += 20;
    breakdown.push({ label: "URL Shortener Detected", points: 20, value: features.domain });
  }

  // Suspicious TLD
  if (features.hasSuspiciousTld) {
    score += 15;
    breakdown.push({ label: "Suspicious TLD", points: 15, value: features.domain });
  }

  // Suspicious chars (@, -, _ etc.)
  if (features.suspiciousCharCount > 3) {
    const points = Math.min(features.suspiciousCharCount * 3, 20);
    score += points;
    breakdown.push({ label: "Suspicious Characters", points, value: features.suspiciousCharCount + " found" });
  }

  // Keywords are supporting context only and intentionally have low influence.
  if (features.phishingKeywordCount >= 3) {
    const points = Math.min(2 + Math.floor(features.phishingKeywordCount / 4), 8);
    score += points;
    breakdown.push({ label: "Phishing Keywords", points, value: features.phishingKeywordCount + " matched" });
  }

  // Multiple forms
  if (features.formCount > 1) {
    score += 10;
    breakdown.push({ label: "Multiple Forms", points: 10, value: features.formCount + " forms" });
  }

  // Suspicious forms (with password fields)
  if (features.suspiciousFormCount > 0) {
    score += 15;
    breakdown.push({ label: "Suspicious Login Forms", points: 15, value: features.suspiciousFormCount + " forms" });
  }

  // JavaScript redirects
  if (features.hasJsRedirect) {
    score += 20;
    breakdown.push({ label: "JS Redirect Detected", points: 20, value: "window.location / meta-refresh" });
  }

  // Popups
  if (features.hasPopup) {
    score += 10;
    breakdown.push({ label: "Popup Scripts", points: 10, value: "window.open / alert" });
  }

  // Iframes
  if (features.iframeCount > 2) {
    score += 10;
    breakdown.push({ label: "Multiple Iframes", points: 10, value: features.iframeCount + " iframes" });
  }

  // Excessive subdomains
  if (features.subdomainCount > 2) {
    score += 10;
    breakdown.push({ label: "Excessive Subdomains", points: 10, value: features.subdomainCount + " levels" });
  }

  // Domain length > 30 chars
  if (features.domainLength > 30) {
    score += 10;
    breakdown.push({ label: "Long Domain Name", points: 10, value: features.domainLength + " chars" });
  }

  // High external link ratio
  if (features.externalLinkCount > 20) {
    score += 5;
    breakdown.push({ label: "Many External Links", points: 5, value: features.externalLinkCount + " links" });
  }

  return { score: Math.min(score, 100), breakdown };
}

/**
 * Classify based on risk score.
 * < 30  → Safe
 * 30–59 → Spam/Fake
 * ≥ 60  → Phishing/Spoofed
 *
 * @param {number} score
 * @returns {string} - "SAFE" | "SPAM" | "PHISHING"
 */
function classify(score) {
  if (score < 30) return "SAFE";
  if (score < 60) return "SPAM";
  return "PHISHING";
}

function isTrustedDomain(domain) {
  const normalized = String(domain || "").toLowerCase().replace(/\.$/, "");
  return TRUSTED_DOMAINS.some(trusted =>
    normalized === trusted || normalized.endsWith(`.${trusted}`)
  );
}

function evaluateDomainTrust(features) {
  const trusted = isTrustedDomain(features.domain);
  let riskScore = trusted ? 0 : 35;
  if (features.hasIpAddress) riskScore += 35;
  if (features.isUrlShortener) riskScore += 25;
  if (features.hasSuspiciousTld) riskScore += 25;
  if (features.subdomainCount > 2) riskScore += 10;
  if (!features.hasHttps) riskScore += 10;

  return {
    trusted,
    status: trusted ? "TRUSTED" : "UNVERIFIED",
    score: Math.min(riskScore, 100),
    matchedDomain: trusted
      ? TRUSTED_DOMAINS.find(item =>
        features.domain === item || features.domain.endsWith(`.${item}`))
      : null
  };
}

function countStructuralPhishingIndicators(features) {
  return [
    features.hasIpAddress,
    features.isUrlShortener,
    features.hasSuspiciousTld,
    features.suspiciousFormCount > 0,
    features.hasJsRedirect,
    !features.hasHttps,
    features.subdomainCount > 2
  ].filter(Boolean).length;
}

function calculateFeatureConfidence(classification, score, domainTrust, features) {
  const urlRiskCount = [
    !features.hasHttps,
    features.urlLength > 75,
    features.suspiciousCharCount > 3,
    features.hasIpAddress,
    features.isUrlShortener,
    features.hasSuspiciousTld,
    features.subdomainCount > 2,
    features.domainLength > 30
  ].filter(Boolean).length;

  const behaviorRiskCount = [
    features.formCount > 2,
    features.inputFieldCount > 8,
    features.externalLinkCount > 20,
    features.iframeCount > 2,
    features.hasJsRedirect,
    features.hasPopup,
    features.suspiciousFormCount > 0
  ].filter(Boolean).length;

  let riskAlignment;
  if (classification === "SAFE") {
    riskAlignment = Math.max(35, 100 - score);
  } else if (classification === "SPAM") {
    riskAlignment = Math.max(45, 95 - Math.abs(score - 45) * 1.6);
  } else {
    riskAlignment = Math.min(98, 45 + score * 0.55);
  }

  const domainCharacteristics = domainTrust.trusted
    ? 96
    : Math.min(92, 52 + Math.abs(domainTrust.score - 35) * 0.8);
  const urlStructure = classification === "SAFE"
    ? Math.max(40, 92 - urlRiskCount * 12)
    : Math.min(94, 48 + urlRiskCount * 10);
  const behavioralIndicators = classification === "SAFE"
    ? Math.max(40, 90 - behaviorRiskCount * 11)
    : Math.min(94, 48 + behaviorRiskCount * 10);

  const totalRiskSignals = urlRiskCount + behaviorRiskCount;
  const featureConsistency = classification === "SAFE"
    ? Math.max(40, 94 - totalRiskSignals * 8)
    : classification === "SPAM"
      ? Math.max(50, 88 - Math.abs(totalRiskSignals - 3) * 8)
      : Math.min(96, 54 + totalRiskSignals * 7);

  const components = {
    riskAlignment: Math.round(riskAlignment),
    domainCharacteristics: Math.round(domainCharacteristics),
    urlStructure: Math.round(urlStructure),
    behavioralIndicators: Math.round(behavioralIndicators),
    featureConsistency: Math.round(featureConsistency)
  };
  const confidence = Math.round(
    components.riskAlignment * 0.3 +
    components.domainCharacteristics * 0.2 +
    components.urlStructure * 0.15 +
    components.behavioralIndicators * 0.2 +
    components.featureConsistency * 0.15
  );

  return {
    confidence: Math.max(35, Math.min(confidence, 98)),
    components
  };
}

/**
 * Convert risk score to confidence percentage.
 * @param {number} score
 * @param {string} classification
 * @returns {number} - 0..100
 */
function calcConfidence(score, classification) {
  if (classification === "SAFE") {
    // Confidence in SAFE = inverse of risk
    return Math.round(100 - score);
  }
  if (classification === "SPAM") {
    // Scale 30–59 → 50–80%
    return Math.round(50 + ((score - 30) / 30) * 30);
  }
  // PHISHING: scale 60–100 → 75–99%
  return Math.round(75 + ((score - 60) / 40) * 24);
}

/**
 * Full classification pipeline.
 * @param {Object} features
 * @returns {Object} - classification result
 */
function runClassifier(features, intelligence = {}) {
  const { score: ruleScore, breakdown } = calculateRiskScore(features);
  const domainTrust = evaluateDomainTrust(features);
  const virusTotal = intelligence.virusTotal || {};
  const abuseIpDb = intelligence.abuseIpDb || {};
  const vtAvailable = virusTotal.available && Number.isFinite(virusTotal.score);
  const virusTotalScore = vtAvailable ? virusTotal.score : ruleScore;
  const score = Math.round(
    ruleScore * 0.2 +
    virusTotalScore * 0.6 +
    domainTrust.score * 0.2
  );

  const structuralIndicators = countStructuralPhishingIndicators(features);
  const maliciousDetections = Number(virusTotal.malicious || 0);
  const suspiciousDetections = Number(virusTotal.suspicious || 0);
  const abuseScore = Number(abuseIpDb.abuseConfidenceScore || 0);

  let classification;
  if (
    maliciousDetections >= 3 ||
    (maliciousDetections > 0 && abuseScore >= 75 && structuralIndicators >= 2) ||
    (score >= 70 && structuralIndicators >= 3)
  ) {
    classification = "PHISHING";
  } else if (
    maliciousDetections === 0 &&
    suspiciousDetections === 0 &&
    (domainTrust.trusted || score < 30)
  ) {
    classification = "SAFE";
  } else {
    classification = "SPAM";
  }

  // A trusted domain is never auto-cleared when VirusTotal detects malware.
  if (domainTrust.trusted && maliciousDetections > 0 && classification === "SAFE") {
    classification = "SPAM";
  }

  const confidenceResult = calculateFeatureConfidence(
    classification, score, domainTrust, features
  );
  const confidence = confidenceResult.confidence;

  const riskLevel = score < 30 ? "LOW" : score < 60 ? "MEDIUM" : "HIGH";

  // Domain risk score (0-100 based on domain-specific factors)
  let domainRisk = 0;
  if (features.hasIpAddress) domainRisk += 40;
  if (features.isUrlShortener) domainRisk += 30;
  if (features.hasSuspiciousTld) domainRisk += 20;
  if (features.subdomainCount > 2) domainRisk += 10;
  domainRisk = Math.min(domainRisk, 100);

  return {
    classification,
    score,
    ruleScore,
    virusTotalScore: vtAvailable ? virusTotalScore : null,
    domainTrustScore: domainTrust.score,
    domainTrust,
    intelligence,
    confidence,
    confidenceComponents: confidenceResult.components,
    riskLevel,
    breakdown,
    domainRisk,
    timestamp: new Date().toISOString()
  };
}
