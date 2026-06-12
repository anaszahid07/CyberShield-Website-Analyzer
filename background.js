/**
 * CyberShield Website Analyzer - Background Service Worker
 * Handles extension lifecycle, reputation API requests, and persistent caches.
 */

importScripts("config.js");

// Store last scan result per tab
const scanResults = {};
const CONFIG = self.CYBERSHIELD_CONFIG || {};
const CACHE_PREFIX = "cybershield:threat-intel:";

function hasApiKey(value) {
  return Boolean(value && value.trim() && !value.includes("YOUR_"));
}

function normalizeUrl(url) {
  const parsed = new URL(url);
  parsed.hash = "";
  return parsed.href;
}

function cacheKey(url) {
  const sourceState = [
    hasApiKey(CONFIG.VIRUSTOTAL_API_KEY) ? "vt1" : "vt0",
    hasApiKey(CONFIG.ABUSEIPDB_API_KEY) ? "abuse1" : "abuse0"
  ].join(":");
  return `${CACHE_PREFIX}${sourceState}:${encodeURIComponent(normalizeUrl(url))}`;
}

async function getCachedThreatIntel(url) {
  const key = cacheKey(url);
  const stored = await chrome.storage.local.get(key);
  const entry = stored[key];
  if (!entry || Date.now() - entry.cachedAt > (CONFIG.CACHE_TTL_MS || 21600000)) {
    if (entry) await chrome.storage.local.remove(key);
    return null;
  }
  return { ...entry.data, cached: true };
}

async function setCachedThreatIntel(url, data) {
  const key = cacheKey(url);
  await chrome.storage.local.set({
    [key]: { cachedAt: Date.now(), data }
  });
}

function base64UrlEncode(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  let payload = null;
  try {
    payload = await response.json();
  } catch (_) {
    payload = null;
  }

  if (!response.ok) {
    const message = payload?.error?.message || payload?.errors?.[0]?.detail ||
      `${response.status} ${response.statusText}`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function emptyVirusTotal(status, error = null) {
  return {
    available: false,
    status,
    harmless: 0,
    malicious: 0,
    suspicious: 0,
    undetected: 0,
    reputation: 0,
    score: null,
    lastAnalysisTimestamp: null,
    error
  };
}

function normalizeVirusTotal(payload) {
  const attributes = payload?.data?.attributes || {};
  const stats = attributes.last_analysis_stats || {};
  const harmless = Number(stats.harmless || 0);
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const undetected = Number(stats.undetected || 0);
  const total = harmless + malicious + suspicious + undetected +
    Number(stats.timeout || 0);
  const detectionRatio = total ? ((malicious + suspicious * 0.5) / total) * 100 : 0;
  const score = Math.min(100, Math.round(
    detectionRatio * 1.4 + malicious * 12 + suspicious * 5
  ));

  return {
    available: true,
    status: malicious > 0 ? "MALICIOUS" : suspicious > 0 ? "SUSPICIOUS" : "CLEAN",
    harmless,
    malicious,
    suspicious,
    undetected,
    reputation: Number(attributes.reputation || 0),
    score,
    lastAnalysisTimestamp: attributes.last_analysis_date
      ? new Date(attributes.last_analysis_date * 1000).toISOString()
      : null,
    error: null
  };
}

async function waitForVirusTotalAnalysis(analysisId, headers) {
  for (let attempt = 0; attempt < 5; attempt++) {
    if (attempt > 0) {
      await new Promise(resolve => setTimeout(resolve, 1200));
    }
    const analysis = await fetchJson(
      `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`,
      { headers }
    );
    if (analysis?.data?.attributes?.status === "completed") return;
  }
}

async function queryVirusTotal(url) {
  if (!hasApiKey(CONFIG.VIRUSTOTAL_API_KEY)) {
    return emptyVirusTotal("NOT_CONFIGURED");
  }

  const headers = { "x-apikey": CONFIG.VIRUSTOTAL_API_KEY.trim() };
  const normalizedUrl = normalizeUrl(url);

  try {
    const body = new URLSearchParams({ url: normalizedUrl });
    const submission = await fetchJson("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    if (submission?.data?.id) {
      await waitForVirusTotalAnalysis(submission.data.id, headers);
    }

    const report = await fetchJson(
      `https://www.virustotal.com/api/v3/urls/${base64UrlEncode(normalizedUrl)}`,
      { headers }
    );
    return normalizeVirusTotal(report);
  } catch (error) {
    return emptyVirusTotal(error.status === 429 ? "RATE_LIMITED" : "ERROR", error.message);
  }
}

async function resolveDomain(domain) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) return domain;

  const response = await fetchJson(
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`
  );
  const answer = (response.Answer || []).find(record =>
    record.type === 1 && /^(\d{1,3}\.){3}\d{1,3}$/.test(record.data)
  );
  return answer?.data || null;
}

function emptyAbuseIpDb(status, error = null) {
  return {
    available: false,
    status,
    ipAddress: null,
    abuseConfidenceScore: null,
    totalReports: null,
    country: null,
    isp: null,
    isWhitelisted: null,
    error
  };
}

async function queryAbuseIpDb(domain) {
  if (!hasApiKey(CONFIG.ABUSEIPDB_API_KEY)) {
    return emptyAbuseIpDb("NOT_CONFIGURED");
  }

  try {
    const ipAddress = await resolveDomain(domain);
    if (!ipAddress) return emptyAbuseIpDb("DNS_UNRESOLVED");

    const params = new URLSearchParams({
      ipAddress,
      maxAgeInDays: String(CONFIG.ABUSE_LOOKBACK_DAYS || 90)
    });
    const payload = await fetchJson(
      `https://api.abuseipdb.com/api/v2/check?${params}`,
      {
        headers: {
          Key: CONFIG.ABUSEIPDB_API_KEY.trim(),
          Accept: "application/json"
        }
      }
    );
    const data = payload?.data || {};
    const abuseConfidenceScore = Number(data.abuseConfidenceScore || 0);
    return {
      available: true,
      status: abuseConfidenceScore >= 75 ? "HIGH_RISK" :
        abuseConfidenceScore >= 25 ? "SUSPICIOUS" : "CLEAN",
      ipAddress: data.ipAddress || ipAddress,
      abuseConfidenceScore,
      totalReports: Number(data.totalReports || 0),
      country: data.countryName || data.countryCode || "Unknown",
      isp: data.isp || "Unknown",
      isWhitelisted: data.isWhitelisted ?? null,
      error: null
    };
  } catch (error) {
    return emptyAbuseIpDb(error.status === 429 ? "RATE_LIMITED" : "ERROR", error.message);
  }
}

async function analyzeThreatIntelligence(url, domain) {
  const cached = await getCachedThreatIntel(url);
  if (cached) return cached;

  const [virusTotal, abuseIpDb] = await Promise.all([
    queryVirusTotal(url),
    queryAbuseIpDb(domain)
  ]);
  const result = {
    virusTotal,
    abuseIpDb,
    cached: false,
    checkedAt: new Date().toISOString()
  };
  await setCachedThreatIntel(url, result);
  return result;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "storeScanResult") {
    const tabId = request.tabId;
    scanResults[tabId] = request.result;
    sendResponse({ success: true });
  }
  if (request.action === "getScanResult") {
    const tabId = request.tabId;
    sendResponse({ result: scanResults[tabId] || null });
  }
  if (request.action === "analyzeThreatIntelligence") {
    analyzeThreatIntelligence(request.url, request.domain)
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
  }
  return true;
});

// Clean up results when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete scanResults[tabId];
});
