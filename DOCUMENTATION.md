# CyberShield Website Analyzer — Documentation

**Version:** 1.0  
**Type:** Chrome Browser Extension (Manifest V3)  
**Classification:** Academic / Research Project — Cybersecurity Tool

---

## 1. Introduction

CyberShield Website Analyzer is a professional-grade Chrome Extension that provides real-time cybersecurity assessment of any website a user visits. Built with a dark SOC (Security Operations Center) inspired interface, it analyzes local website characteristics and optional reputation data from VirusTotal and AbuseIPDB, then classifies sites as **Safe**, **Spam/Fake**, or **Phishing/Spoofed**.

## Threat Intelligence Setup

1. Create personal API keys in the [VirusTotal](https://www.virustotal.com/gui/join-us) and [AbuseIPDB](https://www.abuseipdb.com/register) dashboards.
2. Open `config.js`.
3. Set `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` to your keys.
4. Open `chrome://extensions`, enable Developer mode, and reload CyberShield.

```js
self.CYBERSHIELD_CONFIG = Object.freeze({
  VIRUSTOTAL_API_KEY: "your-virus-total-key",
  ABUSEIPDB_API_KEY: "your-abuseipdb-key",
  CACHE_TTL_MS: 6 * 60 * 60 * 1000,
  ABUSE_LOOKBACK_DAYS: 90
});
```

Do not commit or distribute a configured `config.js`. Chrome extensions cannot
fully conceal bundled client-side secrets, so use personal, rate-limited keys.

Reputation responses are cached in `chrome.storage.local` for six hours by
normalized URL. This avoids repeat API calls when the popup is reopened or the
page is refreshed.

## Hybrid Classification

When VirusTotal is available, the final risk score is:

```text
20% local rule score + 60% VirusTotal score + 20% domain trust score
```

The trusted-domain whitelist reduces false positives for exact domains and
their subdomains. It never clears a site with VirusTotal malicious detections.
Keywords have a maximum local contribution of eight points and cannot produce
a phishing verdict without structural or external reputation evidence.

AbuseIPDB resolves the current hostname through Google Public DNS, then adds IP
abuse confidence, report count, country, and ISP evidence. It is used as
corroborating classification and confidence evidence rather than silently
replacing the requested 20/60/20 score.

---

## 2. Problem Statement

Phishing, spoofed, and spam websites pose a significant threat to internet users worldwide. Traditional antivirus and firewall solutions often fail to detect new or zero-day phishing domains in real time. Users lack immediate, actionable feedback about the safety of a page they are currently viewing.

**CyberShield** addresses this gap by running a local, instant analysis every time the user opens the extension popup.

---

## 3. Objectives

- Provide a real-time, client-side security assessment of the current webpage
- Implement a transparent and explainable rule-based classifier (no black-box ML)
- Extract 15+ meaningful security features from the URL and DOM
- Display a professional cybersecurity dashboard with visual analytics
- Remain usable offline through the local classifier when reputation APIs are unavailable
- Meet Manifest V3 compliance for Chrome Web Store submission readiness

---

## 4. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Chrome Browser                        │
│  ┌─────────────┐    ┌──────────────┐   ┌────────────┐  │
│  │  popup.html │    │  content.js  │   │background  │  │
│  │  popup.css  │◄──►│  features.js │   │  .js       │  │
│  │  popup.js   │    │  (injected)  │   │(SW: store) │  │
│  └──────┬──────┘    └──────┬───────┘   └────────────┘  │
│         │                  │                            │
│         ▼                  ▼                            │
│  ┌─────────────┐    ┌──────────────┐                    │
│  │classifier.js│    │  Active Tab  │                    │
│  │(Rule Engine)│    │   DOM + URL  │                    │
│  └─────────────┘    └──────────────┘                    │
└─────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| File | Role |
|------|------|
| `manifest.json` | Extension configuration, permissions, service worker |
| `popup.html` | Dashboard UI structure |
| `popup.css` | Dark cyber SOC theme, animations |
| `popup.js` | Orchestrator: triggers analysis, renders results, draws charts |
| `features.js` | Feature extraction from URL + live DOM |
| `classifier.js` | Risk scoring engine and classification logic |
| `content.js` | Content script: receives messages from popup |
| `background.js` | Service worker: stores last scan results per tab |

---

## 5. Workflow Diagram

```
User clicks extension icon
        │
        ▼
Get active tab URL & ID
        │
        ▼
Inject content scripts (features.js + content.js)
        │
        ▼
Send message: { action: "extractFeatures" }
        │
        ▼
content.js calls extractFeatures(url)
        │
        ├── URL-based features (length, chars, HTTPS, domain, TLD…)
        └── DOM-based features (forms, inputs, iframes, scripts, links…)
                │
                ▼
        Return features object
                │
                ▼
        runClassifier(features)
                │
                ├── calculateRiskScore()  → weighted sum + breakdown
                ├── classify(score)       → SAFE / SPAM / PHISHING
                └── calcConfidence()     → 0–100%
                        │
                        ▼
                renderResults(url, features, result)
                        │
                        ├── Site Info Card
                        ├── Classification Badge
                        ├── Confidence Circle
                        ├── Risk Gauge
                        ├── Feature Grid
                        ├── Threat Intelligence
                        ├── Bar / Radar / Pie Charts
                        └── Warning Message
                                │
                                ▼
                        Store result via background.js
```

---

## 6. Feature Extraction Process

Features are extracted from two sources:

### 6.1 URL-Based Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | URL Length | Total character count of the URL |
| 2 | Suspicious Character Count | Count of `@`, `-`, `_`, `%`, `=`, `?` |
| 3 | HTTPS Availability | Whether the URL uses `https://` |
| 4 | Domain Name Length | Character count of the hostname |
| 5 | Subdomain Count | Number of sub-levels beyond the root domain |
| 6 | IP Address in URL | Regex check for an IPv4 pattern as the host |
| 7 | URL Shortener | Match against known shortener domains |
| 8 | Suspicious TLD | Match against a list of high-risk TLDs |

### 6.2 DOM-Based Features

| # | Feature | Description |
|---|---------|-------------|
| 9 | Number of Forms | Count of `<form>` elements |
| 10 | Number of Input Fields | Count of `<input>` elements |
| 11 | Number of External Links | Links pointing to a different domain |
| 12 | Number of Iframes | Count of `<iframe>` elements |
| 13 | JavaScript Redirects | Presence of `window.location`, meta-refresh |
| 14 | Popup Scripts | Presence of `window.open`, `alert()`, `confirm()` |
| 15 | Phishing Keyword Count | Matches against 70+ phishing keyword list |

---

## 7. Rule-Based Classification Method

CyberShield uses a **weighted additive risk scoring** approach — each detected risk factor contributes a fixed number of points to a cumulative risk score.

### 7.1 Risk Factor Weights

| Risk Factor | Weight |
|-------------|--------|
| No HTTPS | +25 |
| IP Address in URL | +30 |
| URL Shortener | +20 |
| JS Redirect detected | +20 |
| Suspicious TLD | +15 |
| Long URL (>75 chars) | +15 |
| Long URL (>150 chars) | +20 |
| Phishing keywords (≥3) | +variable (max 25) |
| Suspicious login forms | +15 |
| Multiple forms (>1) | +10 |
| Excessive iframes (>2) | +10 |
| Excessive subdomains (>2) | +10 |
| Long domain (>30 chars) | +10 |
| Popup scripts | +10 |
| Many external links (>20) | +5 |
| Suspicious chars (>3) | +variable (max 20) |

### 7.2 Classification Thresholds

```
Risk Score  0–29  → SAFE
Risk Score 30–59  → SPAM / FAKE
Risk Score 60–100 → PHISHING / SPOOFED
```

---

## 8. Risk Scoring Formula

```
RiskScore = Σ (weight_i × indicator_i)
            where indicator_i ∈ {0, 1} or proportional

Capped at 100.

Confidence:
  SAFE:     100 − RiskScore
  SPAM:     50 + ((RiskScore − 30) / 30) × 30
  PHISHING: 75 + ((RiskScore − 60) / 40) × 24
```

---

## 9. Screenshots

*(Insert screenshots of the extension popup here for the lab report.)*

- Screenshot 1: Extension analyzing a safe website (e.g., https://wikipedia.org)
- Screenshot 2: Extension flagging a phishing/spam URL
- Screenshot 3: Feature Analysis grid with highlighted risk factors
- Screenshot 4: Graphical Analytics section (bar chart, radar, pie)

---

## 10. Results

The CyberShield analyzer was tested against a variety of URLs:

| Website Type | Example Pattern | Classification | Score |
|-------------|----------------|----------------|-------|
| Legitimate HTTPS site | `https://wikipedia.org` | SAFE | 0–15 |
| HTTP-only site | `http://example.com` | SAFE/SPAM | 25+ |
| Phishing pattern | IP + no HTTPS + keywords | PHISHING | 60+ |
| URL shortener | `bit.ly/...` | SPAM | 30–50 |
| Suspicious TLD | `free-gifts.tk` | SPAM/PHISHING | 45–70 |

---

## 11. Limitations

1. **API availability and quotas**: VirusTotal and AbuseIPDB results depend on configured keys, network access, and provider rate limits. The local classifier remains available as a fallback.
2. **False positives**: Legitimate sites with many forms or keywords (banking portals, government sites) may receive elevated scores.
3. **Obfuscated attacks**: Adversarial sites that deliberately avoid rule triggers may evade classification.
4. **JavaScript-heavy SPAs**: Some DOM features may not be fully available if the page hasn't finished rendering.
5. **No ML/AI**: The classifier cannot learn or adapt to new attack patterns without manual rule updates.

---

## 12. Future Improvements

1. **Integration with Google Safe Browsing API** for real-time blocklist lookup
2. **Machine Learning classifier** trained on labeled phishing datasets (e.g., PhishTank)
3. **WHOIS lookup** to check domain age (newly registered domains are higher risk)
4. **SSL certificate inspection** beyond simple HTTPS check (issuer, validity, SANs)
5. **Browser history cross-referencing** to flag impersonation of visited sites
6. **User feedback loop** to improve rules over time
7. **Multi-language phishing keyword support**

---

## 13. Conclusion

CyberShield Website Analyzer demonstrates that a lightweight, rule-based approach can provide meaningful and immediate security signals to users. By extracting 15+ features from the URL and DOM and applying a transparent weighted scoring system, the extension offers an explainable alternative to black-box ML models. It is fully offline-capable, Manifest V3 compliant, and ready for academic evaluation and potential Chrome Web Store submission.

---

*CyberShield Website Analyzer v1.0 — Academic Cybersecurity Project*
