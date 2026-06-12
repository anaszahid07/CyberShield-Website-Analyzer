# 🛡️ CyberShield Website Analyzer

A professional Chrome Extension designed to analyze websites and classify them as:

* ✅ Safe
* ⚠️ Suspicious
* 🚨 Phishing / Spoofed

CyberShield combines feature extraction, heuristic analysis, threat intelligence reasoning, and a cybersecurity-focused dashboard to help users identify potentially malicious websites.

---

## 📌 Project Overview

CyberShield is a browser-based website analysis tool developed as part of a Privacy and Usable Security project.

The extension automatically inspects the currently opened website and extracts multiple security-related features, including:

* URL characteristics
* HTTPS status
* Forms and input fields
* Suspicious URL patterns
* Phishing-related keywords
* Embedded content indicators
* Redirect behavior
* Domain reputation indicators

Based on these observations, the system calculates a risk score and provides a security classification.

---

## ✨ Features

### Website Analysis

* Current URL extraction
* Domain analysis
* HTTPS verification
* Form detection
* Input field analysis
* External link detection
* Iframe detection
* Redirect analysis

### Threat Intelligence Analysis

* URL structure inspection
* Suspicious keyword detection
* Behavioral observations
* Risk assessment
* Security posture evaluation

### Classification Engine

The extension classifies websites into:

| Classification     | Description                            |
| ------------------ | -------------------------------------- |
| Safe               | No significant threats detected        |
| Suspicious         | Multiple warning signs observed        |
| Phishing / Spoofed | Strong indicators of phishing activity |

### Security Dashboard

* Cybersecurity-themed interface
* Real-time website scanning
* Confidence score visualization
* Risk meter
* Feature analysis panel
* Threat intelligence summary
* Security observations

---

## 🏗️ System Architecture

```text
Current Website
        │
        ▼
Feature Extraction Engine
        │
        ▼
Risk Assessment Engine
        │
        ▼
Threat Intelligence Analysis
        │
        ▼
Classification Module
        │
        ▼
CyberShield Dashboard
```

---

## 📂 Project Structure

```text
cybershield-extension/
│
├── manifest.json
├── popup.html
├── popup.css
├── popup.js
├── content.js
├── classifier.js
├── features.js
│
├── assets/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
│
└── screenshot/
```

---

## 🧠 Feature Extraction

The following features are analyzed:

* URL Length
* HTTPS Availability
* Suspicious Characters
* Number of Forms
* Number of Input Fields
* Number of External Links
* Number of Iframes
* JavaScript Redirects
* Popups Detection
* Domain Length
* Subdomain Count
* IP Address in URL
* URL Shorteners
* Suspicious TLD Detection
* Phishing Keywords

---

## 🔍 Classification Logic

CyberShield uses a rule-based security assessment model.

Risk indicators are assigned weights based on their severity.

Examples:

* Long URL
* Excessive Forms
* Multiple Suspicious Keywords
* IP-based URLs
* Suspicious Redirects
* Suspicious URL Structures

The cumulative score determines the final classification.

---

## 📊 Dashboard Components

### Website Information

Displays:

* Domain Name
* Full URL
* Protocol
* HTTPS Status
* Scan Timestamp

### Risk Assessment

Displays:

* Risk Meter
* Risk Score
* Confidence Score

### Feature Analysis

Displays extracted website characteristics and security indicators.

### Threat Intelligence Analysis

Provides analyst-style observations explaining why a website was classified in a particular category.

---

## 📸 Screenshots

### Dashboard Overview

<img src="https://raw.githubusercontent.com/anaszahid07/CyberShield-Website-Analyzer/main/screenshot/dashboard.png" width="900">

### Safe Website Detection

<img src="screenshots/safe-site.png" width="900">


### Suspicious Website Detection

<img src="screenshots/suspicious-site.png" width="900">

### Threat Intelligence Analysis

<img src="screenshots/threat-intelligence.png" width="900">

---

## 🚀 Installation

### Step 1

Clone the repository

```bash
git clone https://github.com/yourusername/cybershield-extension.git
```

### Step 2

Open Chrome and navigate to:

```text
chrome://extensions
```

### Step 3

Enable:

```text
Developer Mode
```

### Step 4

Click:

```text
Load Unpacked
```

### Step 5

Select:

```text
cybershield-extension
```

### Step 6

Open any website and click the CyberShield extension icon.

---

## 🛠️ Technologies Used

* HTML5
* CSS3
* JavaScript
* Chrome Extension Manifest V3

---

## ⚠️ Limitations

* Rule-based classification may generate false positives.
* Does not replace enterprise security tools.
* No real-time threat intelligence feeds.
* Relies on observable website characteristics.

---

## 🔮 Future Enhancements

* Machine Learning Classification
* Reputation Scoring
* Threat Intelligence Feed Integration
* Browser-wide URL Monitoring
* Historical Scan Reports
* Domain Reputation Database

---

## 👨‍💻 Author

Developed as a Privacy & Usable Security Project.

CyberShield Website Analyzer © 2026
