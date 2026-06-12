/**
 * CyberShield Website Analyzer - Content Script
 * Runs in the context of the current page. Extracts features and responds
 * to messages from the popup.
 */

// Listen for feature extraction requests from popup.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extractFeatures") {
    try {
      const features = extractFeatures(window.location.href);
      sendResponse({ success: true, features });
    } catch (err) {
      sendResponse({ success: false, error: err.message });
    }
    return true; // keep message channel open for async response
  }
});
