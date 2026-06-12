/**
 * CyberShield threat-intelligence configuration.
 *
 * Add your personal API keys below, then reload the unpacked extension from
 * chrome://extensions. Do not commit or distribute real API keys.
 */
self.CYBERSHIELD_CONFIG = Object.freeze({
  VIRUSTOTAL_API_KEY: "",
  ABUSEIPDB_API_KEY: "",
  CACHE_TTL_MS: 6 * 60 * 60 * 1000,
  ABUSE_LOOKBACK_DAYS: 90
});
