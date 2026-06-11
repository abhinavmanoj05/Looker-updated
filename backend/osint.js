// backend/osint.js – fetch data from real public OSINT sources
require('dotenv').config();
const axios = require('axios');

// 1. Phishing domains list (already used in scraper as fallback)
async function fetchPhishingDomains() {
  const url = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains.txt';
  const resp = await axios.get(url);
  return resp.data.split(/\r?\n/).filter(l => l.trim().length > 0);
}

// 2. Recent tweets containing keywords (requires Bearer token)
async function fetchTwitterScams() {
  const token = process.env.TWITTER_BEARER_TOKEN;
  if (!token) return [];
  const url = 'https://api.twitter.com/2/tweets/search/recent?query=scam&max_results=10&tweet.fields=text';
  const resp = await axios.get(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.data || !resp.data.data) return [];
  return resp.data.data.map(t => t.text);
}

// 3. AbuseIPDB recent blacklist (requires API key)
async function fetchAbuseIPDB() {
  const key = process.env.ABUSEIPDB_KEY;
  if (!key) return [];
  const url = 'https://api.abuseipdb.com/api/v2/blacklist?limit=10';
  const resp = await axios.get(url, {
    headers: { Key: key, Accept: 'application/json' },
  });
  if (!resp.data || !resp.data.data) return [];
  return resp.data.data.map(entry => entry.ipAddress);
}

module.exports = { fetchPhishingDomains, fetchTwitterScams, fetchAbuseIPDB };
