// backend/scraper.js – real OSINT integration using fetch functions
const { Entry, runCypher } = require('./db');
const { fetchPhishingDomains, fetchAbuseIPDB } = require('./osint');

// Ingest a list of raw items into MongoDB and Neo4j
async function ingestEntries(items) {
  for (const item of items) {
    // Save raw entry to MongoDB (label set later by ML worker)
    await Entry.create({ source: 'osint', raw: item });
    // Create a node in Neo4j if not exists
    const query = `MERGE (n:Entity {name: $name}) RETURN n`;
    await runCypher(query, { name: item });
  }
}

// Main scraper routine – pulls from multiple public sources
async function runOnce() {
  console.log('Scraper started');
  const [domains, iplist] = await Promise.all([
    fetchPhishingDomains(),
    fetchAbuseIPDB(),
  ]);
  const combined = [...domains, ...iplist];
  console.log(`Fetched ${domains.length} domains, ${iplist.length} IPs`);
  await ingestEntries(combined);
  console.log(`Ingested ${combined.length} OSINT items`);
}

module.exports = { runOnce };
