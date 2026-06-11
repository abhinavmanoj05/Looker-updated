// backend/db.js – Neo4j + MongoDB helpers
require('dotenv').config();
const neo4j = require('neo4j-driver');
const mongoose = require('mongoose');

// Neo4j driver
const neoDriver = neo4j.driver(
  process.env.NEO4J_URI || 'bolt://neo4j:7687',
  neo4j.auth.basic(process.env.NEO4J_USER || 'neo4j', process.env.NEO4J_PASSWORD || 'test')
);

// Simple Neo4j query wrapper
async function runCypher(query, params = {}) {
  const session = neoDriver.session();
  try {
    const result = await session.run(query, params);
    return result.records.map(r => r.toObject());
  } finally {
    await session.close();
  }
}

// Example search – returns nodes whose name contains the query
async function searchGraph(q) {
  const safe = q.replace(/"/g, '\\"');
  const query = `MATCH (n) WHERE toLower(n.name) CONTAINS toLower($q) RETURN n LIMIT 25`;
  return runCypher(query, { q: safe });
}

// MongoDB connection (documents for raw feeds)
async function connectMongo() {
  const uri = process.env.MONGO_URI || 'mongodb://mongo:27017/intel';
  await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('MongoDB connected');
}

// Simple schema for raw OSINT entries
const entrySchema = new mongoose.Schema({
  source: String,
  raw: String,
  createdAt: { type: Date, default: Date.now },
});
const Entry = mongoose.model('Entry', entrySchema);

module.exports = { runCypher, searchGraph, connectMongo, Entry };
