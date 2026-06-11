// backend/server.js – Express API without authentication
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const db = require('./db');
const scraper = require('./scraper');
const osint = require('./osint'); // placeholder for future OSINT APIs

const app = express();
const { connectMongo } = require('./db');
connectMongo().catch(err => console.error('Mongo connection error:', err));

// Security middlewares
app.use(helmet());
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(rateLimit({ windowMs: 1 * 60 * 1000, max: 100 }));

// Simple audit logger
app.use((req, res, next) => {
  const logEntry = `[${new Date().toISOString()}] ${req.ip} ${req.method} ${req.originalUrl}\n`;
  require('fs').appendFileSync('audit.log', logEntry);
  next();
});

// Public search endpoint
app.get('/api/search', async (req, res) => {
  const { q } = req.query;
  try {
    const result = await db.searchGraph(q);
    res.json({ success: true, data: result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Search failed' });
  }
});

// Public ingest endpoint (trigger scraper)
app.post('/api/ingest', async (req, res) => {
  try {
    await scraper.runOnce();
    res.json({ success: true, message: 'Ingestion started' });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Public model training endpoint
app.post('/api/train', async (req, res) => {
  const { spawn } = require('child_process');
  const py = spawn('python', ['backend/ml_worker.py']);
  py.stdout.on('data', data => console.log('ML:', data.toString()));
  py.stderr.on('data', data => console.error('ML ERR:', data.toString()));
  py.on('close', code => {
    if (code === 0) {
      res.json({ success: true, message: 'Model training completed' });
    } else {
      res.status(500).json({ success: false, error: 'Training failed' });
    }
  });
});

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Cron jobs – hourly scraper, nightly training at 02:00
cron.schedule('0 * * * *', async () => {
  console.log('Cron: Running hourly scraper');
  try { await scraper.runOnce(); } catch (e) { console.error('Scraper error:', e); }
});

cron.schedule('0 2 * * *', () => {
  console.log('Cron: Starting nightly ML training');
  const { spawn } = require('child_process');
  const py = spawn('python', ['backend/ml_worker.py']);
  py.stdout.on('data', d => console.log('ML (cron):', d.toString()));
  py.stderr.on('data', d => console.error('ML (cron) ERR:', d.toString()));
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => console.log(`Backend listening on port ${PORT}`));
