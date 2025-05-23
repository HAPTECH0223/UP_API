// server.js
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const API_KEY = process.env.API_KEY || 'my-test-key';
const DATA_FILE = process.env.DB_FILE || 'db.json';

const app = express();

// Trust Render's proxy so rateLimit can read X-Forwarded-For
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());

// Helper functions for JSON file operations
function readDatabase() {
  try {
    const data = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading database:', error);
    return { verticalDelay: [], apiKeys: [] };
  }
}

function writeDatabase(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error('Error writing database:', error);
    return false;
  }
}

function getActiveApiKeys() {
  const db = readDatabase();
  return db.apiKeys
    .filter(key => key.status === 'active')
    .map(key => key.key);
}

function updateKeyLastUsed(usedKey) {
  const db = readDatabase();
  const keyIndex = db.apiKeys.findIndex(key => key.key === usedKey);
  if (keyIndex !== -1) {
    db.apiKeys[keyIndex].lastUsed = new Date().toISOString();
    writeDatabase(db);
  }
}

// ——— API Key middleware ———
const apiKeyMiddleware = (req, res, next) => {
  // Skip auth for admin endpoints
  if (req.path.startsWith('/admin')) {
    return next();
  }

  const key = req.header('x-api-key') || req.query.api_key;
  const validKeys = getActiveApiKeys();
  
  if (!validKeys.includes(key)) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  
  // Update last used timestamp
  updateKeyLastUsed(key);
  next();
};

// ——— Rate limiter setup ———
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  keyGenerator: (req) => {
    if (req.path.startsWith('/admin')) {
      return req.ip; // Use IP for admin endpoints
    }
    return req.header('x-api-key') || req.query.api_key || req.ip;
  }
});

// ——— Apply middleware ———
app.use(limiter);
app.use(apiKeyMiddleware);

// ——— Admin Dashboard Routes ———

// Serve admin dashboard
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Get all API keys
app.get('/admin/keys', (req, res) => {
  const db = readDatabase();
  res.json(db.apiKeys || []);
});

// Add new API key
app.post('/admin/keys', (req, res) => {
  const { name, description, environment, key } = req.body;
  
  if (!name || !key) {
    return res.status(400).json({ error: 'Name and key are required' });
  }

  const db = readDatabase();
  
  // Check if key already exists
  if (db.apiKeys.some(k => k.key === key)) {
    return res.status(400).json({ error: 'Key already exists' });
  }

  const newKey = {
    id: Date.now(), // Simple ID generation
    name,
    description: description || '',
    environment: environment || 'production',
    key,
    status: 'active',
    created: new Date().toISOString(),
    lastUsed: null
  };

  db.apiKeys.push(newKey);
  
  if (writeDatabase(db)) {
    res.status(201).json(newKey);
  } else {
    res.status(500).json({ error: 'Failed to save key' });
  }
});

// Toggle key status
app.put('/admin/keys/:id/status', (req, res) => {
  const keyId = parseInt(req.params.id);
  const db = readDatabase();
  
  const keyIndex = db.apiKeys.findIndex(k => k.id === keyId);
  if (keyIndex === -1) {
    return res.status(404).json({ error: 'Key not found' });
  }

  db.apiKeys[keyIndex].status = db.apiKeys[keyIndex].status === 'active' ? 'inactive' : 'active';
  
  if (writeDatabase(db)) {
    res.json(db.apiKeys[keyIndex]);
  } else {
    res.status(500).json({ error: 'Failed to update key' });
  }
});

// Delete API key
app.delete('/admin/keys/:id', (req, res) => {
  const keyId = parseInt(req.params.id);
  const db = readDatabase();
  
  const keyIndex = db.apiKeys.findIndex(k => k.id === keyId);
  if (keyIndex === -1) {
    return res.status(404).json({ error: 'Key not found' });
  }

  const deletedKey = db.apiKeys.splice(keyIndex, 1)[0];
  
  if (writeDatabase(db)) {
    res.json({ message: 'Key deleted', key: deletedKey });
  } else {
    res.status(500).json({ error: 'Failed to delete key' });
  }
});

// ——— Original API Routes ———
const data = readDatabase().verticalDelay || [];

// Single lookup
app.get('/api/v1/buildings/:id/vertical-delay', (req, res) => {
  const item = data.find(d => d.building_id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

// Bulk lookup
app.post('/api/v1/buildings/vertical-delay/bulk', (req, res) => {
  const ids = req.body.building_ids || [];
  const results = data.filter(d => ids.includes(d.building_id));
  res.json(results);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`API server with admin dashboard listening on http://0.0.0.0:${PORT}`)
);
