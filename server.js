// server.js
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const API_KEY = process.env.API_KEY || 'my-test-key';
const DATA_FILE = process.env.DB_FILE || 'db.json';

const app = express();

// Trust Render's proxy so rateLimit can read X-Forwarded-For
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initializeDatabase() {
  try {
    // Create api_keys table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT DEFAULT '',
        environment VARCHAR(50) DEFAULT 'production',
        key VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(20) DEFAULT 'active',
        created TIMESTAMPTZ DEFAULT NOW(),
        last_used TIMESTAMPTZ
      )
    `);

    // Check if we have any keys, if not, add the default one
    const result = await pool.query('SELECT COUNT(*) FROM api_keys');
    if (parseInt(result.rows[0].count) === 0) {
      console.log('Adding default API key to database...');
      await pool.query(`
        INSERT INTO api_keys (name, description, environment, key, status)
        VALUES ($1, $2, $3, $4, $5)
      `, [
        'Default Key',
        'Original environment variable key',
        'production',
        API_KEY,
        'active'
      ]);
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Helper functions for database operations
function readDatabase() {
  try {
    const data = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading database:', error);
    return { verticalDelay: [] };
  }
}

async function getActiveApiKeys() {
  try {
    const result = await pool.query('SELECT key FROM api_keys WHERE status = $1', ['active']);
    return result.rows.map(row => row.key);
  } catch (error) {
    console.error('Error getting active API keys:', error);
    return [];
  }
}

async function updateKeyLastUsed(usedKey) {
  try {
    await pool.query(
      'UPDATE api_keys SET last_used = NOW() WHERE key = $1',
      [usedKey]
    );
  } catch (error) {
    console.error('Error updating key last used:', error);
  }
}

// ——— API Key middleware ———
const apiKeyMiddleware = async (req, res, next) => {
  // Skip auth for admin endpoints
  if (req.path.startsWith('/admin')) {
    return next();
  }

  const key = req.header('x-api-key') || req.query.api_key;
  
  // DEBUG: Log what we're checking
  console.log('=== API KEY DEBUG ===');
  console.log('Request key:', key);
  
  const validKeys = await getActiveApiKeys();
  console.log('Valid keys from DB:', validKeys);
  console.log('Key found:', validKeys.includes(key));
  console.log('==================');
  
  if (!validKeys.includes(key)) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  
  // Update last used timestamp (don't await to avoid slowing down requests)
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
app.get('/admin/keys', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, description, environment, key, status, created, last_used
      FROM api_keys 
      ORDER BY created DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching API keys:', error);
    res.status(500).json({ error: 'Failed to fetch keys' });
  }
});

// Add new API key
app.post('/admin/keys', async (req, res) => {
  const { name, description, environment, key } = req.body;
  
  if (!name || !key) {
    return res.status(400).json({ error: 'Name and key are required' });
  }

  try {
    const result = await pool.query(`
      INSERT INTO api_keys (name, description, environment, key, status)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [
      name,
      description || '',
      environment || 'production',
      key,
      'active'
    ]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') { // Unique constraint violation
      res.status(400).json({ error: 'Key already exists' });
    } else {
      console.error('Error adding API key:', error);
      res.status(500).json({ error: 'Failed to save key' });
    }
  }
});

// Toggle key status
app.put('/admin/keys/:id/status', async (req, res) => {
  const keyId = parseInt(req.params.id);
  
  try {
    const result = await pool.query(`
      UPDATE api_keys 
      SET status = CASE WHEN status = 'active' THEN 'inactive' ELSE 'active' END
      WHERE id = $1
      RETURNING *
    `, [keyId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating key status:', error);
    res.status(500).json({ error: 'Failed to update key' });
  }
});

// Delete API key
app.delete('/admin/keys/:id', async (req, res) => {
  const keyId = parseInt(req.params.id);
  
  try {
    const result = await pool.query('DELETE FROM api_keys WHERE id = $1 RETURNING *', [keyId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Key not found' });
    }

    res.json({ message: 'Key deleted', key: result.rows[0] });
  } catch (error) {
    console.error('Error deleting key:', error);
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

async function startServer() {
  await initializeDatabase();
  app.listen(PORT, '0.0.0.0', () =>
    console.log(`API server with PostgreSQL admin dashboard listening on http://0.0.0.0:${PORT}`)
  );
}

startServer().catch(console.error);
