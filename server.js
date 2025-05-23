// server.js
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const crypto = require('crypto');

const API_KEY = process.env.API_KEY || 'my-test-key';
const DATA_FILE = process.env.DB_FILE || 'db.json';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'secure-admin-password-123';

const app = express();

// Trust Render's proxy so rateLimit can read X-Forwarded-For
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());

// In-memory session store (in production, use Redis or database)
const sessions = new Map();

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
        last_used TIMESTAMPTZ,
        expires_at TIMESTAMPTZ,
        auto_disabled BOOLEAN DEFAULT FALSE
      )
    `);

    // Add expires_at column if it doesn't exist (for existing databases)
    await pool.query(`
      ALTER TABLE api_keys 
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS auto_disabled BOOLEAN DEFAULT FALSE
    `);

    // Check if we have any keys, if not, add the default one
    const result = await pool.query('SELECT COUNT(*) FROM api_keys');
    if (parseInt(result.rows[0].count) === 0) {
      console.log('Adding default API key to database...');
      // Default key expires in 1 year
      const defaultExpiry = new Date();
      defaultExpiry.setFullYear(defaultExpiry.getFullYear() + 1);
      
      await pool.query(`
        INSERT INTO api_keys (name, description, environment, key, status, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [
        'Default Key',
        'Original environment variable key',
        'production',
        API_KEY,
        'active',
        defaultExpiry
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
    // First, auto-disable expired keys
    await autoDisableExpiredKeys();
    
    const result = await pool.query('SELECT key FROM api_keys WHERE status = $1', ['active']);
    return result.rows.map(row => row.key);
  } catch (error) {
    console.error('Error getting active API keys:', error);
    return [];
  }
}

async function autoDisableExpiredKeys() {
  try {
    const result = await pool.query(`
      UPDATE api_keys 
      SET status = 'inactive', auto_disabled = TRUE
      WHERE status = 'active' 
      AND expires_at IS NOT NULL 
      AND expires_at <= NOW()
      RETURNING name, key
    `);
    
    if (result.rows.length > 0) {
      console.log(`Auto-disabled ${result.rows.length} expired API keys:`, 
        result.rows.map(r => r.name).join(', '));
    }
    
    return result.rows.length;
  } catch (error) {
    console.error('Error auto-disabling expired keys:', error);
    return 0;
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

// ——— Authentication Functions ———
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function createSession(username) {
  const sessionToken = generateSessionToken();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
  
  sessions.set(sessionToken, {
    username,
    expiresAt,
    createdAt: new Date()
  });
  
  return sessionToken;
}

function validateSession(sessionToken) {
  const session = sessions.get(sessionToken);
  if (!session) return false;
  
  if (new Date() > session.expiresAt) {
    sessions.delete(sessionToken);
    return false;
  }
  
  return session;
}

function cleanupExpiredSessions() {
  const now = new Date();
  for (const [token, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(token);
    }
  }
}

// Cleanup expired sessions every hour and check for expired keys
setInterval(() => {
  cleanupExpiredSessions();
  autoDisableExpiredKeys();
}, 60 * 60 * 1000); // Every hour

// ——— Authentication Middleware ———
const adminAuthMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const token = authHeader.split(' ')[1];
  const session = validateSession(token);
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
  
  req.user = session;
  next();
};

// ——— API Key middleware ———
const apiKeyMiddleware = async (req, res, next) => {
  // Skip auth for admin login endpoint
  if (req.path === '/admin/login' || req.path === '/admin' || req.path.startsWith('/admin/') && req.method === 'GET') {
    return next();
  }

  // Skip API key check for admin endpoints (they use session auth)
  if (req.path.startsWith('/admin')) {
    return next();
  }

  const key = req.header('x-api-key') || req.query.api_key;
  const validKeys = await getActiveApiKeys();
  
  if (!validKeys.includes(key)) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  
  // Update last used timestamp
  await updateKeyLastUsed(key);
  next();
};

// ——— Rate limiter setup ———
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,    // 15 minutes
  max: 100,                    // limit each API key to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  
  // Use API key as the rate limit identifier for API endpoints
  keyGenerator: (req) => {
    // For admin endpoints, use IP address
    if (req.path.startsWith('/admin')) {
      return `admin_${req.ip}`;
    }
    
    // For API endpoints, use the API key as identifier
    const apiKey = req.header('x-api-key') || req.query.api_key;
    if (apiKey) {
      return `api_${apiKey}`;
    }
    
    // Fallback to IP if no API key (though this should be rejected by middleware)
    return `fallback_${req.ip}`;
  },
  
  // Skip rate limiting for requests that will be rejected by API key middleware anyway
  skip: (req) => {
    // Don't rate limit admin endpoints differently
    if (req.path.startsWith('/admin')) {
      return false;
    }
    
    // Don't waste rate limit slots on requests without API keys
    // (they'll be rejected by apiKeyMiddleware anyway)
    const apiKey = req.header('x-api-key') || req.query.api_key;
    return !apiKey;
  }
});

// ——— Apply middleware ———
app.use(limiter);
app.use(apiKeyMiddleware);

// ——— Admin Authentication Routes ———

// Serve admin dashboard (login page)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Admin login endpoint
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  // Validate credentials
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const sessionToken = createSession(username);
    
    res.json({
      success: true,
      token: sessionToken,
      expiresIn: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      message: 'Login successful'
    });
  } else {
    // Add delay to prevent brute force attacks
    setTimeout(() => {
      res.status(401).json({ error: 'Invalid credentials' });
    }, 1000);
  }
});

// Admin logout endpoint
app.post('/admin/logout', adminAuthMiddleware, (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader.split(' ')[1];
  
  sessions.delete(token);
  res.json({ success: true, message: 'Logged out successfully' });
});

// Check session validity
app.get('/admin/verify', adminAuthMiddleware, (req, res) => {
  res.json({ 
    valid: true, 
    user: req.user.username,
    expiresAt: req.user.expiresAt 
  });
});

// ——— Protected Admin Dashboard Routes ———

// Get all API keys (protected)
app.get('/admin/keys', adminAuthMiddleware, async (req, res) => {
  try {
    // Auto-disable expired keys before fetching
    await autoDisableExpiredKeys();
    
    const result = await pool.query(`
      SELECT id, name, description, environment, key, status, created, last_used, expires_at, auto_disabled
      FROM api_keys 
      ORDER BY created DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching API keys:', error);
    res.status(500).json({ error: 'Failed to fetch keys' });
  }
});

// Add new API key (protected)
app.post('/admin/keys', adminAuthMiddleware, async (req, res) => {
  const { name, description, environment, key, expirationPeriod } = req.body;
  
  if (!name || !key) {
    return res.status(400).json({ error: 'Name and key are required' });
  }

  if (!expirationPeriod) {
    return res.status(400).json({ error: 'Expiration period is required' });
  }

  // Calculate expiration date
  const expiresAt = new Date();
  switch (expirationPeriod) {
    case 'day':
      expiresAt.setDate(expiresAt.getDate() + 1);
      break;
    case 'week':
      expiresAt.setDate(expiresAt.getDate() + 7);
      break;
    case 'month':
      expiresAt.setMonth(expiresAt.getMonth() + 1);
      break;
    default:
      return res.status(400).json({ error: 'Invalid expiration period. Use: day, week, or month' });
  }

  try {
    const result = await pool.query(`
      INSERT INTO api_keys (name, description, environment, key, status, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [
      name,
      description || '',
      environment || 'production',
      key,
      'active',
      expiresAt
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

// Toggle key status (protected)
app.put('/admin/keys/:id/status', adminAuthMiddleware, async (req, res) => {
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

// Delete API key (protected)
app.delete('/admin/keys/:id', adminAuthMiddleware, async (req, res) => {
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
    console.log(`Secure API server with admin dashboard listening on http://0.0.0.0:${PORT}`)
  );
}

startServer().catch(console.error);
