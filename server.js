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
// Increase payload limit for sensor data
app.use(express.json({ limit: '10mb' }));

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

// Add this endpoint after your existing API routes in server.js

// ——— Building Database & Geofencing ———
const BUILDING_DATABASE = [
  {
    id: "walmart_catasauqua_pa",
    name: "Walmart Supercenter",
    address: "1731 MacArthur Rd, Whitehall, PA 18052",
    bounds: {
      north: 40.6825,
      south: 40.6815,
      east: -75.4945,
      west: -75.4965
    },
    type: "retail",
    floors: 1
  },
  {
    id: "target_whitehall_pa", 
    name: "Target",
    address: "1405 MacArthur Rd, Whitehall, PA 18052",
    bounds: {
      north: 40.6835,
      south: 40.6825,
      east: -75.4935,
      west: -75.4955
    },
    type: "retail",
    floors: 1
  },
  {
    id: "123_main_st_nyc",
    name: "Manhattan Office Tower",
    address: "123 Main St, New York, NY 10001",
    bounds: {
      north: 40.7590,
      south: 40.7580,
      east: -73.9850,
      west: -73.9860
    },
    type: "office",
    floors: 25
  },
  {
    id: "456_park_ave_nyc",
    name: "Park Avenue Plaza",
    address: "456 Park Ave, New York, NY 10016", 
    bounds: {
      north: 40.7640,
      south: 40.7630,
      east: -73.9720,
      west: -73.9730
    },
    type: "office",
    floors: 30
  }
];

// ——— RESEARCH-BASED MOVEMENT CLASSIFICATION ALGORITHM ———

function analyzeVerticalMovement(sensorData) {
  const barometer = sensorData.barometer || [];
  const accelerometer = sensorData.accelerometer || [];
  const gps = sensorData.gps || [];
  
  console.log(`📊 Starting analysis: ${barometer.length} baro, ${accelerometer.length} accel, ${gps.length} GPS points`);
  
  // Basic data quality assessment
  const dataQuality = {
    barometer_points: barometer.length,
    accelerometer_points: accelerometer.length,
    gps_points: gps.length,
    duration_covered: calculateDataDuration(barometer, accelerometer),
    sampling_consistency: assessSamplingConsistency(barometer, accelerometer)
  };
  
  // Enhanced movement classification using research-based algorithms
  const movementClassification = classifyMovementTypeResearchBased(barometer, accelerometer);
  
  // Analyze vertical movement patterns
  const verticalEvents = detectVerticalEvents(barometer, accelerometer);
  const elevatorEvents = detectElevatorUsage(barometer, accelerometer);
  
  return {
    data_quality: dataQuality,
    movement_classification: movementClassification,
    vertical_events: verticalEvents,
    elevator_events: elevatorEvents,
    summary: {
      total_vertical_distance: calculateVerticalDistance(barometer),
      average_movement_intensity: calculateMovementIntensity(accelerometer),
      time_in_vertical_motion: calculateVerticalMotionTime(verticalEvents)
    }
  };
}

// ——— RESEARCH-BASED CLASSIFICATION ALGORITHM ———
function classifyMovementTypeResearchBased(barometer, accelerometer) {
  console.log(`🔬 Research-based classification starting...`);
  
  if (accelerometer.length < 10) {
    console.log(`❌ Insufficient accelerometer data: ${accelerometer.length} points`);
    return 'insufficient_data';
  }
  
  // Calculate pressure change rate (research threshold: >0.1 hPa/sec for elevator)
  const pressureAnalysis = analyzePressureChanges(barometer);
  
  // Enhanced accelerometer analysis based on research
  const accelAnalysis = analyzeAccelerometerPatterns(accelerometer);
  
  // Step detection using research thresholds (0.3-0.5g peaks)
  const stepAnalysis = detectStepsResearchBased(accelerometer);
  
  console.log(`📈 Pressure rate: ${pressureAnalysis.change_rate_hpa_per_sec.toFixed(4)} hPa/s`);
  console.log(`📈 Step frequency: ${stepAnalysis.step_frequency.toFixed(2)} Hz`);
  console.log(`📈 Accel variance: ${accelAnalysis.variance.toFixed(3)}`);
  console.log(`📈 Movement intensity: ${accelAnalysis.movement_intensity.toFixed(2)}`);
  
  // Classification logic based on research paper thresholds
  
  // 1. Elevator detection (>0.1 hPa/sec + low variance + acceleration spikes)
  if (pressureAnalysis.change_rate_hpa_per_sec > 0.1 && 
      accelAnalysis.variance < 0.3 && 
      accelAnalysis.has_start_stop_pattern) {
    console.log(`🛗 ELEVATOR detected: Fast pressure change + smooth movement + start/stop spikes`);
    return 'elevator_movement';
  }
  
  // 2. Enhanced Stairs Detection (Indoor + Outdoor conditions)
  const stairsAnalysis = analyzeStairsPattern(pressureAnalysis, stepAnalysis, accelAnalysis);
  
  if (stairsAnalysis.is_stairs_indoor || stairsAnalysis.is_stairs_outdoor) {
    const stairType = stairsAnalysis.is_stairs_outdoor ? 'OUTDOOR' : 'INDOOR';
    console.log(`🚶‍♂️ STAIRS (${stairType}) detected: ${stairsAnalysis.reason}`);
    return 'climbing_stairs';
  }
  
  // 3. Level walking (step pattern + minimal pressure change) - RELAXED THRESHOLDS
  if (stepAnalysis.step_frequency > 1.0 && 
      stepAnalysis.step_frequency < 3.0 &&
      stepAnalysis.step_regularity > 0.2 &&
      Math.abs(pressureAnalysis.change_rate_hpa_per_sec) < 0.02 &&
      accelAnalysis.variance < 8.0) { // Much more relaxed variance threshold
    console.log(`🚶 WALKING detected: Clear steps + minimal pressure change`);
    return 'walking';
  }
  
  // 4. Mixed indoor movement (browsing, shopping, mixed walking/standing) - BROADER RANGE
  if (stepAnalysis.step_frequency > 0.8 && 
      stepAnalysis.step_frequency < 2.0 &&
      accelAnalysis.variance > 1.0 && 
      accelAnalysis.variance < 10.0 &&
      Math.abs(pressureAnalysis.change_rate_hpa_per_sec) < 0.05) {
    console.log(`🛍️ INDOOR_BROWSING detected: Mixed walking with stops/turns`);
    return 'indoor_browsing';
  }
  
  // 5. Escalator (steady pressure + low variance + no steps)
  if (pressureAnalysis.change_rate_hpa_per_sec > 0.02 && 
      pressureAnalysis.change_rate_hpa_per_sec < 0.08 &&
      accelAnalysis.variance < 0.5 && 
      stepAnalysis.step_frequency < 0.5) {
    console.log(`🛤️ ESCALATOR detected: Steady pressure + low variance + minimal steps`);
    return 'escalator_movement';
  }
  
  // 6. Stationary (research: variance < 0.1, avg magnitude < 10.2 m/s²)
  if (accelAnalysis.variance < 0.3 && accelAnalysis.average_magnitude < 10.5) {
    console.log(`🛑 STATIONARY detected: Low variance + low magnitude`);
    return 'stationary';
  }
  
  // 7. Vehicle (high variance + high magnitude)
  if (accelAnalysis.variance > 15.0 && accelAnalysis.average_magnitude > 12.0) {
    console.log(`🚗 VEHICLE detected: Very high variance + high magnitude`);
    return 'vehicle_transport';
  }
  
  // 8. Active movement (catch broader movement patterns)
  if (stepAnalysis.step_frequency > 0.5 && 
      stepAnalysis.step_frequency < 3.0 &&
      accelAnalysis.variance > 0.5) {
    console.log(`🏃 ACTIVE_MOVEMENT detected: Moderate steps + movement variance`);
    return 'active_movement';
  }
  
  // 8. Enhanced unknown classification with detailed reasoning
  console.log(`❓ UNKNOWN_MOVEMENT: Detailed analysis:`);
  console.log(`   - Pressure rate: ${pressureAnalysis.change_rate_hpa_per_sec.toFixed(4)} hPa/s`);
  console.log(`   - Step freq: ${stepAnalysis.step_frequency.toFixed(2)} Hz`);
  console.log(`   - Variance: ${accelAnalysis.variance.toFixed(3)}`);
  console.log(`   - Avg magnitude: ${accelAnalysis.average_magnitude.toFixed(2)} m/s²`);
  console.log(`   - Duration: ${(accelAnalysis.duration_seconds || 0).toFixed(1)}s`);
  
  return 'unknown_movement';
}

// ——— RESEARCH-BASED PRESSURE ANALYSIS ———
function analyzePressureChanges(barometer) {
  if (barometer.length < 2) {
    return {
      change_rate_hpa_per_sec: 0,
      total_change_hpa: 0,
      duration_seconds: 0
    };
  }
  
  const startPressure = barometer[0].pressure_hpa;
  const endPressure = barometer[barometer.length - 1].pressure_hpa;
  const totalChange = Math.abs(endPressure - startPressure);
  
  const startTime = barometer[0].timestamp;
  const endTime = barometer[barometer.length - 1].timestamp;
  const durationSeconds = (endTime - startTime) / 1000;
  
  const changeRate = durationSeconds > 0 ? totalChange / durationSeconds : 0;
  
  return {
    change_rate_hpa_per_sec: changeRate,
    total_change_hpa: totalChange,
    duration_seconds: durationSeconds,
    start_pressure: startPressure,
    end_pressure: endPressure
  };
}

// ——— RESEARCH-BASED ACCELEROMETER ANALYSIS ———
function analyzeAccelerometerPatterns(accelerometer) {
  const magnitudes = accelerometer.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  const variance = calculateVariance(magnitudes);
  const avgMagnitude = magnitudes.reduce((sum, mag) => sum + mag, 0) / magnitudes.length;
  
  // Duration analysis
  const startTime = accelerometer[0].timestamp;
  const endTime = accelerometer[accelerometer.length - 1].timestamp;
  const durationSeconds = (endTime - startTime) / 1000;
  
  // Vertical component analysis (research: Z-axis for vertical movement)
  const zValues = accelerometer.map(reading => Math.abs(reading.z));
  const zVariance = calculateVariance(zValues);
  const verticalIntensity = zVariance / (avgMagnitude + 1);
  
  // Start/stop pattern detection (research: elevator signature)
  const startSection = magnitudes.slice(0, Math.min(10, magnitudes.length / 4));
  const endSection = magnitudes.slice(-Math.min(10, magnitudes.length / 4));
  const middleSection = magnitudes.slice(
    Math.floor(magnitudes.length * 0.3), 
    Math.floor(magnitudes.length * 0.7)
  );
  
  const startVariance = calculateVariance(startSection);
  const endVariance = calculateVariance(endSection);
  const middleVariance = calculateVariance(middleSection);
  
  const hasStartStopPattern = (startVariance > middleVariance * 1.2) || 
                             (endVariance > middleVariance * 1.2);
  
  return {
    variance: variance,
    average_magnitude: avgMagnitude,
    vertical_intensity: verticalIntensity,
    duration_seconds: durationSeconds,
    has_start_stop_pattern: hasStartStopPattern,
    movement_intensity: avgMagnitude - 9.8, // Subtract gravity
    z_variance: zVariance
  };
}

// ——— ENHANCED STAIRS ANALYSIS (Indoor vs Outdoor) ———
function analyzeStairsPattern(pressureAnalysis, stepAnalysis, accelAnalysis) {
  const isStepPattern = stepAnalysis.step_frequency > 0.8 && stepAnalysis.step_frequency < 2.8;
  const hasVerticalMovement = accelAnalysis.vertical_intensity > 0.2;
  
  // OUTDOOR STAIRS - Research-based thresholds (clear pressure changes)
  const is_stairs_outdoor = 
    pressureAnalysis.change_rate_hpa_per_sec >= 0.015 && // Strong pressure signal
    pressureAnalysis.change_rate_hpa_per_sec <= 0.08 &&
    isStepPattern &&
    accelAnalysis.vertical_intensity > 0.4;
  
  // INDOOR STAIRS - Relaxed thresholds (HVAC interference, short distances)
  const is_stairs_indoor = 
    !is_stairs_outdoor && // Not already caught by outdoor
    (
      // Scenario 1: Minimal pressure + clear step pattern + vertical movement
      (pressureAnalysis.change_rate_hpa_per_sec >= 0.0008 && 
       isStepPattern && 
       hasVerticalMovement) ||
      
      // Scenario 2: Significant total pressure change + strong step pattern + higher rate
      (Math.abs(pressureAnalysis.total_change_hpa) > 0.15 && // Much higher threshold
       pressureAnalysis.change_rate_hpa_per_sec > 0.0015 && // Must have some rate
       stepAnalysis.step_frequency > 1.0 && 
       stepAnalysis.step_frequency < 2.5 &&
       accelAnalysis.vertical_intensity > 0.5) || // Higher vertical requirement
      
      // Scenario 3: High step frequency + vertical intensity (even without pressure)
      (stepAnalysis.step_frequency > 1.5 && // Higher frequency requirement
       stepAnalysis.step_frequency < 2.2 &&
       accelAnalysis.vertical_intensity > 0.7 && // Much higher vertical
       accelAnalysis.variance > 5.0) || // More energetic than level walking
      
      // Scenario 4: SLOW STAIRS - Research-backed threshold (0.001 hPa/s minimum)
      (pressureAnalysis.change_rate_hpa_per_sec > 0.001 && // Much lower threshold per research
       stepAnalysis.step_frequency > 0.3 && // Very slow but rhythmic
       stepAnalysis.step_frequency < 1.0 && // Below normal walking
       accelAnalysis.variance < 3.0 && // Controlled movement
       hasVerticalMovement) // Some vertical component
    );
  
  // Generate reason for debugging
  let reason = '';
  if (is_stairs_outdoor) {
    reason = `Rate: ${pressureAnalysis.change_rate_hpa_per_sec.toFixed(4)} hPa/s, Steps: ${stepAnalysis.step_frequency.toFixed(2)} Hz, Vertical: ${accelAnalysis.vertical_intensity.toFixed(3)}`;
  } else if (is_stairs_indoor) {
    if (pressureAnalysis.change_rate_hpa_per_sec >= 0.0008 && isStepPattern && hasVerticalMovement) {
      reason = `Indoor minimal pressure + steps (${stepAnalysis.step_frequency.toFixed(2)} Hz) + vertical`;
    } else if (Math.abs(pressureAnalysis.total_change_hpa) > 0.05) {
      reason = `Indoor total pressure change (${pressureAnalysis.total_change_hpa.toFixed(3)} hPa) + strong steps`;
    } else {
      reason = `Indoor high step frequency (${stepAnalysis.step_frequency.toFixed(2)} Hz) + vertical intensity`;
    }
  }
  
  return {
    is_stairs_outdoor,
    is_stairs_indoor,
    is_stairs_any: is_stairs_outdoor || is_stairs_indoor,
    reason,
    step_pattern_detected: isStepPattern,
    vertical_movement_detected: hasVerticalMovement
  };
}
function detectStepsResearchBased(accelerometer) {
  if (accelerometer.length < 5) {
    return { step_frequency: 0, step_regularity: 0, step_count: 0 };
  }
  
  // Calculate acceleration magnitudes
  const magnitudes = accelerometer.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  // Research threshold: 0.3-0.5g (3-5 m/s²) for step detection
  const stepThreshold = 3.0; // m/s² (research: ~0.3g)
  const avgMagnitude = magnitudes.reduce((sum, mag) => sum + mag, 0) / magnitudes.length;
  
  // Peak detection for steps
  const peaks = [];
  for (let i = 1; i < magnitudes.length - 1; i++) {
    if (magnitudes[i] > magnitudes[i-1] && 
        magnitudes[i] > magnitudes[i+1] && 
        magnitudes[i] > (avgMagnitude + stepThreshold)) {
      peaks.push(i);
    }
  }
  
  // Calculate step frequency (research: ~1.5-2 Hz for normal walking)
  const startTime = accelerometer[0].timestamp;
  const endTime = accelerometer[accelerometer.length - 1].timestamp;
  const durationSeconds = (endTime - startTime) / 1000;
  const stepFrequency = durationSeconds > 0 ? peaks.length / durationSeconds : 0;
  
  // Calculate step regularity
  let stepRegularity = 0;
  if (peaks.length > 1) {
    const intervals = [];
    for (let i = 1; i < peaks.length; i++) {
      const timeInterval = (accelerometer[peaks[i]].timestamp - accelerometer[peaks[i-1]].timestamp) / 1000;
      intervals.push(timeInterval);
    }
    
    if (intervals.length > 0) {
      const avgInterval = intervals.reduce((sum, val) => sum + val, 0) / intervals.length;
      const intervalVariance = calculateVariance(intervals);
      stepRegularity = Math.max(0, 1 - (Math.sqrt(intervalVariance) / avgInterval));
    }
  }
  
  return {
    step_frequency: stepFrequency,
    step_regularity: stepRegularity,
    step_count: peaks.length,
    avg_magnitude: avgMagnitude,
    peak_threshold_used: stepThreshold
  };
}

// Keep existing helper functions
function calculateVariance(values) {
  if (values.length < 2) return 0;
  const avg = values.reduce((sum, val) => sum + val, 0) / values.length;
  const variance = values.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / values.length;
  return variance;
}

function calculateDataDuration(barometer, accelerometer) {
  const allTimestamps = [
    ...barometer.map(d => d.timestamp),
    ...accelerometer.map(d => d.timestamp)
  ].sort((a, b) => a - b);
  
  if (allTimestamps.length < 2) return 0;
  return allTimestamps[allTimestamps.length - 1] - allTimestamps[0];
}

function assessSamplingConsistency(barometer, accelerometer) {
  if (barometer.length < 2) return 0;
  
  const intervals = [];
  for (let i = 1; i < barometer.length; i++) {
    intervals.push(barometer[i].timestamp - barometer[i-1].timestamp);
  }
  
  const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((sum, interval) => {
    return sum + Math.pow(interval - avgInterval, 2);
  }, 0) / intervals.length;
  
  return Math.max(0, 1 - (Math.sqrt(variance) / avgInterval));
}

function calculateVerticalDistance(barometer) {
  if (barometer.length < 2) return 0;
  
  const startPressure = barometer[0].pressure_hpa;
  const endPressure = barometer[barometer.length - 1].pressure_hpa;
  
  // Research: 1 hPa ≈ 8.4 meters at sea level
  return Math.abs(startPressure - endPressure) * 8.4;
}

function calculateMovementIntensity(accelerometer) {
  if (accelerometer.length === 0) return 0;
  
  const magnitudes = accelerometer.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  return magnitudes.reduce((sum, mag) => sum + mag, 0) / magnitudes.length;
}

function calculateVerticalMotionTime(verticalEvents) {
  return verticalEvents.reduce((total, event) => total + (event.duration_ms || 0), 0);
}

// Simplified versions of existing functions for the rest of the server
function detectVerticalEvents(barometer, accelerometer) {
  return []; // Simplified for now
}

function detectElevatorUsage(barometer, accelerometer) {
  return []; // Simplified for now
}

// Building detection functions (keeping existing)
function findBuildingFromGPS(lat, lon) {
  let bestMatch = null;
  let bestConfidence = 0;
  
  for (const building of BUILDING_DATABASE) {
    if (lat >= building.bounds.south && lat <= building.bounds.north &&
        lon >= building.bounds.west && lon <= building.bounds.east) {
      
      const centerLat = (building.bounds.north + building.bounds.south) / 2;
      const centerLon = (building.bounds.east + building.bounds.west) / 2;
      const distance = Math.sqrt(Math.pow(lat - centerLat, 2) + Math.pow(lon - centerLon, 2));
      
      const maxDistance = Math.sqrt(
        Math.pow(building.bounds.north - building.bounds.south, 2) + 
        Math.pow(building.bounds.east - building.bounds.west, 2)
      ) / 2;
      
      const confidence = Math.max(0, 1 - (distance / maxDistance));
      
      if (confidence > bestConfidence) {
        bestMatch = building;
        bestConfidence = confidence;
      }
    }
  }
  
  return {
    building: bestMatch,
    confidence: bestConfidence,
    coordinates: { lat, lon }
  };
}

async function extractBuildingId(gpsData) {
  if (!gpsData || gpsData.length === 0) {
    return {
      building_id: 'no_gps_data',
      confidence: 0,
      method: 'no_data',
      coordinates: null
    };
  }
  
  const buildingMatches = gpsData.map(point => {
    return findBuildingFromGPS(point.lat, point.lon);
  });
  
  const validMatches = buildingMatches.filter(match => match.building !== null);
  
  if (validMatches.length === 0) {
    const avgLat = gpsData.reduce((sum, p) => sum + p.lat, 0) / gpsData.length;
    const avgLon = gpsData.reduce((sum, p) => sum + p.lon, 0) / gpsData.length;
    
    return {
      building_id: `unknown_${avgLat.toFixed(4)}_${avgLon.toFixed(4)}`,
      confidence: 0.1,
      method: 'coordinate_fallback',
      coordinates: { lat: avgLat, lon: avgLon }
    };
  }
  
  const buildingCounts = {};
  validMatches.forEach(match => {
    const id = match.building.id;
    if (!buildingCounts[id]) {
      buildingCounts[id] = { count: 0, totalConfidence: 0, building: match.building };
    }
    buildingCounts[id].count++;
    buildingCounts[id].totalConfidence += match.confidence;
  });
  
  let bestBuilding = null;
  let bestScore = 0;
  
  for (const [buildingId, data] of Object.entries(buildingCounts)) {
    const consensusRatio = data.count / gpsData.length;
    const avgConfidence = data.totalConfidence / data.count;
    const score = consensusRatio * avgConfidence;
    
    if (score > bestScore) {
      bestScore = score;
      bestBuilding = data;
    }
  }
  
  return {
    building_id: bestBuilding.building.id,
    building_name: bestBuilding.building.name,
    building_address: bestBuilding.building.address,
    building_type: bestBuilding.building.type,
    building_floors: bestBuilding.building.floors,
    confidence: bestScore,
    method: 'gps_consensus',
    gps_points_analyzed: gpsData.length,
    gps_points_matched: validMatches.length
  };
}

// ——— Sensor Data Upload Endpoint ———
app.post('/api/v1/sensor-data', async (req, res) => {
  try {
    const sensorData = req.body;
    
    if (!sensorData.session_id || !sensorData.device_id || !sensorData.sensor_data) {
      return res.status(400).json({ 
        error: 'Missing required fields: session_id, device_id, sensor_data' 
      });
    }
    
    console.log(`📱 Received sensor data from device: ${sensorData.device_id}`);
    console.log(`📊 Session: ${sensorData.session_id}`);
    console.log(`🔢 Data points - Barometer: ${sensorData.sensor_data.barometer?.length || 0}, Accelerometer: ${sensorData.sensor_data.accelerometer?.length || 0}, GPS: ${sensorData.sensor_data.gps?.length || 0}`);
    
    // Enhanced processing with building detection
    const buildingInfo = await extractBuildingId(sensorData.sensor_data.gps);
    const dataAnalysis = analyzeVerticalMovement(sensorData.sensor_data);
    
    const processedData = {
      session_id: sensorData.session_id,
      device_id: sensorData.device_id,
      start_time: sensorData.start_time,
      end_time: sensorData.end_time,
      
      // Building Information
      building_info: buildingInfo,
      
      // Data Analysis
      data_analysis: dataAnalysis,
      
      // Session Metadata
      session_duration_minutes: calculateSessionDuration(sensorData.start_time, sensorData.end_time),
      permissions: sensorData.permissions || {},
      processed_at: new Date().toISOString()
    };
    
    console.log(`🏢 Building: ${buildingInfo.building_name || buildingInfo.building_id} (confidence: ${(buildingInfo.confidence * 100).toFixed(1)}%)`);
    console.log(`📊 Movement analysis: ${dataAnalysis.movement_classification}, Vertical events: ${dataAnalysis.vertical_events.length}`);
    
    res.status(201).json({
      success: true,
      message: 'Sensor data received and processed',
      session_id: sensorData.session_id,
      building: {
        id: buildingInfo.building_id,
        name: buildingInfo.building_name,
        confidence: buildingInfo.confidence
      },
      analysis: {
        movement_type: dataAnalysis.movement_classification,
        vertical_events: dataAnalysis.vertical_events.length,
        data_quality: dataAnalysis.data_quality
      }
    });
    
  } catch (error) {
    console.error('❌ Error processing sensor data:', error);
    res.status(500).json({ 
      error: 'Failed to process sensor data',
      details: error.message 
    });
  }
});

function calculateSessionDuration(startTime, endTime) {
  if (!startTime || !endTime) return 0;
  const start = new Date(startTime);
  const end = new Date(endTime);
  return (end - start) / (1000 * 60); // Return minutes
}
// Start server
const PORT = process.env.PORT || 3000;

async function startServer() {
  await initializeDatabase();
  app.listen(PORT, '0.0.0.0', () =>
    console.log(`Secure API server with admin dashboard listening on http://0.0.0.0:${PORT}`)
  );
}

startServer().catch(console.error);
