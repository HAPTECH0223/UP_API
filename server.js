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

// Advanced building detection with confidence scoring
function findBuildingFromGPS(lat, lon) {
  let bestMatch = null;
  let bestConfidence = 0;
  
  for (const building of BUILDING_DATABASE) {
    // Check if point is within building bounds
    if (lat >= building.bounds.south && lat <= building.bounds.north &&
        lon >= building.bounds.west && lon <= building.bounds.east) {
      
      // Calculate confidence based on distance from center
      const centerLat = (building.bounds.north + building.bounds.south) / 2;
      const centerLon = (building.bounds.east + building.bounds.west) / 2;
      const distance = Math.sqrt(Math.pow(lat - centerLat, 2) + Math.pow(lon - centerLon, 2));
      
      // Closer to center = higher confidence
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

// Enhanced building ID extraction with multiple GPS points analysis
async function extractBuildingId(gpsData) {
  if (!gpsData || gpsData.length === 0) {
    return {
      building_id: 'no_gps_data',
      confidence: 0,
      method: 'no_data',
      coordinates: null
    };
  }
  
  // Analyze all GPS points for consistency
  const buildingMatches = gpsData.map(point => {
    return findBuildingFromGPS(point.lat, point.lon);
  });
  
  // Filter out non-matches and calculate consensus
  const validMatches = buildingMatches.filter(match => match.building !== null);
  
  if (validMatches.length === 0) {
    // No building matches - create location-based ID
    const avgLat = gpsData.reduce((sum, p) => sum + p.lat, 0) / gpsData.length;
    const avgLon = gpsData.reduce((sum, p) => sum + p.lon, 0) / gpsData.length;
    
    return {
      building_id: `unknown_${avgLat.toFixed(4)}_${avgLon.toFixed(4)}`,
      confidence: 0.1,
      method: 'coordinate_fallback',
      coordinates: { lat: avgLat, lon: avgLon }
    };
  }
  
  // Find most common building match
  const buildingCounts = {};
  validMatches.forEach(match => {
    const id = match.building.id;
    if (!buildingCounts[id]) {
      buildingCounts[id] = { count: 0, totalConfidence: 0, building: match.building };
    }
    buildingCounts[id].count++;
    buildingCounts[id].totalConfidence += match.confidence;
  });
  
  // Get building with highest consensus
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

// ——— Sensor Data Analysis ———
function analyzeVerticalMovement(sensorData) {
  const barometer = sensorData.barometer || [];
  const accelerometer = sensorData.accelerometer || [];
  const gps = sensorData.gps || [];
  
  // Basic data quality assessment
  const dataQuality = {
    barometer_points: barometer.length,
    accelerometer_points: accelerometer.length,
    gps_points: gps.length,
    duration_covered: calculateDataDuration(barometer, accelerometer),
    sampling_consistency: assessSamplingConsistency(barometer, accelerometer)
  };
  
  // Analyze vertical movement patterns
  const verticalEvents = detectVerticalEvents(barometer, accelerometer);
  const movementClassification = classifyMovementType(accelerometer);
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

function detectVerticalEvents(barometer, accelerometer) {
  const events = [];
  
  if (barometer.length < 10) return events; // Need minimum data
  
  // Analyze pressure changes (1 hPa ≈ 8.4 meters altitude change)
  const pressureThreshold = 0.5; // hPa - significant pressure change
  const timeThreshold = 5000; // 5 seconds minimum duration
  
  let currentEvent = null;
  
  for (let i = 1; i < barometer.length; i++) {
    const pressureDiff = barometer[i].pressure_hpa - barometer[i-1].pressure_hpa;
    const timeDiff = barometer[i].timestamp - barometer[i-1].timestamp;
    
    if (Math.abs(pressureDiff) > pressureThreshold && timeDiff < 30000) { // Within 30 seconds
      if (!currentEvent) {
        currentEvent = {
          start_time: barometer[i-1].timestamp,
          start_pressure: barometer[i-1].pressure_hpa,
          direction: pressureDiff > 0 ? 'up' : 'down',
          max_pressure_change: Math.abs(pressureDiff)
        };
      } else {
        // Extend current event
        currentEvent.end_time = barometer[i].timestamp;
        currentEvent.end_pressure = barometer[i].pressure_hpa;
        currentEvent.max_pressure_change = Math.max(
          currentEvent.max_pressure_change, 
          Math.abs(pressureDiff)
        );
      }
    } else if (currentEvent && timeDiff > timeThreshold) {
      // End current event
      currentEvent.end_time = currentEvent.end_time || barometer[i-1].timestamp;
      currentEvent.duration_ms = currentEvent.end_time - currentEvent.start_time;
      currentEvent.estimated_floors = Math.round(currentEvent.max_pressure_change / 0.12); // ~0.12 hPa per floor
      
      if (currentEvent.duration_ms >= timeThreshold) {
        events.push(currentEvent);
      }
      currentEvent = null;
    }
  }
  
  return events;
}

function classifyMovementType(accelerometer) {
  if (accelerometer.length < 20) return 'insufficient_data';
  
  // Enhanced movement analysis with multiple metrics
  const metrics = calculateAdvancedMovementMetrics(accelerometer);
  
  // Multi-factor classification
  if (metrics.is_stationary) {
    return 'stationary';
  } else if (metrics.has_walking_pattern) {
    return metrics.is_stairs ? 'climbing_stairs' : 'walking';
  } else if (metrics.has_elevator_pattern) {
    return 'elevator_movement';
  } else if (metrics.has_vehicle_pattern) {
    return 'vehicle_transport';
  } else if (metrics.has_escalator_pattern) {
    return 'escalator_movement';
  } else {
    return 'unknown_movement';
  }
}

function calculateAdvancedMovementMetrics(accelerometer) {
  const magnitudes = accelerometer.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  const variance = calculateVariance(magnitudes);
  const avgMagnitude = magnitudes.reduce((sum, mag) => sum + mag, 0) / magnitudes.length;
  const stepPattern = detectStepPattern(accelerometer);
  const smoothness = calculateSmoothness(magnitudes);
  const verticalComponent = analyzeVerticalComponent(accelerometer);
  
  return {
    variance: variance,
    average_magnitude: avgMagnitude,
    smoothness: smoothness,
    step_frequency: stepPattern.frequency,
    step_regularity: stepPattern.regularity,
    vertical_intensity: verticalComponent.intensity,
    
    // Classification flags
    is_stationary: variance < 0.1 && avgMagnitude < 10.2,
    has_walking_pattern: stepPattern.frequency > 0.5 && stepPattern.frequency < 3.0,
    has_elevator_pattern: variance < 0.3 && smoothness > 0.7 && verticalComponent.intensity > 0.3,
    has_vehicle_pattern: variance > 2.0 && smoothness < 0.3,
    has_escalator_pattern: variance < 0.8 && verticalComponent.intensity > 0.5 && stepPattern.frequency < 0.5,
    is_stairs: stepPattern.frequency > 0.8 && verticalComponent.intensity > 0.6
  };
}

function detectStepPattern(accelerometer) {
  // Analyze for rhythmic patterns indicating walking/climbing
  const magnitudes = accelerometer.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  // Simple frequency analysis (looking for 1-3 Hz walking patterns)
  const peaks = findPeaks(magnitudes);
  const timespan = (accelerometer[accelerometer.length - 1].timestamp - accelerometer[0].timestamp) / 1000;
  const frequency = peaks.length / timespan; // Hz
  
  // Calculate regularity of peaks
  if (peaks.length < 2) {
    return { frequency: 0, regularity: 0 };
  }
  
  const intervals = [];
  for (let i = 1; i < peaks.length; i++) {
    intervals.push(peaks[i] - peaks[i-1]);
  }
  
  const avgInterval = intervals.reduce((sum, val) => sum + val, 0) / intervals.length;
  const intervalVariance = calculateVariance(intervals);
  const regularity = Math.max(0, 1 - (intervalVariance / (avgInterval * avgInterval)));
  
  return {
    frequency: frequency,
    regularity: regularity,
    peak_count: peaks.length
  };
}

function analyzeVerticalComponent(accelerometer) {
  // Analyze the Z-axis (vertical) component patterns
  const zValues = accelerometer.map(reading => reading.z);
  const zVariance = calculateVariance(zValues);
  const zAvg = zValues.reduce((sum, val) => sum + val, 0) / zValues.length;
  
  // Detect consistent vertical acceleration patterns
  const verticalIntensity = zVariance / (Math.abs(zAvg) + 1);
  
  return {
    intensity: verticalIntensity,
    average_z: zAvg,
    z_variance: zVariance
  };
}

function findPeaks(values) {
  const peaks = [];
  const threshold = 0.5; // Minimum peak prominence
  
  for (let i = 1; i < values.length - 1; i++) {
    if (values[i] > values[i-1] && values[i] > values[i+1] && 
        values[i] > (Math.max(...values) * threshold)) {
      peaks.push(i);
    }
  }
  
  return peaks;
}

// ——— Advanced Elevator Detection System ———

function detectElevatorUsage(barometer, accelerometer) {
  const elevatorEvents = [];
  
  if (barometer.length < 30 || accelerometer.length < 30) {
    return elevatorEvents; // Need sufficient data for pattern analysis
  }
  
  // Step 1: Find potential elevator periods using pressure changes
  const pressureCandidates = findPressureChangeEvents(barometer);
  
  // Step 2: Analyze accelerometer patterns during those periods
  for (const candidate of pressureCandidates) {
    const accelPattern = analyzeAccelerationPattern(accelerometer, candidate);
    const elevatorSignature = checkElevatorSignature(candidate, accelPattern);
    
    if (elevatorSignature.isElevator) {
      elevatorEvents.push({
        start_time: candidate.start_time,
        end_time: candidate.end_time,
        duration_ms: candidate.duration_ms,
        floors_traveled: elevatorSignature.floors_traveled,
        direction: candidate.direction,
        confidence: elevatorSignature.confidence,
        acceleration_pattern: accelPattern,
        pressure_change: candidate.pressure_change,
        elevator_type: elevatorSignature.elevator_type, // passenger, freight, express
        wait_time_before: elevatorSignature.wait_time_before,
        door_events: elevatorSignature.door_events
      });
    }
  }
  
  return elevatorEvents;
}

function findPressureChangeEvents(barometer) {
  const events = [];
  const PRESSURE_THRESHOLD = 0.2; // hPa - more sensitive than before
  const MIN_DURATION = 3000; // 3 seconds minimum
  const MAX_DURATION = 120000; // 2 minutes maximum (handles slow freight elevators)
  
  let currentEvent = null;
  
  for (let i = 1; i < barometer.length; i++) {
    const pressureDiff = barometer[i].pressure_hpa - barometer[i-1].pressure_hpa;
    const timeDiff = barometer[i].timestamp - barometer[i-1].timestamp;
    
    // Detect significant pressure changes
    if (Math.abs(pressureDiff) > PRESSURE_THRESHOLD && timeDiff < 5000) {
      if (!currentEvent) {
        // Start new event
        currentEvent = {
          start_time: barometer[i-1].timestamp,
          start_pressure: barometer[i-1].pressure_hpa,
          direction: pressureDiff > 0 ? 'up' : 'down',
          pressure_changes: [pressureDiff],
          total_pressure_change: pressureDiff
        };
      } else {
        // Continue existing event if direction is consistent
        const newDirection = pressureDiff > 0 ? 'up' : 'down';
        if (newDirection === currentEvent.direction || Math.abs(pressureDiff) > 0.5) {
          currentEvent.end_time = barometer[i].timestamp;
          currentEvent.end_pressure = barometer[i].pressure_hpa;
          currentEvent.pressure_changes.push(pressureDiff);
          currentEvent.total_pressure_change += pressureDiff;
        }
      }
    } else if (currentEvent && timeDiff > 3000) {
      // End current event if pressure stabilizes
      currentEvent.end_time = currentEvent.end_time || barometer[i-1].timestamp;
      currentEvent.duration_ms = currentEvent.end_time - currentEvent.start_time;
      currentEvent.pressure_change = Math.abs(currentEvent.total_pressure_change);
      
      // Only keep events with reasonable duration and pressure change
      if (currentEvent.duration_ms >= MIN_DURATION && 
          currentEvent.duration_ms <= MAX_DURATION &&
          currentEvent.pressure_change > 0.3) {
        events.push(currentEvent);
      }
      currentEvent = null;
    }
  }
  
  return events;
}

function analyzeAccelerationPattern(accelerometer, pressureEvent) {
  // Get accelerometer data during pressure event
  const eventAccel = accelerometer.filter(reading => 
    reading.timestamp >= pressureEvent.start_time && 
    reading.timestamp <= (pressureEvent.end_time || pressureEvent.start_time + 60000)
  );
  
  if (eventAccel.length < 10) {
    return { pattern: 'insufficient_data', confidence: 0 };
  }
  
  // Calculate acceleration magnitudes
  const magnitudes = eventAccel.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  // Analyze pattern characteristics
  const variance = calculateVariance(magnitudes);
  const avgMagnitude = magnitudes.reduce((sum, mag) => sum + mag, 0) / magnitudes.length;
  const smoothness = calculateSmoothness(magnitudes);
  const startEndPattern = analyzeStartEndAcceleration(magnitudes);
  
  return {
    pattern: classifyAccelerationPattern(variance, avgMagnitude, smoothness, startEndPattern),
    variance: variance,
    average_magnitude: avgMagnitude,
    smoothness: smoothness,
    start_end_pattern: startEndPattern,
    readings_count: eventAccel.length
  };
}

function checkElevatorSignature(pressureEvent, accelPattern) {
  let confidence = 0;
  let elevatorType = 'unknown';
  let floors_traveled = 0;
  
  // Pressure-based scoring
  const pressure_score = calculatePressureScore(pressureEvent);
  confidence += pressure_score * 0.4;
  
  // Acceleration pattern scoring
  const accel_score = calculateAccelerationScore(accelPattern);
  confidence += accel_score * 0.6;
  
  // Estimate floors traveled (1 floor ≈ 0.12 hPa pressure change)
  floors_traveled = Math.round(pressureEvent.pressure_change / 0.12);
  
  // Classify elevator type based on patterns
  if (pressureEvent.duration_ms > 60000) {
    elevatorType = 'freight'; // Very slow
  } else if (floors_traveled > 10 && pressureEvent.duration_ms < 30000) {
    elevatorType = 'express'; // Fast, many floors
  } else if (floors_traveled >= 1) {
    elevatorType = 'passenger'; // Normal passenger elevator
  }
  
  // Detect waiting and door events
  const wait_time_before = detectWaitingPeriod(pressureEvent);
  const door_events = detectDoorEvents(accelPattern);
  
  return {
    isElevator: confidence > 0.65, // Stricter threshold
    confidence: confidence,
    floors_traveled: floors_traveled,
    elevator_type: elevatorType,
    wait_time_before: wait_time_before,
    door_events: door_events
  };
}

function calculatePressureScore(pressureEvent) {
  let score = 0;
  
  // Pressure change magnitude (more change = more likely elevator)
  const pressure_magnitude = pressureEvent.pressure_change;
  if (pressure_magnitude > 0.5) score += 0.3;
  if (pressure_magnitude > 1.0) score += 0.2;
  if (pressure_magnitude > 2.0) score += 0.2;
  
  // Duration appropriateness (elevators have typical duration ranges)
  const duration_sec = pressureEvent.duration_ms / 1000;
  if (duration_sec >= 5 && duration_sec <= 60) score += 0.3;
  
  return Math.min(score, 1.0);
}

function calculateAccelerationScore(accelPattern) {
  let score = 0;
  
  // Low variance suggests smooth elevator movement
  if (accelPattern.variance < 0.5) score += 0.4;
  if (accelPattern.variance < 0.2) score += 0.2;
  
  // Smoothness indicates controlled mechanical movement
  if (accelPattern.smoothness > 0.7) score += 0.3;
  
  // Start-end acceleration pattern (elevators start/stop smoothly)
  if (accelPattern.start_end_pattern && accelPattern.start_end_pattern.has_start_stop) {
    score += 0.3;
  }
  
  return Math.min(score, 1.0);
}

function calculateSmoothness(magnitudes) {
  if (magnitudes.length < 3) return 0;
  
  // Calculate how smooth the acceleration changes are
  let smoothness_sum = 0;
  for (let i = 1; i < magnitudes.length - 1; i++) {
    const change1 = Math.abs(magnitudes[i] - magnitudes[i-1]);
    const change2 = Math.abs(magnitudes[i+1] - magnitudes[i]);
    const smoothness = 1 - Math.abs(change1 - change2) / (change1 + change2 + 0.001);
    smoothness_sum += smoothness;
  }
  
  return smoothness_sum / (magnitudes.length - 2);
}

function analyzeStartEndAcceleration(magnitudes) {
  if (magnitudes.length < 10) return { has_start_stop: false };
  
  const start_section = magnitudes.slice(0, Math.min(5, magnitudes.length / 4));
  const end_section = magnitudes.slice(-Math.min(5, magnitudes.length / 4));
  const middle_section = magnitudes.slice(
    Math.floor(magnitudes.length * 0.3), 
    Math.floor(magnitudes.length * 0.7)
  );
  
  const start_variance = calculateVariance(start_section);
  const end_variance = calculateVariance(end_section);
  const middle_variance = calculateVariance(middle_section);
  
  // Elevators typically have higher variance at start/end (acceleration/deceleration)
  const has_start_stop = (start_variance > middle_variance * 1.5) || 
                        (end_variance > middle_variance * 1.5);
  
  return {
    has_start_stop: has_start_stop,
    start_variance: start_variance,
    middle_variance: middle_variance,
    end_variance: end_variance
  };
}

function detectWaitingPeriod(pressureEvent) {
  // TODO: Analyze accelerometer data before pressure event to detect waiting
  // This would require looking at stationary periods before elevator movement
  return 0; // Placeholder
}

function detectDoorEvents(accelPattern) {
  // TODO: Detect subtle acceleration spikes that indicate door opening/closing
  // Elevator doors create small vibrations detectable by accelerometer
  return []; // Placeholder
}

function classifyAccelerationPattern(variance, avgMagnitude, smoothness, startEndPattern) {
  if (variance < 0.2 && smoothness > 0.7) {
    return 'smooth_vertical'; // Likely elevator
  } else if (variance > 1.0 && startEndPattern.has_start_stop) {
    return 'walking_with_stops'; // Likely stairs with rest periods
  } else if (variance > 0.5 && avgMagnitude > 10.5) {
    return 'active_movement'; // Walking or climbing stairs
  } else {
    return 'stationary_or_minimal'; // Not moving much
  }
}

function calculateVariance(values) {
  if (values.length < 2) return 0;
  const avg = values.reduce((sum, val) => sum + val, 0) / values.length;
  const variance = values.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / values.length;
  return variance;
}

// Helper functions
function calculateDataDuration(barometer, accelerometer) {
  const allTimestamps = [
    ...barometer.map(d => d.timestamp),
    ...accelerometer.map(d => d.timestamp)
  ].sort((a, b) => a - b);
  
  if (allTimestamps.length < 2) return 0;
  return allTimestamps[allTimestamps.length - 1] - allTimestamps[0];
}

function assessSamplingConsistency(barometer, accelerometer) {
  // Check if sampling rates are consistent
  // Returns score 0-1 (1 = perfect consistency)
  
  if (barometer.length < 2) return 0;
  
  const intervals = [];
  for (let i = 1; i < barometer.length; i++) {
    intervals.push(barometer[i].timestamp - barometer[i-1].timestamp);
  }
  
  const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((sum, interval) => {
    return sum + Math.pow(interval - avgInterval, 2);
  }, 0) / intervals.length;
  
  // Lower variance = higher consistency
  return Math.max(0, 1 - (Math.sqrt(variance) / avgInterval));
}

function calculateVerticalDistance(barometer) {
  if (barometer.length < 2) return 0;
  
  const startPressure = barometer[0].pressure_hpa;
  const endPressure = barometer[barometer.length - 1].pressure_hpa;
  
  // Convert pressure difference to approximate elevation change
  // 1 hPa ≈ 8.4 meters at sea level
  return Math.abs(startPressure - endPressure) * 8.4;
}

function calculateMovementIntensity(accelerometer) {
  if (accelerometer.length === 0) return 0;
  
  const magnitudes = accelerometer.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  return magnitudes.reduce((sum, mag) => sum + mag, 0) / magnitudes.length;
}

function calculateAccelerometerVariance(accelerometer) {
  if (accelerometer.length < 2) return 0;
  
  const magnitudes = accelerometer.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  const avg = magnitudes.reduce((sum, mag) => sum + mag, 0) / magnitudes.length;
  const variance = magnitudes.reduce((sum, mag) => sum + Math.pow(mag - avg, 2), 0) / magnitudes.length;
  
  return variance;
}

function calculateAverageAcceleration(accelerometer) {
  if (accelerometer.length === 0) return 0;
  
  const magnitudes = accelerometer.map(reading => 
    Math.sqrt(reading.x * reading.x + reading.y * reading.y + reading.z * reading.z)
  );
  
  return magnitudes.reduce((sum, mag) => sum + mag, 0) / magnitudes.length;
}

function calculateVerticalMotionTime(verticalEvents) {
  return verticalEvents.reduce((total, event) => total + (event.duration_ms || 0), 0);
}

function calculateSessionDuration(startTime, endTime) {
  if (!startTime || !endTime) return 0;
  const start = new Date(startTime);
  const end = new Date(endTime);
  return (end - start) / (1000 * 60); // Return minutes
}

// ——— Sensor Data Upload Endpoint ———
app.post('/api/v1/sensor-data', async (req, res) => {
  try {
    const sensorData = req.body;
    
    // Validate required fields
    if (!sensorData.session_id || !sensorData.device_id || !sensorData.sensor_data) {
      return res.status(400).json({ 
        error: 'Missing required fields: session_id, device_id, sensor_data' 
      });
    }
    
    // Log the received data for debugging
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
    
    // TODO: Store in database
    // await storeSessionData(processedData);
    
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
// Start server
const PORT = process.env.PORT || 3000;

async function startServer() {
  await initializeDatabase();
  app.listen(PORT, '0.0.0.0', () =>
    console.log(`Secure API server with admin dashboard listening on http://0.0.0.0:${PORT}`)
  );
}

startServer().catch(console.error);
