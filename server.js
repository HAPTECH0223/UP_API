// server.js
const express       = require('express');
const cors          = require('cors');
const rateLimit     = require('express-rate-limit');

// Load your API key from env (set this in Render or your local .env)
const API_KEY       = process.env.API_KEY || 'my-test-key';
const DATA_FILE     = process.env.DB_FILE || 'db.json';
const data          = require(`./${DATA_FILE}`).verticalDelay;

const app = express();

// Trust the first proxy (Render’s load-balancer)
// so express-rate-limit can correctly read X-Forwarded-For
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());
app.use(apiKeyMiddleware);
app.use(limiter);


// 1) API-Key check middleware
app.use((req, res, next) => {
  const key = req.header('x-api-key') || req.query.api_key;
  if (key !== API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  next();
});

// 2) Rate limiter: max 100 requests per 15 minutes per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15m
  max: 100,
  standardHeaders: true,     // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false,      // Disable the `X-RateLimit-*` headers
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

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

// Start the stub server, respecting Render’s PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Mock API listening on http://0.0.0.0:${PORT}`);
});
