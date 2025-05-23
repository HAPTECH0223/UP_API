// server.js
const express       = require('express');
const cors          = require('cors');
const rateLimit     = require('express-rate-limit');

const API_KEY       = process.env.API_KEY || 'my-test-key';
const DATA_FILE     = process.env.DB_FILE  || 'db.json';
const data          = require(`./${DATA_FILE}`).verticalDelay;

const app = express();

// Trust Render’s proxy so rateLimit can read X-Forwarded-For
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());

// ——— Define API Key middleware here ———
const apiKeyMiddleware = (req, res, next) => {
  const key = req.header('x-api-key') || req.query.api_key;
  if (key !== API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  next();
};

// ——— Rate limiter setup ———
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,    // 15 minutes
  max: 100,                    // limit each key to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },

  // HERE: use the API key as the identifier
  keyGenerator: (req /*, res*/) => {
    // Pull from header or query-param, just like your auth middleware
    return req.header('x-api-key') || req.query.api_key || req.ip;
  }
});


// ——— Apply middleware ———
app.use(apiKeyMiddleware);
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () =>
  console.log(`Mock API listening on http://0.0.0.0:${PORT}`)
);
