// server.js
const express = require('express');
const cors    = require('cors');

// Use an env var for the data file, falling back to db.json
const DATA_FILE = process.env.DB_FILE || 'db.json';
const data      = require(`./${DATA_FILE}`).verticalDelay;

const app = express();
app.use(cors());
app.use(express.json());

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

// Listen on the port Render (or any host) gives you
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Mock API listening on http://0.0.0.0:${PORT}`);
});
