// server.js
const express = require('express');
const cors    = require('cors');
const data    = require('./db.json').verticalDelay; // array from your db.json

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

// Start the stub server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Mock API listening on http://localhost:${PORT}`);
});
