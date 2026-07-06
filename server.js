const express = require('express');
const safeMerge = require('./safeMerge');

const app = express();
app.use(express.json());

// Original vulnerable endpoint (commented out for reference):
// app.post('/update', (req, res) => {
//   const config = loadConfig();   // e.g., { theme: 'dark' }
//   Object.assign(config, req.body); // Shallow merge – but if body has __proto__, it pollutes
//   // ...
// });

// Fixed endpoint using safe merge
app.post('/update', (req, res) => {
  try {
    const config = loadConfig(); // assume this returns a plain object
    const updatedConfig = safeMerge({}, config, req.body); // merge safely
    saveConfig(updatedConfig);
    res.json({ status: 'ok' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

function loadConfig() {
  return { theme: 'dark', language: 'en' };
}

function saveConfig(config) {
  // persistence logic
  console.log('Config saved:', config);
}

app.listen(3000, () => console.log('Server running on port 3000'));
