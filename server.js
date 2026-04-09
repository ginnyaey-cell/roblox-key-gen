const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();

app.use(cors());
app.use(express.json());

// In-memory storage for keys (use database in production)
const keys = new Map();

// Generate a secure random key
function generateKey() {
  return crypto.randomBytes(16).toString('hex');
}

// API endpoint to generate a key
app.post('/api/generate-key', (req, res) => {
  const { expirationHours, shortlink, steps } = req.body;
  
  if (!expirationHours) {
    return res.status(400).json({ error: 'Expiration hours required' });
  }

  const key = generateKey();
  const expirationTime = new Date();
  expirationTime.setHours(expirationTime.getHours() + parseInt(expirationHours));
  
  const keyData = {
    key,
    createdAt: new Date(),
    expiresAt: expirationTime,
    shortlink: shortlink || null,
    steps: steps || 1,
    isValid: true
  };

  keys.set(key, keyData);

  res.json({
    success: true,
    key,
    expiresAt: expirationTime,
    shortlink: shortlink ? `https://short.link/${key}` : null,
    message: 'Key generated successfully'
  });
});

// API endpoint to verify a key
app.post('/api/verify-key', (req, res) => {
  const { key } = req.body;

  if (!key) {
    return res.status(400).json({ error: 'Key required' });
  }

  const keyData = keys.get(key);

  if (!keyData) {
    return res.status(404).json({ error: 'Key not found' });
  }

  if (new Date() > keyData.expiresAt) {
    keyData.isValid = false;
    return res.status(401).json({ error: 'Key expired' });
  }

  if (!keyData.isValid) {
    return res.status(401).json({ error: 'Key is invalid' });
  }

  res.json({
    success: true,
    key,
    expiresAt: keyData.expiresAt,
    steps: keyData.steps,
    message: 'Key is valid'
  });
});

// API endpoint to use/consume a key
app.post('/api/use-key', (req, res) => {
  const { key, currentStep } = req.body;

  if (!key) {
    return res.status(400).json({ error: 'Key required' });
  }

  const keyData = keys.get(key);

  if (!keyData) {
    return res.status(404).json({ error: 'Key not found' });
  }

  if (new Date() > keyData.expiresAt) {
    keyData.isValid = false;
    return res.status(401).json({ error: 'Key expired' });
  }

  if (!keyData.isValid) {
    return res.status(401).json({ error: 'Key is invalid' });
  }

  // Check if current step is within allowed steps
  if (currentStep && currentStep > keyData.steps) {
    return res.status(403).json({ error: 'Step limit exceeded for this key' });
  }

  res.json({
    success: true,
    message: 'Key validated for use',
    nextStep: (currentStep || 0) + 1,
    totalSteps: keyData.steps
  });
});

// Cleanup expired keys every hour
setInterval(() => {
  const now = new Date();
  for (const [key, data] of keys.entries()) {
    if (now > data.expiresAt) {
      keys.delete(key);
    }
  }
}, 3600000); // 1 hour

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Key generator API running on port ${PORT}`);
});
