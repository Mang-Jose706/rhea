const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// In-memory presence store: userId -> timestamp (ms)
const presence = new Map();
const PRESENCE_THRESHOLD_MS = 60000; // 60s

app.post('/presence/heartbeat', (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'missing userId' });
  const now = Date.now();
  presence.set(userId.toString(), now);
  return res.json({ ok: true, userId, lastSeen: new Date(now).toISOString() });
});

app.get('/presence/:userId', (req, res) => {
  const userId = req.params.userId;
  const t = presence.get(userId);
  if (!t) return res.json({ userId, online: false, lastSeen: null });
  const online = (Date.now() - t) < PRESENCE_THRESHOLD_MS;
  return res.json({ userId, online, lastSeen: new Date(t).toISOString() });
});

app.get('/presence', (req, res) => {
  const out = [];
  for (const [userId, t] of presence.entries()) {
    out.push({ userId, lastSeen: new Date(t).toISOString(), online: (Date.now() - t) < PRESENCE_THRESHOLD_MS });
  }
  res.json(out);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Presence server listening on http://localhost:${PORT}`));
