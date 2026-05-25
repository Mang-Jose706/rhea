Presence server (heartbeat)

1. Install dependencies:

```bash
cd server
npm install
```

2. Start server:

```bash
npm start
```

3. Endpoints:
- POST /presence/heartbeat  { userId }
- GET  /presence/:userId
- GET  /presence

This is an in-memory server useful for local testing only.
