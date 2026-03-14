=====================================================
  BACKEND ENGINEER FILES
  NEXUS SOC Hackathon
=====================================================

YOUR 7 FILES:
  - main.py              ← FastAPI server (run this)
  - auth_security.py     ← Login validation + bcrypt
  - device_tracker.py    ← IP/MAC fingerprint tracking
  - ip_blocker.py        ← Blocklist management
  - encryption_module.py ← AES-256 encryption
  - event_logger.py      ← Security event logging
  - requirements.txt     ← All dependencies

STEP 1 — Get ML engineer's files:
  Ask ML engineer to send you their 7 files.
  Put them ALL in the same folder as main.py.

STEP 2 — Install (1 command):
  pip install -r requirements.txt

  If cryptography fails:
  pip install fastapi uvicorn bcrypt scikit-learn numpy

STEP 3 — Run:
  python main.py
  Server starts at http://localhost:8000
  API docs at http://localhost:8000/docs  ← show judges this!

STEP 4 — Connect to DB (when DB engineer is ready):
  Create file .env in same folder:
    DATABASE_URL=postgresql://postgres:password@localhost/nexus_soc
  (Without this it still runs fine with in-memory data)

ENDPOINTS TO DEMO TO JUDGES:
  GET  http://localhost:8000/api/dashboard/overview
  GET  http://localhost:8000/api/threats/feed
  GET  http://localhost:8000/api/threats/blocked
  WS   ws://localhost:8000/ws/live-feed

TEST A LOGIN (paste in terminal):
  curl -X POST http://localhost:8000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"user_id":"USR_4421","auth_method":"PATTERN",
         "device_id":"DEV_UNKNOWN","ip_address":"185.220.101.44",
         "location":"Unknown"}'
  → Should return anomaly_score > 70 and require_mfa: true

TEST A FRAUD TRANSACTION:
  curl -X POST http://localhost:8000/api/transaction/analyze \
    -H "Content-Type: application/json" \
    -d '{"user_id":"USR_4421","amount":5200000,
         "recipient":"ACC_OFFSHORE","ip_address":"185.220.101.44",
         "location":"Unknown"}'
  → Should return fraud_probability > 0.9

YOUR TALKING POINT FOR JUDGES:
  "I built the FastAPI backend that orchestrates 4 AI
   agents running in parallel background tasks. Every
   login goes through device fingerprinting, anomaly
   scoring, and automatic threat response. The
   WebSocket streams real-time events to the dashboard.
   All biometrics are AES-256-GCM encrypted."
