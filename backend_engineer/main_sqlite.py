"""
NEXUS SOC — Banking Cyber Defense System
FastAPI Backend — SQLite3 version (Mac friendly)

Setup:  python3 init_db.py      (run once, creates nexus_soc.db)
Run:    python3 main.py
Docs:   http://localhost:8000/docs
"""

import sys, sqlite3, os

# ── Dependency check ──────────────────────────────────────────
missing = []
try: import fastapi
except ImportError: missing.append("fastapi")
try: import uvicorn
except ImportError: missing.append("uvicorn")

if missing:
    print("=" * 55)
    print("ERROR: Missing packages. Run this first:")
    print(f"  pip3 install {' '.join(missing)}")
    print("=" * 55)
    sys.exit(1)

if not os.path.exists("nexus_soc.db"):
    print("=" * 55)
    print("ERROR: nexus_soc.db not found.")
    print("Run this first:  python3 init_db.py")
    print("=" * 55)
    sys.exit(1)

# ── Imports ───────────────────────────────────────────────────
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import asyncio, logging
from datetime import datetime, timezone
from typing import List
import uvicorn


from backend_engineer.auth_security import AuthSecurityModule
from backend_engineer.auth_security import AuthSecurityModule
from backend_engineer.device_tracker import DeviceTracker
from backend_engineer.event_logger import EventLogger
from backend_engineer.ip_blocker import IPBlocker
from DL_engineer.fraud_detection   import FraudDetectionModule
from DL_engineer.anomaly_detection import AnomalyDetectionModule
from backend_engineer.encryption_module import EncryptionModule
from DL_engineer.network_agent      import NetworkMonitoringAgent
from DL_engineer.auth_agent         import AuthenticationAgent
from DL_engineer.fraud_agent        import FraudDetectionAgent
from DL_engineer.threat_agent       import ThreatResponseAgent
from fastapi.middleware.cors import CORSMiddleware

# ... (where you define app = FastAPI())


# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title="NEXUS SOC — Banking Cyber Defense",
    description="Multi-Agent Cybersecurity Defense System",
    version="4.2.1"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nexus-soc")

# ── SQLite helper ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("nexus_soc.db")
    conn.row_factory = sqlite3.Row   # rows act like dicts
    return conn

# ── Module init ───────────────────────────────────────────────
auth_module    = AuthSecurityModule()
device_tracker = DeviceTracker()
fraud_module   = FraudDetectionModule()
anomaly_module = AnomalyDetectionModule()
ip_blocker     = IPBlocker()
crypto         = EncryptionModule()
event_logger   = EventLogger()

net_agent    = NetworkMonitoringAgent(ip_blocker, event_logger)
auth_agent   = AuthenticationAgent(auth_module, anomaly_module, event_logger)
fraud_agent  = FraudDetectionAgent(fraud_module, event_logger)
threat_agent = ThreatResponseAgent(ip_blocker, event_logger)

# ── WebSocket manager ─────────────────────────────────────────
class ConnectionManager:
    def __init__(self): self.active: List[WebSocket] = []
    async def connect(self, ws):
        await ws.accept(); self.active.append(ws)
    def disconnect(self, ws):
        if ws in self.active: self.active.remove(ws)
    async def broadcast(self, msg):
        dead = []
        for ws in self.active:
            try: await ws.send_json(msg)
            except: dead.append(ws)
        for ws in dead: self.disconnect(ws)

manager = ConnectionManager()

def now(): return datetime.now(timezone.utc).isoformat()

# ── Routes ────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "NEXUS SOC Online", "version": "4.2.1", "db": "SQLite3"}

# Overview — reads live counts from SQLite
@app.get("/api/dashboard/overview")
async def get_overview():
    db = get_db()
    transactions = db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    threats      = db.execute("SELECT COUNT(*) FROM threat_logs WHERE severity IN ('HIGH','CRITICAL')").fetchone()[0]
    blocked      = db.execute("SELECT COUNT(*) FROM blocked_addresses WHERE is_active=1").fetchone()[0]
    frozen       = db.execute("SELECT COUNT(*) FROM users WHERE account_status='FROZEN'").fetchone()[0]
    db.close()
    return {
        "total_transactions":    transactions + event_logger.get_transaction_count(),
        "suspicious_activities": threats + event_logger.get_suspicious_count(),
        "active_users":          auth_module.get_active_user_count(),
        "blocked_ips":           blocked,
        "blocked_macs":          len(ip_blocker.get_blocked_macs()),
        "frozen_accounts":       frozen,
        "threat_score":          threat_agent.get_current_threat_score(),
        "timestamp":             now()
    }

# Login — anomaly detection + device tracking
@app.post("/api/auth/login")
async def process_login(data: dict):
    user_id     = data.get("user_id", "")
    auth_method = data.get("auth_method", "PASSWORD")
    device_id   = data.get("device_id", "")
    ip          = data.get("ip_address", "0.0.0.0")
    mac         = data.get("mac_address")
    location    = data.get("location", "Unknown")

    if ip_blocker.is_blocked(ip, mac):
        raise HTTPException(status_code=403, detail="Access denied — IP/MAC blocked")

    device_trust  = device_tracker.check_device(user_id, device_id, mac or "", ip)
    anomaly_score = anomaly_module.score_login(
        user_id=user_id, auth_method=auth_method, device_id=device_id,
        ip=ip, location=location, login_time=datetime.now(timezone.utc)
    )
    auth_module.record_attempt(
        user_id=user_id, auth_method=auth_method, device_id=device_id,
        ip=ip, location=location, anomaly_score=anomaly_score, success=True
    )

    # Save to SQLite
    import uuid
    db = get_db()
    db.execute(
        "INSERT INTO authentication_history (auth_id,user_id,auth_method,device_id,ip_address,mac_address,location_city,success,anomaly_score) VALUES (?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), user_id, auth_method, device_id, ip, mac, location, 1, anomaly_score)
    )
    db.commit(); db.close()

    if anomaly_score > 70:
        await threat_agent.respond(user_id=user_id, ip=ip, mac=mac, score=anomaly_score)
        await manager.broadcast({
            "type": "ANOMALY", "severity": "HIGH",
            "user_id": user_id, "ip": ip,
            "anomaly_score": anomaly_score, "timestamp": now()
        })

    return {
        "success": True,
        "anomaly_score": anomaly_score,
        "device_trusted": device_trust.get("trusted", False),
        "require_mfa": anomaly_score > 50,
        "flags": device_trust.get("flags", [])
    }

# Transaction fraud analysis
@app.post("/api/transaction/analyze")
async def analyze_transaction(txn: dict):
    result = fraud_module.analyze(
        user_id=txn.get("user_id", ""),
        amount=float(txn.get("amount", 0)),
        recipient=txn.get("recipient", ""),
        tx_time=txn.get("timestamp"),
        ip=txn.get("ip_address", "0.0.0.0"),
        location=txn.get("location", "Unknown")
    )

    # Save to SQLite
    import uuid
    db = get_db()
    db.execute(
        "INSERT INTO transactions (tx_id,user_id,account_from,account_to,amount,ip_address,location,fraud_score,status) VALUES (?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), txn.get("user_id",""), txn.get("account_from","OWN"),
         txn.get("recipient",""), float(txn.get("amount",0)),
         txn.get("ip_address",""), txn.get("location",""),
         result["fraud_probability"],
         "BLOCKED" if result["fraud_probability"] > 0.8 else "APPROVED")
    )
    db.commit(); db.close()

    if result["fraud_probability"] > 0.7:
        await manager.broadcast({
            "type": "FRAUD_ALERT", "severity": "CRITICAL",
            "fraud_score": result["fraud_probability"],
            "reasons": result["reasons"], "timestamp": now()
        })
    return result

# Get all devices
@app.get("/api/network/devices")
async def get_devices():
    db = get_db()
    rows = db.execute("SELECT * FROM devices").fetchall()
    db.close()
    return [dict(r) for r in rows]

# Threat feed — from SQLite
@app.get("/api/threats/feed")
async def get_threat_feed(limit: int = 50):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]

# Blocked addresses — from SQLite
@app.get("/api/threats/blocked")
async def get_blocked():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM blocked_addresses WHERE is_active=1"
    ).fetchall()
    db.close()
    return {"blocked": [dict(r) for r in rows]}

# Manual block
@app.post("/api/threats/block")
async def manual_block(data: dict):
    import uuid
    ip     = data.get("ip")
    mac    = data.get("mac")
    reason = data.get("reason", "Manual block by admin")
    db = get_db()
    if ip:
        ip_blocker.block_ip(ip, reason)
        db.execute(
            "INSERT INTO blocked_addresses (block_id,address_type,address_value,reason) VALUES (?,?,?,?)",
            (str(uuid.uuid4()), "IP", ip, reason)
        )
    if mac:
        ip_blocker.block_mac(mac, reason)
        db.execute(
            "INSERT INTO blocked_addresses (block_id,address_type,address_value,reason) VALUES (?,?,?,?)",
            (str(uuid.uuid4()), "MAC", mac, reason)
        )
    db.commit(); db.close()
    await manager.broadcast({"type": "BLOCKED", "ip": ip, "mac": mac,
                              "reason": reason, "timestamp": now()})
    return {"status": "blocked", "ip": ip, "mac": mac}

# Users list
@app.get("/api/users")
async def get_users():
    db = get_db()
    rows = db.execute(
        "SELECT user_id, name, email, account_status, risk_level, created_at FROM users"
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]

# ML model status
@app.get("/api/ml/status")
async def get_ml_status():
    return {
        "isolation_forest": {
            "accuracy": anomaly_module.get_accuracy(),
            "last_trained": anomaly_module.last_trained,
            "samples": anomaly_module.sample_count
        },
        "random_forest": {
            "accuracy": fraud_module.get_accuracy(),
            "last_trained": fraud_module.last_trained,
            "samples": fraud_module.sample_count
        }
    }

# ── WebSocket live feed ───────────────────────────────────────
@app.websocket("/ws/live-feed")
async def ws_live_feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "CONNECTED",
                                   "message": "NEXUS SOC Live Feed Connected",
                                   "timestamp": now()})
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ── Background agents ─────────────────────────────────────────
async def run_agents():
    while True:
        try:
            events = (await net_agent.tick() +
                      await auth_agent.tick() +
                      await fraud_agent.tick())
            for e in events:
                await threat_agent.evaluate(e)
                await manager.broadcast(e)
        except Exception as ex:
            logger.error(f"Agent error: {ex}")
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup():
    logger.info("🚀 NEXUS SOC starting — SQLite3 mode")
    asyncio.create_task(run_agents())
    logger.info("✅ All agents online. http://localhost:8000/docs")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
