"""
NEXUS SOC — Banking Cyber Defense System
Main FastAPI Backend Server

Run:  python main.py
Docs: http://localhost:8000/docs
"""

# ── Graceful import check ─────────────────────────────────────
import sys

missing = []
try:
    import fastapi
except ImportError:
    missing.append("fastapi")
try:
    import uvicorn
except ImportError:
    missing.append("uvicorn")

if missing:
    print("=" * 55)
    print("ERROR: Missing packages. Run this first:")
    print(f"  pip install {' '.join(missing)}")
    print("=" * 55)
    sys.exit(1)

# ── Main imports ──────────────────────────────────────────────
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional
import uvicorn

# ── Local module imports ──────────────────────────────────────
from backend_engineer.auth_security     import AuthSecurityModule
from backend_engineer.device_tracker    import DeviceTracker
from DL_engineer.fraud_detection   import FraudDetectionModule
from DL_engineer.anomaly_detection import AnomalyDetectionModule
from backend_engineer.ip_blocker        import IPBlocker
from backend_engineer.encryption_module import EncryptionModule
from backend_engineer.event_logger      import EventLogger
from DL_engineer.network_agent      import NetworkMonitoringAgent
from DL_engineer.auth_agent         import AuthenticationAgent
from DL_engineer.fraud_agent        import FraudDetectionAgent
from DL_engineer.threat_agent       import ThreatResponseAgent

# ── App Setup ─────────────────────────────────────────────────
app = FastAPI(
    title="NEXUS SOC — Banking Cyber Defense API",
    description="Multi-Agent Cybersecurity Defense System for Banking Networks",
    version="4.2.1"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nexus-soc")

# ── Module Init ───────────────────────────────────────────────
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

# ── WebSocket Manager ─────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

# ── Routes ────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "NEXUS SOC Online", "version": "4.2.1", "agents": 4}

@app.get("/api/dashboard/overview")
async def get_overview():
    return {
        "total_transactions": event_logger.get_transaction_count(),
        "suspicious_activities": event_logger.get_suspicious_count(),
        "active_users": auth_module.get_active_user_count(),
        "blocked_ips": len(ip_blocker.get_blocked_ips()),
        "blocked_macs": len(ip_blocker.get_blocked_macs()),
        "threat_score": threat_agent.get_current_threat_score(),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/api/auth/login")
async def process_login(login_data: dict):
    user_id     = login_data.get("user_id", "")
    auth_method = login_data.get("auth_method", "PASSWORD")
    device_id   = login_data.get("device_id", "")
    ip_address  = login_data.get("ip_address", "0.0.0.0")
    mac_address = login_data.get("mac_address")
    location    = login_data.get("location", "Unknown")

    # 1. Blocklist check
    if ip_blocker.is_blocked(ip_address, mac_address):
        event_logger.log_event("BLOCKED_LOGIN", "HIGH", ip_address,
                                f"Blocked login attempt from {ip_address}")
        raise HTTPException(status_code=403, detail="Access denied — IP/MAC blocked")

    # 2. Device fingerprint check
    device_trust = device_tracker.check_device(
        user_id, device_id, mac_address or "", ip_address
    )

    # 3. Anomaly score
    anomaly_score = anomaly_module.score_login(
        user_id=user_id, auth_method=auth_method, device_id=device_id,
        ip=ip_address, location=location, login_time=datetime.now(timezone.utc)
    )

    # 4. Record attempt
    auth_module.record_attempt(
        user_id=user_id, auth_method=auth_method, device_id=device_id,
        ip=ip_address, location=location,
        anomaly_score=anomaly_score, success=True
    )

    # 5. Auto-respond if high anomaly
    if anomaly_score > 70:
        action = await threat_agent.respond(
            user_id=user_id, ip=ip_address,
            mac=mac_address, score=anomaly_score
        )
        await manager.broadcast({
            "type": "ANOMALY", "severity": "HIGH",
            "user_id": user_id, "ip": ip_address,
            "anomaly_score": anomaly_score,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    return {
        "success": True,
        "anomaly_score": anomaly_score,
        "device_trusted": device_trust.get("trusted", False),
        "require_mfa": anomaly_score > 50,
        "flags": device_trust.get("flags", [])
    }

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
    if result["fraud_probability"] > 0.7:
        await manager.broadcast({
            "type": "FRAUD_ALERT", "severity": "CRITICAL",
            "fraud_score": result["fraud_probability"],
            "reasons": result["reasons"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        if result["fraud_probability"] > 0.9:
            await threat_agent.freeze_account(txn.get("user_id", ""))
    return result

@app.get("/api/network/devices")
async def get_devices():
    return device_tracker.get_all_devices()

@app.get("/api/threats/feed")
async def get_threat_feed(limit: int = 50):
    return event_logger.get_recent_events(limit)

@app.get("/api/threats/blocked")
async def get_blocked():
    return {
        "blocked_ips": ip_blocker.get_blocked_ips(),
        "blocked_macs": ip_blocker.get_blocked_macs()
    }

@app.post("/api/threats/block")
async def manual_block(block_data: dict):
    ip  = block_data.get("ip")
    mac = block_data.get("mac")
    reason = block_data.get("reason", "Manual block by admin")
    if ip:
        ip_blocker.block_ip(ip, reason)
    if mac:
        ip_blocker.block_mac(mac, reason)
    event_logger.log_event("MANUAL_BLOCK", "HIGH", ip or mac, reason)
    await manager.broadcast({
        "type": "BLOCKED", "ip": ip, "mac": mac, "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    return {"status": "blocked", "ip": ip, "mac": mac}

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

# ── WebSocket Live Feed ───────────────────────────────────────
@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "CONNECTED",
            "message": "NEXUS SOC Live Feed Connected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ── Background Agent Loop ─────────────────────────────────────
async def run_agents():
    while True:
        try:
            net_events   = await net_agent.tick()
            auth_events  = await auth_agent.tick()
            fraud_events = await fraud_agent.tick()
            for event in net_events + auth_events + fraud_events:
                await threat_agent.evaluate(event)
                await manager.broadcast(event)
        except Exception as e:
            logger.error(f"Agent error: {e}")
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup():
    logger.info("🚀 NEXUS SOC Backend Starting...")
    asyncio.create_task(run_agents())
    logger.info("✅ All agents online.")

# ── Entry Point ───────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
