"""
NEXUS SOC — Banking Cyber Defense System
Main FastAPI Backend Server
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import json
import logging
from datetime import datetime
from typing import List, Optional
import uvicorn

from modules.auth_security import AuthSecurityModule
from modules.device_tracker import DeviceTracker
from modules.fraud_detection import FraudDetectionModule
from modules.anomaly_detection import AnomalyDetectionModule
from modules.ip_blocker import IPBlocker
from modules.encryption_module import EncryptionModule
from modules.event_logger import EventLogger
from agents.network_agent import NetworkMonitoringAgent
from agents.auth_agent import AuthenticationAgent
from agents.fraud_agent import FraudDetectionAgent
from agents.threat_agent import ThreatResponseAgent
from encryption_module import EncryptionModule

# Initialize the security core
crypto = EncryptionModule()

@app.post("/analyze")
async def analyze_transaction(txn: Transaction):
    # 1. ENCRYPT PII (Personally Identifiable Information)
    # We encrypt the user_id before it goes to the logs or external agents
    context = f"txn:{txn.txn_id}"
    encrypted_user = crypto.encrypt(txn.user_id, context=context)
    
    # 2. ANONYMIZED PAYLOAD
    # We send the hashed/anonymized data to the agents
    payload = txn.dict()
    payload["user_id"] = encrypted_user.decode() # Sending encrypted blob
    
    print(f"🔒 Processing Encrypted Transaction: {txn.txn_id}")
    
    # ... rest of your multi-agent logic ...

# ─── App Configuration ────────────────────────────────────────
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nexus-soc")

# ─── Module Initialization ────────────────────────────────────
auth_module     = AuthSecurityModule()
device_tracker  = DeviceTracker()
fraud_module    = FraudDetectionModule()
anomaly_module  = AnomalyDetectionModule()
ip_blocker      = IPBlocker()
crypto          = EncryptionModule()
event_logger    = EventLogger()

# Multi-Agent System
net_agent    = NetworkMonitoringAgent(ip_blocker, event_logger)
auth_agent   = AuthenticationAgent(auth_module, anomaly_module, event_logger)
fraud_agent  = FraudDetectionAgent(fraud_module, event_logger)
threat_agent = ThreatResponseAgent(ip_blocker, event_logger)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# ─── REST Endpoints ───────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "NEXUS SOC Online", "version": "4.2.1", "agents": 4}

@app.get("/api/dashboard/overview")
async def get_overview():
    """System overview metrics"""
    return {
        "total_transactions": event_logger.get_transaction_count(),
        "suspicious_activities": event_logger.get_suspicious_count(),
        "active_users": auth_module.get_active_user_count(),
        "blocked_ips": len(ip_blocker.get_blocked_ips()),
        "blocked_macs": len(ip_blocker.get_blocked_macs()),
        "threat_score": threat_agent.get_current_threat_score(),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/auth/login")
async def process_login(login_data: dict):
    """
    Process a login attempt through the security pipeline.
    Runs device tracking, behavior analysis, and anomaly scoring.
    """
    user_id    = login_data.get("user_id")
    auth_method = login_data.get("auth_method")
    device_id  = login_data.get("device_id")
    ip_address = login_data.get("ip_address")
    mac_address = login_data.get("mac_address")
    location   = login_data.get("location")
    biometric_data = login_data.get("biometric_data")

    # 1. Check IP/MAC blocklist
    if ip_blocker.is_blocked(ip_address, mac_address):
        event_logger.log_blocked_attempt(user_id, ip_address, mac_address)
        await manager.broadcast({
            "type": "THREAT",
            "severity": "HIGH",
            "message": f"Blocked login attempt from {ip_address}",
            "timestamp": datetime.utcnow().isoformat()
        })
        raise HTTPException(status_code=403, detail="Access denied — IP/MAC blocked")

    # 2. Track device fingerprint
    device_trust = device_tracker.check_device(user_id, device_id, mac_address, ip_address)

    # 3. Verify biometric/auth credential (if provided)
    auth_result = None
    if biometric_data:
        encrypted = crypto.encrypt(biometric_data)
        auth_result = auth_module.verify_biometric(user_id, encrypted, auth_method)

    # 4. Run behavior anomaly detection
    anomaly_score = anomaly_module.score_login(
        user_id=user_id,
        auth_method=auth_method,
        device_id=device_id,
        ip=ip_address,
        location=location,
        login_time=datetime.utcnow()
    )

    # 5. Record authentication event
    auth_record = auth_module.record_attempt(
        user_id=user_id,
        auth_method=auth_method,
        device_id=device_id,
        ip=ip_address,
        location=location,
        anomaly_score=anomaly_score,
        success=auth_result is not False
    )

    # 6. If anomaly threshold exceeded → trigger response
    if anomaly_score > 70:
        response_action = await threat_agent.respond(
            user_id=user_id,
            ip=ip_address,
            mac=mac_address,
            score=anomaly_score
        )
        await manager.broadcast({
            "type": "ANOMALY",
            "severity": "HIGH",
            "user_id": user_id,
            "ip": ip_address,
            "anomaly_score": anomaly_score,
            "action": response_action,
            "timestamp": datetime.utcnow().isoformat()
        })

    return {
        "success": auth_result is not False,
        "anomaly_score": anomaly_score,
        "device_trusted": device_trust,
        "require_mfa": anomaly_score > 50,
        "auth_id": auth_record.get("auth_id") if auth_record else None
    }

@app.post("/api/transaction/analyze")
async def analyze_transaction(txn: dict):
    """Analyze a financial transaction for fraud"""
    result = fraud_module.analyze(
        user_id=txn.get("user_id"),
        amount=txn.get("amount"),
        recipient=txn.get("recipient"),
        tx_time=txn.get("timestamp"),
        ip=txn.get("ip_address"),
        location=txn.get("location")
    )

    if result["fraud_probability"] > 0.7:
        await manager.broadcast({
            "type": "FRAUD_ALERT",
            "severity": "CRITICAL",
            "transaction": txn,
            "fraud_score": result["fraud_probability"],
            "reasons": result["reasons"],
            "timestamp": datetime.utcnow().isoformat()
        })
        # Trigger auto-response
        if result["fraud_probability"] > 0.9:
            await threat_agent.freeze_account(txn.get("user_id"))

    return result

@app.get("/api/network/devices")
async def get_devices():
    """Get all tracked devices"""
    return device_tracker.get_all_devices()

@app.get("/api/threats/feed")
async def get_threat_feed(limit: int = 50):
    """Get recent threat events"""
    return event_logger.get_recent_events(limit)

@app.get("/api/threats/blocked")
async def get_blocked():
    """Get blocked IPs and MACs"""
    return {
        "blocked_ips": ip_blocker.get_blocked_ips(),
        "blocked_macs": ip_blocker.get_blocked_macs()
    }

@app.post("/api/threats/block")
async def manual_block(block_data: dict):
    """Manually block an IP or MAC"""
    ip = block_data.get("ip")
    mac = block_data.get("mac")
    reason = block_data.get("reason", "Manual block by admin")

    if ip:
        ip_blocker.block_ip(ip, reason)
    if mac:
        ip_blocker.block_mac(mac, reason)

    event_logger.log_event("MANUAL_BLOCK", "HIGH", ip or mac, reason)
    await manager.broadcast({
        "type": "BLOCKED",
        "ip": ip,
        "mac": mac,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat()
    })
    return {"status": "blocked", "ip": ip, "mac": mac}

@app.get("/api/ml/status")
async def get_ml_status():
    """Get ML model performance metrics"""
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

# ─── WebSocket Live Feed ──────────────────────────────────────
@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial state
        await websocket.send_json({
            "type": "CONNECTED",
            "message": "NEXUS SOC Live Feed Connected",
            "timestamp": datetime.utcnow().isoformat()
        })
        while True:
            # Keep connection alive; broadcasts sent via manager
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ─── Agent Orchestrator ────────────────────────────────────────
async def run_agents():
    """Background task: run all agents in parallel"""
    while True:
        try:
            # Run agent tick
            net_events   = await net_agent.tick()
            auth_events  = await auth_agent.tick()
            fraud_events = await fraud_agent.tick()

            all_events = net_events + auth_events + fraud_events
            for event in all_events:
                await threat_agent.evaluate(event)
                await manager.broadcast(event)

        except Exception as e:
            logger.error(f"Agent error: {e}")
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup():
    logger.info("🚀 NEXUS SOC Backend Starting...")
    logger.info("🤖 Initializing Multi-Agent System...")
    asyncio.create_task(run_agents())
    logger.info("✅ All agents online. Dashboard ready.")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
