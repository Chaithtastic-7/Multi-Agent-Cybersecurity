import asyncio
import json
import logging
import uvicorn
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Import your custom modules
from auth_security import AuthSecurityModule
from device_tracker import DeviceTracker
from ip_blocker import IPBlocker
from encryption_module import EncryptionModule
from event_logger import EventLogger

# These likely need to be imported or defined in your modules
# Assuming AnomalyDetectionModule and FraudDetectionModule exist in your project
from DL_engineer.fraud_detection import FraudDetectionModule
from DL_engineer.anomaly_detection import AnomalyDetectionModule

# Agent imports
from DL_engineer.network_agent import NetworkMonitoringAgent
from DL_engineer.auth_agent import AuthenticationAgent
from DL_engineer.fraud_agent import FraudDetectionAgent
from DL_engineer.threat_agent import ThreatResponseAgent

# ─── Pydantic Models ──────────────────────────────────────────
class Transaction(BaseModel):
    txn_id: str
    user_id: str
    amount: float
    recipient: str
    location: Optional[str] = "Unknown"
    ip_address: Optional[str] = "0.0.0.0"
    timestamp: Optional[str] = None

# ─── App Configuration ────────────────────────────────────────
app = FastAPI(
    title="NEXUS SOC — Banking Cyber Defense API",
    description="Multi-Agent Cybersecurity Defense System",
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

# ─── WebSocket Connection Manager ─────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
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
    return {
        "total_transactions": event_logger.get_transaction_count(),
        "suspicious_activities": event_logger.get_suspicious_count(),
        "active_users": auth_module.get_active_user_count(),
        "blocked_ips": len(ip_blocker.get_blocked_ips()),
        "blocked_macs": len(ip_blocker.get_blocked_macs()),
        "threat_score": threat_agent.get_current_threat_score(),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/transaction/analyze")
async def analyze_transaction(txn: Transaction):
    """
    Main Transaction Analysis Pipeline.
    Encrypts PII and runs Fraud/Anomaly detection.
    """
    # 1. ENCRYPT PII (Anonymize for agents)
    context = f"txn:{txn.txn_id}"
    encrypted_user = crypto.encrypt(txn.user_id, context=context)
    
    # 2. Prepare Data for Agents
    txn_data = txn.dict()
    txn_data["encrypted_user_id"] = encrypted_user.decode() if isinstance(encrypted_user, bytes) else encrypted_user
    
    # 3. Analyze for Fraud
    result = fraud_module.analyze(
        user_id=txn.user_id,
        amount=txn.amount,
        recipient=txn.recipient,
        tx_time=txn.timestamp or datetime.utcnow().isoformat(),
        ip=txn.ip_address,
        location=txn.location
    )

    # 4. Critical Alert Handling
    if result["fraud_probability"] > 0.7:
        alert_msg = {
            "type": "FRAUD_ALERT",
            "severity": "CRITICAL",
            "transaction": txn_data,
            "fraud_score": result["fraud_probability"],
            "reasons": result.get("reasons", []),
            "timestamp": datetime.utcnow().isoformat()
        }
        await manager.broadcast(alert_msg)
        
        if result["fraud_probability"] > 0.9:
            await threat_agent.freeze_account(txn.user_id)

    return result

@app.post("/api/auth/login")
async def process_login(login_data: dict):
    user_id = login_data.get("user_id")
    ip_address = login_data.get("ip_address")
    mac_address = login_data.get("mac_address")

    # 1. Blocklist Check
    if ip_blocker.is_blocked(ip_address, mac_address):
        event_logger.log_blocked_attempt(user_id, ip_address, mac_address)
        await manager.broadcast({
            "type": "THREAT",
            "severity": "HIGH",
            "message": f"Blocked attempt: {ip_address}",
            "timestamp": datetime.utcnow().isoformat()
        })
        raise HTTPException(status_code=403, detail="Access denied")

    # 2. Logic Chain: Device Tracking -> Anomaly Scoring
    device_trust = device_tracker.check_device(user_id, login_data.get("device_id"), mac_address, ip_address)
    anomaly_score = anomaly_module.score_login(user_id=user_id, **login_data)

    # 3. Threat Response
    if anomaly_score > 70:
        action = await threat_agent.respond(user_id, ip_address, mac_address, anomaly_score)
        await manager.broadcast({"type": "ANOMALY", "user_id": user_id, "score": anomaly_score, "action": action})

    return {"success": True, "anomaly_score": anomaly_score, "device_trusted": device_trust}

# ─── WebSocket Live Feed ──────────────────────────────────────
@app.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "CONNECTED", "timestamp": datetime.utcnow().isoformat()})
        while True:
            data = await websocket.receive_text()
            if data == "ping": await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ─── Agent Orchestrator ────────────────────────────────────────
async def run_agents():
    """Continuous Background Orchestrator"""
    while True:
        try:
            # Gather events from all specialized agents
            net_events   = await net_agent.tick()
            auth_events  = await auth_agent.tick()
            fraud_events = await fraud_agent.tick()

            all_events = net_events + auth_events + fraud_events
            for event in all_events:
                await threat_agent.evaluate(event)
                await manager.broadcast(event)

        except Exception as e:
            logger.error(f"Agent Engine Error: {e}")
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup():
    logger.info("🤖 NEXUS SOC Backend/Agents Starting...")
    asyncio.create_task(run_agents())

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)