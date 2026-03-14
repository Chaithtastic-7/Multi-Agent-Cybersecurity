"""
auth_agent.py — Authentication Monitoring Agent
"""
import asyncio
import random
from datetime import datetime
from typing import List


class AuthenticationAgent:
    def __init__(self, auth_module, anomaly_module, event_logger):
        self._auth = auth_module
        self._anomaly = anomaly_module
        self._logger = event_logger
        self._anomaly_count = 0

    async def tick(self) -> List[dict]:
        events = []
        if random.random() < 0.05:
            user = f"USR_{random.randint(1000,9999)}"
            score = random.uniform(55, 90)
            event = {
                "type": "AUTH_ANOMALY",
                "severity": "HIGH" if score > 70 else "MEDIUM",
                "user_id": user,
                "anomaly_score": score,
                "description": f"Auth anomaly for {user} — method change detected",
                "timestamp": datetime.utcnow().isoformat(),
                "agent": "AUTH_AGENT",
            }
            self._anomaly_count += 1
            events.append(event)
        return events
