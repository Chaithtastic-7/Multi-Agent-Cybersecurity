"""
fraud_agent.py — Fraud Detection Agent
"""
import random
from datetime import datetime
from typing import List


class FraudDetectionAgent:
    def __init__(self, fraud_module, event_logger):
        self._fraud = fraud_module
        self._logger = event_logger
        self._critical_count = 0

    async def tick(self) -> List[dict]:
        events = []
        if random.random() < 0.04:
            user = f"USR_{random.randint(1000,9999)}"
            amount = random.randint(100000, 5000000)
            prob = random.uniform(0.65, 0.99)
            event = {
                "type": "FRAUD_ALERT",
                "severity": "CRITICAL" if prob > 0.85 else "HIGH",
                "user_id": user,
                "amount": amount,
                "fraud_probability": prob,
                "description": f"Fraud detected for {user} — ₹{amount:,} transfer, {prob:.1%} probability",
                "timestamp": datetime.utcnow().isoformat(),
                "agent": "FRAUD_AGENT",
            }
            self._critical_count += 1
            events.append(event)
        return events
