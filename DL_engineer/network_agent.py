"""
network_agent.py — Network Monitoring Agent
Analyzes network traffic, IP activity, and device patterns.
"""

import asyncio
import random
from datetime import datetime
from typing import List


class NetworkMonitoringAgent:
    """
    Continuously monitors network traffic for anomalies.
    Detects: port scans, DDoS, botnet C2 activity, IP spoofing.
    """

    def __init__(self, ip_blocker, event_logger):
        self._ip_blocker = ip_blocker
        self._event_logger = event_logger
        self._packets_per_sec = 2841
        self._scan_count = 0

    async def tick(self) -> List[dict]:
        """One monitoring cycle — returns list of events."""
        events = []
        self._scan_count += 1
        self._packets_per_sec = random.randint(2200, 3400)

        # Simulate occasional network anomaly detection
        if random.random() < 0.08:
            suspicious_ip = f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            event = {
                "type": "NETWORK_ANOMALY",
                "severity": "HIGH",
                "ip": suspicious_ip,
                "description": f"Suspicious traffic pattern from {suspicious_ip} — port scan detected",
                "timestamp": datetime.utcnow().isoformat(),
                "agent": "NET_MONITOR",
            }
            self._event_logger.log_event("PORT_SCAN", "HIGH", suspicious_ip, event["description"])
            events.append(event)

        return events

    def get_packets_per_sec(self) -> int:
        return self._packets_per_sec
