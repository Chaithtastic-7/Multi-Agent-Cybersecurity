"""
event_logger.py — Security Event Logger
Logs all security events, threat detections, and audit trails.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Optional
from collections import deque


class EventLogger:
    """
    Centralized security event logging for the SOC dashboard.
    Maintains in-memory ring buffer + would write to DB/SIEM in production.
    """

    MAX_EVENTS = 10_000

    def __init__(self):
        self._events: deque = deque(maxlen=self.MAX_EVENTS)
        self._transaction_count = 48_291
        self._suspicious_count = 127
        self._seed_initial_events()

    def _seed_initial_events(self):
        seed = [
            ("SYSTEM_START",     "INFO",   None,               "NEXUS SOC backend initialized — all agents online"),
            ("AUTH_ANOMALY",     "HIGH",   "192.168.4.22",      "USR_4421 auth method changed FINGERPRINT→PATTERN from unknown device"),
            ("FRAUD_ALERT",      "CRITICAL","185.220.101.44",   "USR_4421 rapid transfer burst — 7 txns in 12s, ₹8,40,000 total"),
            ("IP_BLOCKED",       "HIGH",   "185.220.101.44",    "Auto-blocked — fraud trigger, threat score 94"),
            ("BRUTE_FORCE",      "HIGH",   "45.142.212.100",    "247 failed login attempts in 60s — brute force detected"),
            ("IP_BLOCKED",       "HIGH",   "45.142.212.100",    "Auto-blocked — brute force threshold exceeded"),
            ("LARGE_TRANSFER",   "HIGH",   "172.16.8.44",       "ACC_7892 offshore transfer ₹52,00,000 — unknown recipient"),
            ("ACCOUNT_FROZEN",   "CRITICAL","192.168.4.22",     "USR_4421 account temporarily frozen pending verification"),
        ]
        for event_type, severity, ip, description in seed:
            self.log_event(event_type, severity, ip, description)

    def log_event(self, event_type: str, severity: str,
                  ip: Optional[str], description: str,
                  extra: dict = None) -> dict:
        """Log a security event."""
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "severity": severity,
            "ip": ip,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "extra": extra or {},
        }
        self._events.append(event)

        # Count suspicious events
        if severity in ("HIGH", "CRITICAL"):
            self._suspicious_count += 1

        return event

    def log_blocked_attempt(self, user_id: str, ip: str, mac: str):
        self.log_event(
            "BLOCKED_ACCESS", "HIGH", ip,
            f"Login attempt from blocked IP/MAC — User: {user_id}, MAC: {mac}"
        )

    def get_recent_events(self, limit: int = 50) -> List[dict]:
        """Get most recent events."""
        events = list(self._events)
        return events[-limit:][::-1]  # Most recent first

    def get_events_by_type(self, event_type: str, limit: int = 20) -> List[dict]:
        return [e for e in reversed(list(self._events))
                if e["event_type"] == event_type][:limit]

    def get_events_by_severity(self, severity: str, limit: int = 20) -> List[dict]:
        return [e for e in reversed(list(self._events))
                if e["severity"] == severity][:limit]

    def get_transaction_count(self) -> int:
        import random
        self._transaction_count += random.randint(5, 25)
        return self._transaction_count

    def get_suspicious_count(self) -> int:
        return self._suspicious_count

    def get_stats(self) -> dict:
        events = list(self._events)
        return {
            "total_events": len(events),
            "critical": sum(1 for e in events if e["severity"] == "CRITICAL"),
            "high": sum(1 for e in events if e["severity"] == "HIGH"),
            "info": sum(1 for e in events if e["severity"] == "INFO"),
        }
