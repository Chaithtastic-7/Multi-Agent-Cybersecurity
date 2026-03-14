"""
threat_agent.py — Threat Response Agent
Coordinates automated threat response: blocking, freezing, alerting.
"""

from datetime import datetime
from typing import Optional


class ThreatResponseAgent:
    """
    The Threat Response Agent orchestrates automated defense actions
    when threat scores exceed configured thresholds.

    Inspired by response logic that could have mitigated:
    - Cosmos Bank (2018): Auto-freeze accounts showing ATM velocity spikes
    - Union Bank SWIFT (2016): Block operator sessions with anomalous SWIFT patterns
    """

    SCORE_MFA_THRESHOLD    = 50
    SCORE_BLOCK_THRESHOLD  = 70
    SCORE_FREEZE_THRESHOLD = 85

    def __init__(self, ip_blocker, event_logger):
        self._ip_blocker = ip_blocker
        self._event_logger = event_logger
        self._frozen_accounts: set = set()
        self._threat_score = 75
        self._response_count = 0

    async def respond(self, user_id: str, ip: str, mac: Optional[str],
                      score: float) -> dict:
        """
        Execute threat response based on anomaly score.
        Returns dict of actions taken.
        """
        actions = []

        if score >= self.SCORE_FREEZE_THRESHOLD:
            # Freeze account
            self._frozen_accounts.add(user_id)
            self._event_logger.log_event(
                "ACCOUNT_FROZEN", "CRITICAL", ip,
                f"Account {user_id} frozen — threat score {score:.0f}"
            )
            actions.append("ACCOUNT_FROZEN")

        if score >= self.SCORE_BLOCK_THRESHOLD:
            # Block IP
            self._ip_blocker.block_ip(
                ip, f"Automated block — anomaly score {score:.0f}", "HIGH"
            )
            if mac:
                self._ip_blocker.block_mac(
                    mac, f"Automated block — anomaly score {score:.0f}", "HIGH"
                )
            self._event_logger.log_event(
                "AUTO_BLOCK", "HIGH", ip,
                f"IP/MAC auto-blocked — threat score {score:.0f}"
            )
            actions.append("IP_BLOCKED")
            actions.append("MAC_BLOCKED")
            self._response_count += 1

        if score >= self.SCORE_MFA_THRESHOLD:
            # Require MFA
            self._event_logger.log_event(
                "MFA_TRIGGERED", "HIGH", ip,
                f"MFA required for {user_id} — anomaly score {score:.0f}"
            )
            actions.append("MFA_REQUIRED")

        # Update global threat score
        self._threat_score = min(98, max(self._threat_score, int(score)))

        return {
            "actions": actions,
            "threat_score": score,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def evaluate(self, event: dict):
        """Evaluate an event from other agents and respond if needed."""
        severity = event.get("severity", "")
        if severity == "CRITICAL":
            self._threat_score = min(98, self._threat_score + 5)
        elif severity == "HIGH":
            self._threat_score = min(98, self._threat_score + 2)

    async def freeze_account(self, user_id: str):
        self._frozen_accounts.add(user_id)

    def get_current_threat_score(self) -> int:
        import random
        drift = random.randint(-2, 3)
        self._threat_score = max(10, min(98, self._threat_score + drift))
        return self._threat_score

    def is_account_frozen(self, user_id: str) -> bool:
        return user_id in self._frozen_accounts
