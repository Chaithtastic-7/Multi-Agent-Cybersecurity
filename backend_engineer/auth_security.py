"""
auth_security.py — Authentication Security Module
Handles user auth validation, biometric verification, and behavior tracking.
"""

import bcrypt
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from collections import defaultdict

class AuthSecurityModule:
    """
    Manages user authentication with multi-method support:
    - Fingerprint biometrics
    - Facial recognition
    - Pattern lock
    - Password (bcrypt)
    
    Tracks historical auth behavior for anomaly detection.
    """

    AUTH_METHODS = {"FINGERPRINT", "FACIAL", "PATTERN", "PASSWORD"}
    
    def __init__(self):
        # In production these would be DB-backed. Here: in-memory simulation.
        self._users: Dict[str, dict] = {}
        self._auth_history: Dict[str, List[dict]] = defaultdict(list)
        self._active_sessions: Dict[str, dict] = {}
        self._failed_attempts: Dict[str, int] = defaultdict(int)
        self._lockout_until: Dict[str, datetime] = {}
        
        # Seed demo users
        self._seed_demo_users()

    def _seed_demo_users(self):
        """Seed realistic banking users for simulation."""
        demo_users = [
            {
                "user_id": "USR_4421",
                "name": "Arjun Sharma",
                "email": "arjun.sharma@nexusbank.in",
                "preferred_auth": "FINGERPRINT",
                "trusted_devices": ["DEV_A1B2", "DEV_C3D4"],
                "typical_location": "Mumbai",
                "typical_hours": (8, 22),
            },
            {
                "user_id": "USR_1190",
                "name": "Priya Mehta",
                "email": "priya.mehta@nexusbank.in",
                "preferred_auth": "FINGERPRINT",
                "trusted_devices": ["DEV_E5F6"],
                "typical_location": "Delhi",
                "typical_hours": (7, 21),
            },
            {
                "user_id": "USR_7734",
                "name": "Rahul Verma",
                "email": "rahul.verma@nexusbank.in",
                "preferred_auth": "FACIAL",
                "trusted_devices": ["DEV_G7H8"],
                "typical_location": "Bangalore",
                "typical_hours": (9, 23),
            },
            {
                "user_id": "USR_2234",
                "name": "Sneha Kapoor",
                "email": "sneha.kapoor@nexusbank.in",
                "preferred_auth": "FACIAL",
                "trusted_devices": ["DEV_I9J0"],
                "typical_location": "Pune",
                "typical_hours": (8, 20),
            },
        ]
        for u in demo_users:
            self._users[u["user_id"]] = u
            # Seed historical auth records
            for _ in range(20):
                self._auth_history[u["user_id"]].append({
                    "auth_method": u["preferred_auth"],
                    "device_id": u["trusted_devices"][0],
                    "location": u["typical_location"],
                    "timestamp": datetime.utcnow() - timedelta(days=_),
                    "success": True,
                    "anomaly_score": 5,
                })

    def hash_password(self, password: str) -> bytes:
        """Hash password using bcrypt with cost factor 12."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

    def verify_password(self, password: str, hashed: bytes) -> bool:
        """Verify a password against its bcrypt hash."""
        return bcrypt.checkpw(password.encode(), hashed)

    def verify_biometric(self, user_id: str, encrypted_template: bytes,
                          method: str) -> bool:
        """
        Verify biometric data against stored encrypted template.
        In production: compare AES-256 encrypted templates.
        Simulation: always returns True unless user not found.
        """
        if user_id not in self._users:
            return False
        # Real implementation:
        # stored = db.get_biometric_template(user_id, method)
        # return hmac.compare_digest(encrypted_template, stored)
        return True  # Simulation

    def record_attempt(self, user_id: str, auth_method: str,
                       device_id: str, ip: str, location: str,
                       anomaly_score: float, success: bool) -> dict:
        """Record an authentication attempt to history."""
        record = {
            "auth_id": str(uuid.uuid4()),
            "user_id": user_id,
            "auth_method": auth_method,
            "device_id": device_id,
            "ip": ip,
            "location": location,
            "anomaly_score": anomaly_score,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._auth_history[user_id].append(record)
        
        # Track failures for lockout
        if not success:
            self._failed_attempts[ip] += 1
            if self._failed_attempts[ip] >= 5:
                self._lockout_until[user_id] = datetime.utcnow() + timedelta(minutes=15)
        else:
            self._failed_attempts[ip] = 0  # Reset on success
        
        return record

    def get_auth_history(self, user_id: str, days: int = 30) -> List[dict]:
        """Get authentication history for a user."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        history = self._auth_history.get(user_id, [])
        return [h for h in history if isinstance(h.get("timestamp"), str)
                or h.get("timestamp", datetime.min) > cutoff]

    def get_preferred_method(self, user_id: str) -> Optional[str]:
        """Get the most frequently used auth method for a user."""
        history = self._auth_history.get(user_id, [])
        if not history:
            return None
        from collections import Counter
        methods = [h["auth_method"] for h in history if h.get("success")]
        if not methods:
            return None
        return Counter(methods).most_common(1)[0][0]

    def is_locked_out(self, user_id: str) -> bool:
        """Check if a user account is locked out."""
        lockout = self._lockout_until.get(user_id)
        if lockout and datetime.utcnow() < lockout:
            return True
        return False

    def get_active_user_count(self) -> int:
        """Get count of active sessions (simulation)."""
        import random
        return 3847 + random.randint(-50, 50)

    def get_user_profile(self, user_id: str) -> Optional[dict]:
        """Get user profile (without sensitive fields)."""
        user = self._users.get(user_id)
        if not user:
            return None
        return {
            "user_id": user["user_id"],
            "name": user["name"],
            "preferred_auth": user["preferred_auth"],
            "typical_location": user["typical_location"],
        }
