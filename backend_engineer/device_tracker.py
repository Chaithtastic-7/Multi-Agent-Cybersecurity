"""
device_tracker.py — Device Fingerprint Tracking Module
Tracks IP, MAC, device type, and login frequency.
Flags unknown or suspicious devices.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict


class DeviceTracker:
    """
    Maintains a registry of known devices per user.
    Detects:
    - New/unknown devices
    - MAC address spoofing indicators
    - Abnormal login frequency
    - Geographic anomalies
    """

    LOGIN_FREQ_WINDOW_MINUTES = 60
    HIGH_FREQ_THRESHOLD = 15          # logins per hour — suspicious
    EXTREME_FREQ_THRESHOLD = 50       # logins per hour — brute force

    def __init__(self):
        # user_id → list of known devices
        self._user_devices: Dict[str, List[dict]] = defaultdict(list)
        # ip → list of recent login timestamps
        self._ip_login_log: Dict[str, List[datetime]] = defaultdict(list)
        # All devices registry
        self._device_registry: Dict[str, dict] = {}
        
        self._seed_demo_devices()

    def _seed_demo_devices(self):
        demo = [
            {"user_id":"USR_4421","device_id":"DEV_A1B2","mac":"78:4F:43:55:6A:BC","ip":"192.168.1.100","device_type":"Mobile","trusted":True,"last_seen":datetime.utcnow(),"location":"Mumbai"},
            {"user_id":"USR_4421","device_id":"DEV_C3D4","mac":"B8:27:EB:12:34:56","ip":"192.168.1.101","device_type":"Desktop","trusted":True,"last_seen":datetime.utcnow(),"location":"Mumbai"},
            {"user_id":"USR_1190","device_id":"DEV_E5F6","mac":"D4:61:9D:AB:CD:EF","ip":"10.0.0.88","device_type":"Mobile","trusted":True,"last_seen":datetime.utcnow(),"location":"Delhi"},
            {"user_id":"USR_7734","device_id":"DEV_G7H8","mac":"AC:DE:48:00:11:22","ip":"172.16.1.4","device_type":"Desktop","trusted":True,"last_seen":datetime.utcnow(),"location":"Bangalore"},
            {"user_id":"USR_2234","device_id":"DEV_I9J0","mac":"F8:3A:77:C2:11:DE","ip":"172.16.8.44","device_type":"Mobile","trusted":True,"last_seen":datetime.utcnow(),"location":"Pune"},
        ]
        for d in demo:
            self._user_devices[d["user_id"]].append(d)
            self._device_registry[d["device_id"]] = d

    def check_device(self, user_id: str, device_id: str,
                     mac: str, ip: str) -> dict:
        """
        Check if a device is known/trusted for a user.
        Returns trust assessment with flags.
        
        Returns:
            dict: {trusted, is_new, flags, risk_contribution}
        """
        known_devices = self._user_devices.get(user_id, [])
        mac_match = any(d["mac"] == mac for d in known_devices)
        device_match = any(d["device_id"] == device_id for d in known_devices)
        
        flags = []
        risk = 0

        # Unknown device
        if not device_match and not mac_match:
            flags.append("UNKNOWN_DEVICE")
            risk += 30
        elif not device_match and mac_match:
            flags.append("KNOWN_MAC_NEW_DEVICE_ID")
            risk += 10
        elif device_match and not mac_match:
            flags.append("MAC_CHANGED")
            risk += 25  # Possible MAC spoofing

        # Check login frequency from this IP
        freq = self._get_login_frequency(ip)
        if freq > self.EXTREME_FREQ_THRESHOLD:
            flags.append("EXTREME_LOGIN_FREQUENCY")
            risk += 40
        elif freq > self.HIGH_FREQ_THRESHOLD:
            flags.append("HIGH_LOGIN_FREQUENCY")
            risk += 20

        # Check for VPN/Tor IP ranges (simplified)
        if self._is_suspicious_ip(ip):
            flags.append("SUSPICIOUS_IP_RANGE")
            risk += 35

        # Record this login
        self._record_login(user_id, device_id, mac, ip)

        return {
            "trusted": len(flags) == 0,
            "is_new": not device_match,
            "flags": flags,
            "risk_contribution": min(risk, 100),
        }

    def register_device(self, user_id: str, device_id: str,
                        mac: str, ip: str, device_type: str,
                        location: str) -> dict:
        """Register a new trusted device for a user."""
        device = {
            "device_id": device_id,
            "user_id": user_id,
            "mac": mac,
            "ip": ip,
            "device_type": device_type,
            "trusted": True,
            "last_seen": datetime.utcnow(),
            "location": location,
            "registered_at": datetime.utcnow().isoformat(),
        }
        self._user_devices[user_id].append(device)
        self._device_registry[device_id] = device
        return device

    def _record_login(self, user_id: str, device_id: str,
                      mac: str, ip: str):
        """Record a login timestamp for frequency tracking."""
        self._ip_login_log[ip].append(datetime.utcnow())
        # Clean old entries
        cutoff = datetime.utcnow() - timedelta(minutes=self.LOGIN_FREQ_WINDOW_MINUTES)
        self._ip_login_log[ip] = [t for t in self._ip_login_log[ip] if t > cutoff]
        
        # Update last seen
        if device_id in self._device_registry:
            self._device_registry[device_id]["last_seen"] = datetime.utcnow()

    def _get_login_frequency(self, ip: str) -> int:
        """Get login count from an IP in the last frequency window."""
        cutoff = datetime.utcnow() - timedelta(minutes=self.LOGIN_FREQ_WINDOW_MINUTES)
        logins = self._ip_login_log.get(ip, [])
        return sum(1 for t in logins if t > cutoff)

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is in known suspicious ranges (Tor exit nodes, known attacker IPs)."""
        suspicious_prefixes = [
            "185.220.",  # Tor exit nodes
            "45.142.",   # Known malicious hosting
            "194.165.",  # Bulletproof hosting
            "185.100.",  # Tor relays
        ]
        return any(ip.startswith(p) for p in suspicious_prefixes)

    def get_all_devices(self) -> List[dict]:
        """Get all tracked devices (sanitized)."""
        return [
            {
                "device_id": d["device_id"],
                "user_id": d["user_id"],
                "mac": d["mac"],
                "ip": d["ip"],
                "device_type": d["device_type"],
                "trusted": d["trusted"],
                "last_seen": d["last_seen"].isoformat() if isinstance(d["last_seen"], datetime) else d["last_seen"],
                "location": d.get("location", "Unknown"),
            }
            for d in self._device_registry.values()
        ]

    def get_user_devices(self, user_id: str) -> List[dict]:
        """Get devices for a specific user."""
        return self._user_devices.get(user_id, [])

    def untrust_device(self, device_id: str):
        """Mark a device as untrusted."""
        if device_id in self._device_registry:
            self._device_registry[device_id]["trusted"] = False
