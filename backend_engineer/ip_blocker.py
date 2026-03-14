"""
ip_blocker.py — IP and MAC Address Blocking Module
Manages blocklists for suspicious/malicious IPs and MAC addresses.
Supports auto-expiry, reason tracking, and CIDR range blocking.
"""

import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set


class IPBlocker:
    """
    Manages IP and MAC address blocklists with:
    - Auto-expiry (temporary blocks)
    - Permanent blocks for critical threats
    - CIDR range blocking for botnets
    - Reason and severity tracking
    """

    DEFAULT_BLOCK_HOURS = 24
    PERMANENT_SCORE_THRESHOLD = 90

    def __init__(self):
        # ip → {reason, severity, blocked_at, expires_at, block_count}
        self._blocked_ips: Dict[str, dict] = {}
        # mac → {reason, severity, blocked_at, expires_at}
        self._blocked_macs: Dict[str, dict] = {}
        # CIDR ranges
        self._blocked_ranges: List[str] = []
        # Whitelist (never block)
        self._whitelist_ips: Set[str] = {"127.0.0.1", "::1"}

        self._seed_initial_blocks()

    def _seed_initial_blocks(self):
        known_bad = [
            ("185.220.101.44", "Tor exit node — rapid fraud", "CRITICAL"),
            ("45.142.212.100", "Brute force 247 attempts",    "HIGH"),
            ("192.168.4.22",   "Anomaly score 94",            "HIGH"),
        ]
        bad_macs = [
            ("A4:B2:C8:D1:E9:F2", "Unknown device fraud pattern", "HIGH"),
            ("C0:FF:EE:BA:AD:01", "Tor/VPN device fingerprint",  "CRITICAL"),
        ]
        for ip, reason, severity in known_bad:
            self.block_ip(ip, reason, severity)
        for mac, reason, severity in bad_macs:
            self.block_mac(mac, reason, severity)

    def block_ip(self, ip: str, reason: str = "Threat detected",
                 severity: str = "HIGH",
                 duration_hours: Optional[int] = None) -> dict:
        """
        Block an IP address.
        Returns the block record.
        """
        if ip in self._whitelist_ips:
            return {"blocked": False, "reason": "IP is whitelisted"}

        hours = duration_hours or (
            0 if severity == "CRITICAL" else self.DEFAULT_BLOCK_HOURS
        )
        expires = None if hours == 0 else datetime.utcnow() + timedelta(hours=hours)

        existing = self._blocked_ips.get(ip, {})
        block_count = existing.get("block_count", 0) + 1

        record = {
            "ip": ip,
            "reason": reason,
            "severity": severity,
            "blocked_at": datetime.utcnow().isoformat(),
            "expires_at": expires.isoformat() if expires else "PERMANENT",
            "permanent": hours == 0,
            "block_count": block_count,
        }
        self._blocked_ips[ip] = record
        return record

    def block_mac(self, mac: str, reason: str = "Threat detected",
                  severity: str = "HIGH",
                  duration_hours: Optional[int] = None) -> dict:
        """Block a MAC address."""
        mac_normalized = self._normalize_mac(mac)
        hours = duration_hours or (0 if severity == "CRITICAL" else self.DEFAULT_BLOCK_HOURS)
        expires = None if hours == 0 else datetime.utcnow() + timedelta(hours=hours)

        record = {
            "mac": mac_normalized,
            "reason": reason,
            "severity": severity,
            "blocked_at": datetime.utcnow().isoformat(),
            "expires_at": expires.isoformat() if expires else "PERMANENT",
            "permanent": hours == 0,
        }
        self._blocked_macs[mac_normalized] = record
        return record

    def block_range(self, cidr: str, reason: str):
        """Block an entire CIDR range (e.g., botnet /24)."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            self._blocked_ranges.append({"cidr": cidr, "reason": reason,
                                          "blocked_at": datetime.utcnow().isoformat()})
        except ValueError:
            pass

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from blocklist."""
        if ip in self._blocked_ips:
            del self._blocked_ips[ip]
            return True
        return False

    def unblock_mac(self, mac: str) -> bool:
        """Remove a MAC from blocklist."""
        mac_norm = self._normalize_mac(mac)
        if mac_norm in self._blocked_macs:
            del self._blocked_macs[mac_norm]
            return True
        return False

    def is_blocked(self, ip: Optional[str] = None,
                   mac: Optional[str] = None) -> bool:
        """
        Check if an IP or MAC is blocked.
        Returns True if either is currently blocked.
        """
        if ip and self._is_ip_blocked(ip):
            return True
        if mac and self._is_mac_blocked(mac):
            return True
        return False

    def _is_ip_blocked(self, ip: str) -> bool:
        if ip in self._whitelist_ips:
            return False
        record = self._blocked_ips.get(ip)
        if record:
            if record["permanent"]:
                return True
            if record["expires_at"] != "PERMANENT":
                expires = datetime.fromisoformat(record["expires_at"])
                if datetime.utcnow() < expires:
                    return True
                else:
                    del self._blocked_ips[ip]  # Auto-expire

        # Check CIDR ranges
        try:
            ip_obj = ipaddress.ip_address(ip)
            for r in self._blocked_ranges:
                if ip_obj in ipaddress.ip_network(r["cidr"], strict=False):
                    return True
        except ValueError:
            pass

        return False

    def _is_mac_blocked(self, mac: str) -> bool:
        mac_norm = self._normalize_mac(mac)
        record = self._blocked_macs.get(mac_norm)
        if record:
            if record["permanent"]:
                return True
            if record["expires_at"] != "PERMANENT":
                expires = datetime.fromisoformat(record["expires_at"])
                if datetime.utcnow() < expires:
                    return True
                else:
                    del self._blocked_macs[mac_norm]
        return False

    def get_blocked_ips(self) -> List[dict]:
        """Get all currently blocked IPs (auto-removes expired)."""
        active = {}
        for ip, record in list(self._blocked_ips.items()):
            if record["permanent"] or \
               datetime.fromisoformat(record["expires_at"]) > datetime.utcnow():
                active[ip] = record
            else:
                del self._blocked_ips[ip]
        return list(active.values())

    def get_blocked_macs(self) -> List[dict]:
        """Get all currently blocked MACs."""
        active = {}
        for mac, record in list(self._blocked_macs.items()):
            if record["permanent"] or \
               datetime.fromisoformat(record["expires_at"]) > datetime.utcnow():
                active[mac] = record
            else:
                del self._blocked_macs[mac]
        return list(active.values())

    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC to uppercase colon-separated format."""
        cleaned = re.sub(r'[^0-9a-fA-F]', '', mac)
        if len(cleaned) != 12:
            return mac.upper()
        return ':'.join(cleaned[i:i+2] for i in range(0, 12, 2)).upper()

    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist (never blocked)."""
        self._whitelist_ips.add(ip)
        self.unblock_ip(ip)  # Remove if currently blocked
