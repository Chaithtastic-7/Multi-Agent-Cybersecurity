"""
encryption_module.py — AES-256 Encryption for Sensitive Data
Encrypts: biometric templates, pattern data, device fingerprints.
"""

import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class EncryptionModule:
    """
    AES-256-GCM encryption for sensitive banking security data.
    
    Encrypts:
    - Biometric authentication templates (fingerprint, facial data)
    - Pattern lock authentication sequences
    - Device fingerprint data
    
    Uses PBKDF2 key derivation with per-record salt for maximum security.
    """

    KEY_LENGTH = 32        # 256 bits
    NONCE_LENGTH = 12      # 96 bits for GCM
    SALT_LENGTH = 16       # 128 bits
    KDF_ITERATIONS = 310_000  # NIST recommended 2024

    def __init__(self, master_key: bytes = None):
        """
        Initialize with a master key.
        In production, this should come from HSM or secrets manager (e.g., AWS KMS).
        """
        self._master_key = master_key or self._derive_master_key()

    def _derive_master_key(self) -> bytes:
        """
        Derive master key from environment variable or generate.
        In production: load from HSM / AWS KMS / Azure Key Vault.
        """
        secret = os.environ.get("SOC_MASTER_SECRET", "nexus-soc-demo-secret-do-not-use-in-prod").encode()
        salt = b"nexus-soc-fixed-salt-v1"  # In production: stored in HSM
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(secret)

    def encrypt(self, plaintext: bytes | str, context: str = "") -> bytes:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt (bytes or string)
            context: Additional authenticated data (user_id, purpose, etc.)
        
        Returns:
            bytes: salt(16) + nonce(12) + ciphertext + tag(16)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Per-record salt for key diversification
        salt = os.urandom(self.SALT_LENGTH)
        nonce = os.urandom(self.NONCE_LENGTH)
        aad = context.encode('utf-8') if context else b""

        # Derive record-specific key from master + salt
        record_key = self._derive_record_key(salt)
        aesgcm = AESGCM(record_key)
        
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        
        # Output: salt || nonce || ciphertext_with_tag
        return base64.b64encode(salt + nonce + ciphertext)

    def decrypt(self, ciphertext_b64: bytes, context: str = "") -> bytes:
        """
        Decrypt AES-256-GCM encrypted data.
        
        Args:
            ciphertext_b64: Base64-encoded encrypted data
            context: Additional authenticated data (must match encryption context)
        
        Returns:
            bytes: Decrypted plaintext
        
        Raises:
            ValueError: If decryption fails (wrong key, tampered data)
        """
        try:
            raw = base64.b64decode(ciphertext_b64)
            salt = raw[:self.SALT_LENGTH]
            nonce = raw[self.SALT_LENGTH:self.SALT_LENGTH + self.NONCE_LENGTH]
            ciphertext = raw[self.SALT_LENGTH + self.NONCE_LENGTH:]
            aad = context.encode('utf-8') if context else b""

            record_key = self._derive_record_key(salt)
            aesgcm = AESGCM(record_key)
            
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise ValueError(f"Decryption failed — data may be tampered: {e}")

    def hash_biometric_template(self, template: bytes, user_id: str) -> str:
        """
        Create a secure hash of a biometric template for comparison.
        Uses HMAC-SHA256 with user_id as context.
        
        In production: templates would be encrypted with AES-256, 
        then hashed for fast comparison.
        """
        return hmac.new(
            self._master_key,
            template + user_id.encode(),
            hashlib.sha256
        ).hexdigest()

    def verify_biometric_template(self, template: bytes, user_id: str,
                                   stored_hash: str) -> bool:
        """
        Securely compare a biometric template against stored hash.
        Uses constant-time comparison to prevent timing attacks.
        """
        computed = self.hash_biometric_template(template, user_id)
        return hmac.compare_digest(computed, stored_hash)

    def encrypt_pattern(self, pattern_sequence: list, user_id: str) -> bytes:
        """
        Encrypt a pattern lock sequence.
        Pattern is converted to canonical form before encryption.
        """
        pattern_str = ",".join(str(p) for p in pattern_sequence)
        return self.encrypt(pattern_str.encode(), context=f"pattern:{user_id}")

    def encrypt_device_fingerprint(self, fingerprint: dict, device_id: str) -> bytes:
        """
        Encrypt device fingerprint data.
        Includes: browser fingerprint, hardware signatures, etc.
        """
        import json
        fp_bytes = json.dumps(fingerprint, sort_keys=True).encode()
        return self.encrypt(fp_bytes, context=f"device:{device_id}")

    def _derive_record_key(self, salt: bytes) -> bytes:
        """Derive a unique key per record using master key + salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(self._master_key)

    def generate_token(self, user_id: str, purpose: str,
                        ttl_minutes: int = 10) -> str:
        """
        Generate a time-limited HMAC token for MFA or verification.
        """
        from datetime import datetime
        timestamp = int(datetime.utcnow().timestamp() // (ttl_minutes * 60))
        message = f"{user_id}:{purpose}:{timestamp}".encode()
        token = hmac.new(self._master_key, message, hashlib.sha256).hexdigest()[:12]
        return token.upper()

    def verify_token(self, user_id: str, purpose: str,
                     token: str, ttl_minutes: int = 10) -> bool:
        """Verify an HMAC time-limited token (allows 1 window drift)."""
        for drift in [0, -1]:
            from datetime import datetime
            timestamp = int(datetime.utcnow().timestamp() // (ttl_minutes * 60)) + drift
            message = f"{user_id}:{purpose}:{timestamp}".encode()
            expected = hmac.new(self._master_key, message, hashlib.sha256).hexdigest()[:12].upper()
            if hmac.compare_digest(token.upper(), expected):
                return True
        return False
