"""
Encryption utilities for secure data handling
"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
salt = os.urandom(16)
from config.settings import Settings
from cryptography.hazmat.backends import default_backend

class EncryptionManager:
    def __init__(self):
        settings = Settings()
        self.key = self._get_or_generate_key(settings.ENCRYPTION_KEY)
        self.cipher = Fernet(self.key)

    def _get_or_generate_key(self, key_string: str) -> bytes:
        """Generate encryption key from string"""
        if not key_string or key_string == 'default-encryption-key':
            # Generate a new key if default
            return Fernet.generate_key()

        # Derive key from string using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(key_string.encode()))
        return key

    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not data:
            return ""
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt string data"""
        if not encrypted_data:
            return ""
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception:
            return ""

    def hash_data(self, data: str) -> str:
        """Create SHA-256 hash of data"""
        import hashlib
        return hashlib.sha256(data.encode()).hexdigest()

    def generate_session_token(self) -> str:
        """Generate secure session token"""
        import secrets
        return secrets.token_urlsafe(32)