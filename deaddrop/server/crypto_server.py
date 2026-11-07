"""Server-side encryption and hashing for secrets at rest."""

import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from deaddrop.server.config import MASTER_KEY, IP_SALT


def encrypt_at_rest(data: bytes, aad: bytes = b"") -> bytes:
    """Encrypts sensitive fields (SS, TOTP secret) before storing in the database.

    Uses AES-256-GCM with MASTER_KEY.
    Format: 12-byte IV + ciphertext + 16-byte tag.
    """
    iv = secrets.token_bytes(12)
    aesgcm = AESGCM(MASTER_KEY)
    ct = aesgcm.encrypt(iv, data, aad)
    return iv + ct


def decrypt_at_rest(blob: bytes, aad: bytes = b"") -> bytes:
    """Decrypts sensitive fields at rest using MASTER_KEY."""
    if len(blob) < 28:
        raise ValueError("Encrypted blob too short.")
    iv = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(MASTER_KEY)
    return aesgcm.decrypt(iv, ct, aad)


def hash_drop_id(drop_id: str) -> str:
    """Returns SHA-256 hash of drop_id for anonymized audit log entries."""
    return hashlib.sha256(drop_id.encode("utf-8")).hexdigest()[:32]


def hash_ip(ip: str) -> str:
    """Hashes client IP with rotating salt for privacy-preserving audit logs."""
    h = hashlib.sha256(IP_SALT + ip.encode("utf-8"))
    return h.hexdigest()[:16]


def hash_backup_code(code: str) -> str:
    """Computes SHA-256 hash of a backup code."""
    cleaned = code.strip().replace("-", "").upper()
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


def constant_time_compare(val1: str, val2: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))
