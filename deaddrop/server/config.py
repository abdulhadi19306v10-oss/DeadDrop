"""Server configuration and settings."""

import os
import secrets
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_BLOB_DIR = BASE_DIR / "blob_storage"
DEFAULT_DB_PATH = BASE_DIR / "deaddrop.db"

BLOB_STORAGE_DIR = Path(os.getenv("DEADDROP_BLOB_DIR", str(DEFAULT_BLOB_DIR)))
DB_PATH = Path(os.getenv("DEADDROP_DB_PATH", str(DEFAULT_DB_PATH)))

# Ensure blob storage directory exists
BLOB_STORAGE_DIR.mkdir(parents=True, exist_ok=True)

# Master key resolution (for encrypting secrets at rest in DB)
MASTER_KEY_HEX = os.getenv("DEADDROP_MASTER_KEY")
if MASTER_KEY_HEX:
    try:
        MASTER_KEY = bytes.fromhex(MASTER_KEY_HEX)
        if len(MASTER_KEY) != 32:
            raise ValueError("DEADDROP_MASTER_KEY must be exactly 32 bytes (64 hex characters).")
    except ValueError as e:
        raise RuntimeError(f"Invalid DEADDROP_MASTER_KEY: {e}")
else:
    # Persistent master key file if env var is not set
    key_file = BASE_DIR / ".master_key.bin"
    if key_file.exists():
        MASTER_KEY = key_file.read_bytes()
    else:
        MASTER_KEY = secrets.token_bytes(32)
        key_file.write_bytes(MASTER_KEY)

# JWT Secret
JWT_SECRET = os.getenv("DEADDROP_JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60 * 24  # 24 hours

# Security & Policy Settings
MAX_BLOB_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_FAILED_ATTEMPTS = 5
BASE_LOCKOUT_SECONDS = 900  # 15 minutes
DOWNLOAD_TOKEN_TTL = 60  # 60 seconds
IP_SALT = secrets.token_bytes(16)  # Daily rotating salt for IP hashing in audit log
