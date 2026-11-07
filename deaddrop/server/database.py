"""Database connection and schema initialization using aiosqlite."""

import aiosqlite
from pathlib import Path
from typing import AsyncGenerator
from deaddrop.server.config import DB_PATH


INIT_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  totp_enc BLOB NOT NULL,
  totp_last_step INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS drops (
  id TEXT PRIMARY KEY,
  owner_id TEXT REFERENCES users(id),
  blob_path TEXT NOT NULL,
  blob_size INTEGER,
  salt BLOB,
  wrapped_fk BLOB,
  ss_enc BLOB NOT NULL,
  totp_enc BLOB NOT NULL,
  totp_last_step INTEGER DEFAULT 0,
  max_downloads INTEGER NOT NULL DEFAULT 1,
  downloads INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_codes (
  drop_id TEXT REFERENCES drops(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  drop_hash TEXT,
  event TEXT NOT NULL,
  outcome TEXT NOT NULL,
  ip_hash TEXT
);

CREATE TABLE IF NOT EXISTS download_tokens (
  token TEXT PRIMARY KEY,
  drop_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
"""


async def init_db() -> None:
    """Initializes SQLite database tables and foreign keys."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(INIT_SQL)
        await db.commit()


async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Dependency for obtaining an async database connection."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA foreign_keys = ON;")
        yield db
