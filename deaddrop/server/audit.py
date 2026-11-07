"""Append-only audit logging engine."""

import time
from typing import Any, Dict, List, Optional
import aiosqlite
from deaddrop.server.crypto_server import hash_drop_id, hash_ip


async def log_audit(
    db: aiosqlite.Connection,
    drop_id: Optional[str],
    event: str,
    outcome: str,
    ip: str = "127.0.0.1",
) -> None:
    """Appends an immutable audit entry to the audit_log table.

    Never stores raw IPs or plain drop IDs. Uses salted hashes for privacy.
    """
    ts = int(time.time())
    drop_h = hash_drop_id(drop_id) if drop_id else None
    ip_h = hash_ip(ip)

    await db.execute(
        """
        INSERT INTO audit_log (ts, drop_hash, event, outcome, ip_hash)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ts, drop_h, event, outcome, ip_h),
    )
    await db.commit()


async def get_audit_trail(db: aiosqlite.Connection, drop_id: str) -> List[Dict[str, Any]]:
    """Retrieves audit trail entries for a specific drop."""
    drop_h = hash_drop_id(drop_id)
    async with db.execute(
        """
        SELECT ts, event, outcome, ip_hash
        FROM audit_log
        WHERE drop_hash = ?
        ORDER BY ts ASC
        """,
        (drop_h,),
    ) as cursor:
        rows = await cursor.fetchall()
        return [
            {
                "timestamp": row["ts"],
                "event": row["event"],
                "outcome": row["outcome"],
                "ip_hash": row["ip_hash"],
            }
            for row in rows
        ]
