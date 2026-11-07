"""Drop management, streaming blob upload/download, unlock, and audit routes."""

import os
import secrets
import time
from pathlib import Path
from typing import List, Optional
import aiosqlite
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, StreamingResponse

from deaddrop.server.audit import get_audit_trail, log_audit
from deaddrop.server.config import (
    BASE_LOCKOUT_SECONDS,
    BLOB_STORAGE_DIR,
    DOWNLOAD_TOKEN_TTL,
    MAX_BLOB_SIZE,
    MAX_FAILED_ATTEMPTS,
)
from deaddrop.server.crypto_server import (
    constant_time_compare,
    decrypt_at_rest,
    encrypt_at_rest,
    hash_backup_code,
)
from deaddrop.server.database import get_db
from deaddrop.server.models import (
    AuditEntry,
    CreateDropRequest,
    CreateDropResponse,
    DropItem,
    FinalizeDropRequest,
    UnlockDropRequest,
    UnlockDropResponse,
)
from deaddrop.server.ratelimit import check_lockout, record_failed_attempt
from deaddrop.server.routes.auth import get_current_user_optional
from deaddrop.server.totp import (
    generate_backup_codes,
    generate_totp_secret,
    get_provisioning_uri,
    verify_totp,
)

router = APIRouter(prefix="/drops", tags=["drops"])

GENERIC_UNAVAILABLE_MSG = "Drop unavailable or invalid verification."


def _get_client_ip(request: Request) -> str:
    """Extracts client IP address safely from request headers or socket."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def _shred_file(filepath: Path) -> None:
    """Overwrites file with zeroes before unlinking to prevent disk recovery."""
    if filepath.exists() and filepath.is_file():
        try:
            size = filepath.stat().st_size
            with open(filepath, "wb") as f:
                f.write(b"\x00" * min(size, 4096))
            filepath.unlink()
        except OSError:
            pass


@router.post("", response_model=CreateDropResponse)
async def create_drop(
    req: CreateDropRequest,
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Step 1: Creates drop record on relay.

    Generates Server Share (SS), TOTP secret, backup codes.
    Returns drop_id, SS, TOTP enrollment URI, and backup codes to sender.
    """
    owner_id = user_id if user_id else None
    drop_id = secrets.token_hex(16)
    client_ip = _get_client_ip(request)

    # 1. Generate 256-bit Server Share (SS)
    ss_bytes = secrets.token_bytes(32)
    ss_enc = encrypt_at_rest(ss_bytes, aad=drop_id.encode("utf-8"))

    # 2. Generate per-drop TOTP Secret
    totp_secret = generate_totp_secret()
    totp_enc = encrypt_at_rest(totp_secret.encode("utf-8"), aad=drop_id.encode("utf-8"))

    # 3. Generate backup codes
    backup_codes = generate_backup_codes(5)

    # 4. Storage paths and policies
    blob_path = str(BLOB_STORAGE_DIR / f"{drop_id}.ddrp")
    now = int(time.time())
    expires_at = now + (req.expires_hours * 3600)

    # Insert drop record
    await db.execute(
        """
        INSERT INTO drops (
            id, owner_id, blob_path, blob_size, salt, wrapped_fk,
            ss_enc, totp_enc, totp_last_step, max_downloads, downloads,
            expires_at, failed_attempts, locked_until, status, created_at
        )
        VALUES (?, ?, ?, 0, NULL, NULL, ?, ?, 0, ?, 0, ?, 0, 0, 'pending', ?)
        """,
        (drop_id, owner_id, blob_path, ss_enc, totp_enc, req.max_downloads, expires_at, now),
    )

    # Insert salted hashes of backup codes
    for code in backup_codes:
        c_hash = hash_backup_code(code)
        await db.execute(
            "INSERT INTO backup_codes (drop_id, code_hash, used) VALUES (?, ?, 0)",
            (drop_id, c_hash),
        )

    await db.commit()
    await log_audit(db, drop_id, "DROP_CREATE", "SUCCESS", client_ip)

    totp_uri = get_provisioning_uri(totp_secret, drop_id)
    return CreateDropResponse(
        drop_id=drop_id,
        ss_hex=ss_bytes.hex(),
        totp_secret=totp_secret,
        totp_uri=totp_uri,
        backup_codes=backup_codes,
        expires_at=expires_at,
    )


@router.put("/{drop_id}/blob")
async def upload_blob(
    drop_id: str,
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Step 2: Stream encrypted ciphertext blob to relay."""
    client_ip = _get_client_ip(request)
    async with db.execute("SELECT id, blob_path, status, expires_at FROM drops WHERE id = ?", (drop_id,)) as cur:
        drop = await cur.fetchone()

    now = int(time.time())
    if not drop or drop["status"] != "pending" or drop["expires_at"] <= now:
        await log_audit(db, drop_id, "BLOB_UPLOAD", "FAILED_INVALID_DROP", client_ip)
        raise HTTPException(status_code=400, detail=GENERIC_UNAVAILABLE_MSG)

    blob_path = Path(drop["blob_path"])
    total_written = 0

    try:
        with open(blob_path, "wb") as f_out:
            async for chunk in request.stream():
                total_written += len(chunk)
                if total_written > MAX_BLOB_SIZE:
                    raise HTTPException(status_code=413, detail="Ciphertext blob exceeds max allowed size.")
                f_out.write(chunk)

        await db.execute(
            "UPDATE drops SET blob_size = ?, status = 'uploaded' WHERE id = ?",
            (total_written, drop_id),
        )
        await db.commit()
        await log_audit(db, drop_id, "BLOB_UPLOAD", f"SUCCESS_{total_written}B", client_ip)
        return {"status": "uploaded", "blob_size": total_written}

    except Exception:
        _shred_file(blob_path)
        raise


@router.post("/{drop_id}/finalize")
async def finalize_drop(
    drop_id: str,
    req: FinalizeDropRequest,
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Step 3: Stores salt and WrappedFK, activates the drop."""
    client_ip = _get_client_ip(request)
    async with db.execute("SELECT id, status, expires_at FROM drops WHERE id = ?", (drop_id,)) as cur:
        drop = await cur.fetchone()

    now = int(time.time())
    if not drop or drop["status"] != "uploaded" or drop["expires_at"] <= now:
        await log_audit(db, drop_id, "DROP_FINALIZE", "FAILED_INVALID_STATUS", client_ip)
        raise HTTPException(status_code=400, detail=GENERIC_UNAVAILABLE_MSG)

    try:
        salt_bytes = bytes.fromhex(req.salt_hex)
        wrapped_fk_bytes = bytes.fromhex(req.wrapped_fk_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hexadecimal formatting.")

    await db.execute(
        "UPDATE drops SET salt = ?, wrapped_fk = ?, status = 'active' WHERE id = ?",
        (salt_bytes, wrapped_fk_bytes, drop_id),
    )
    await db.commit()
    await log_audit(db, drop_id, "DROP_FINALIZE", "SUCCESS_ACTIVE", client_ip)
    return {"status": "active"}


@router.post("/{drop_id}/unlock", response_model=UnlockDropResponse)
async def unlock_drop(
    drop_id: str,
    req: UnlockDropRequest,
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Step 4: Recipient verifies 2FA (TOTP or single-use backup code).

    Enforces:
    - Lockout checks (5 failed attempts -> 15 min lock)
    - Replay guard (totp_last_step)
    - Expiration & max download limits
    Releases:
    - SS (Server Share), salt, WrappedFK, and 60-second download token.
    """
    client_ip = _get_client_ip(request)
    now = int(time.time())

    async with db.execute(
        """
        SELECT id, salt, wrapped_fk, ss_enc, totp_enc, totp_last_step,
               max_downloads, downloads, expires_at, failed_attempts,
               locked_until, status
        FROM drops
        WHERE id = ?
        """,
        (drop_id,),
    ) as cur:
        drop = await cur.fetchone()

    # Generic rejection if nonexistent, inactive, or expired
    if not drop or drop["status"] != "active" or drop["expires_at"] <= now or drop["downloads"] >= drop["max_downloads"]:
        await log_audit(db, drop_id, "UNLOCK_ATTEMPT", "REJECTED_UNAVAILABLE", client_ip)
        raise HTTPException(status_code=400, detail=GENERIC_UNAVAILABLE_MSG)

    # 1. Check Lockout Status
    is_locked, remaining_lock = check_lockout(drop["locked_until"], now)
    if is_locked:
        await log_audit(db, drop_id, "UNLOCK_ATTEMPT", f"REJECTED_LOCKED_{remaining_lock}S", client_ip)
        raise HTTPException(
            status_code=429,
            detail=f"Drop is locked due to repeated failed attempts. Try again in {remaining_lock} seconds.",
        )

    authenticated = False
    new_totp_step = drop["totp_last_step"]

    # 2. Authenticate via TOTP
    if req.totp_code:
        totp_secret = decrypt_at_rest(drop["totp_enc"], aad=drop_id.encode("utf-8")).decode("utf-8")
        is_valid, step_used, msg = verify_totp(totp_secret, req.totp_code, drop["totp_last_step"], now)
        if is_valid:
            authenticated = True
            new_totp_step = step_used
        else:
            auth_fail_reason = msg

    # 3. Authenticate via Backup Code (if TOTP not passed)
    elif req.backup_code:
        target_hash = hash_backup_code(req.backup_code)
        async with db.execute(
            "SELECT code_hash FROM backup_codes WHERE drop_id = ? AND code_hash = ? AND used = 0",
            (drop_id, target_hash),
        ) as cur:
            row = await cur.fetchone()

        if row:
            authenticated = True
            # Invalidate backup code immediately
            await db.execute(
                "UPDATE backup_codes SET used = 1 WHERE drop_id = ? AND code_hash = ?",
                (drop_id, target_hash),
            )
        else:
            auth_fail_reason = "Invalid or already used backup code."
    else:
        auth_fail_reason = "No 2FA credentials provided."

    # Handle Failed Authentication
    if not authenticated:
        new_failed, new_locked_until, duration = record_failed_attempt(drop["failed_attempts"], now)
        await db.execute(
            "UPDATE drops SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (new_failed, new_locked_until, drop_id),
        )
        await db.commit()
        await log_audit(db, drop_id, "UNLOCK_ATTEMPT", f"FAILED_ATTEMPT_{new_failed}", client_ip)

        if new_locked_until > now:
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed attempts. Drop is now locked for {duration // 60} minutes.",
            )
        raise HTTPException(status_code=400, detail=GENERIC_UNAVAILABLE_MSG)

    # Authentication Succeeded: Reset failed attempts, update totp_last_step
    download_token = secrets.token_urlsafe(32)
    token_expiry = now + DOWNLOAD_TOKEN_TTL

    await db.execute(
        """
        UPDATE drops
        SET failed_attempts = 0, locked_until = 0, totp_last_step = ?
        WHERE id = ?
        """,
        (new_totp_step, drop_id),
    )
    await db.execute(
        "INSERT INTO download_tokens (token, drop_id, expires_at) VALUES (?, ?, ?)",
        (download_token, drop_id, token_expiry),
    )
    await db.commit()
    await log_audit(db, drop_id, "UNLOCK_SUCCESS", "TOKEN_ISSUED", client_ip)

    # Decrypt server share
    ss_bytes = decrypt_at_rest(drop["ss_enc"], aad=drop_id.encode("utf-8"))

    return UnlockDropResponse(
        ss_hex=ss_bytes.hex(),
        salt_hex=drop["salt"].hex(),
        wrapped_fk_hex=drop["wrapped_fk"].hex(),
        download_token=download_token,
    )


@router.get("/{drop_id}/blob")
async def download_blob(
    drop_id: str,
    token: str = Query(...),
    request: Request = None,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Step 5: Streams ciphertext blob using short-lived download token."""
    client_ip = _get_client_ip(request) if request else "127.0.0.1"
    now = int(time.time())

    # Validate and burn single-use download token
    async with db.execute(
        "SELECT token, expires_at FROM download_tokens WHERE token = ? AND drop_id = ?",
        (token, drop_id),
    ) as cur:
        tok_row = await cur.fetchone()

    if not tok_row or tok_row["expires_at"] <= now:
        await log_audit(db, drop_id, "BLOB_DOWNLOAD", "REJECTED_EXPIRED_TOKEN", client_ip)
        raise HTTPException(status_code=403, detail="Download token expired or invalid.")

    # Delete token (single-use)
    await db.execute("DELETE FROM download_tokens WHERE token = ?", (token,))

    async with db.execute(
        "SELECT id, blob_path, downloads, max_downloads, status FROM drops WHERE id = ?",
        (drop_id,),
    ) as cur:
        drop = await cur.fetchone()

    if not drop or not Path(drop["blob_path"]).exists():
        raise HTTPException(status_code=404, detail=GENERIC_UNAVAILABLE_MSG)

    new_downloads = drop["downloads"] + 1
    blob_path = Path(drop["blob_path"])

    # If limit reached, mark burned / completed
    if new_downloads >= drop["max_downloads"]:
        await db.execute("UPDATE drops SET downloads = ?, status = 'burned' WHERE id = ?", (new_downloads, drop_id))
        await db.commit()
        await log_audit(db, drop_id, "BLOB_DOWNLOAD", f"SUCCESS_FINAL_BURNED_{new_downloads}/{drop['max_downloads']}", client_ip)
    else:
        await db.execute("UPDATE drops SET downloads = ? WHERE id = ?", (new_downloads, drop_id))
        await db.commit()
        await log_audit(db, drop_id, "BLOB_DOWNLOAD", f"SUCCESS_{new_downloads}/{drop['max_downloads']}", client_ip)

    return FileResponse(
        path=str(blob_path),
        media_type="application/octet-stream",
        filename=f"{drop_id}.ddrp",
    )


@router.delete("/{drop_id}")
async def burn_drop(
    drop_id: str,
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Manual Burn: Securely shreds ciphertext blob and marks drop as burned."""
    client_ip = _get_client_ip(request)
    async with db.execute("SELECT id, blob_path, owner_id FROM drops WHERE id = ?", (drop_id,)) as cur:
        drop = await cur.fetchone()

    if not drop:
        raise HTTPException(status_code=404, detail=GENERIC_UNAVAILABLE_MSG)

    # If drop belongs to registered owner, verify user_id
    if drop["owner_id"] and drop["owner_id"] != "anonymous_sender":
        if user_id != drop["owner_id"]:
            raise HTTPException(status_code=403, detail="Forbidden.")

    blob_path = Path(drop["blob_path"])
    _shred_file(blob_path)

    await db.execute(
        "UPDATE drops SET status = 'burned', ss_enc = X'00', salt = NULL, wrapped_fk = NULL WHERE id = ?",
        (drop_id,),
    )
    await db.commit()
    await log_audit(db, drop_id, "DROP_BURN", "MANUAL_SHRED_SUCCESS", client_ip)
    return {"status": "burned"}


@router.get("", response_model=List[DropItem])
async def list_drops(
    db: aiosqlite.Connection = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Lists drops created by the current user session (or anonymous drops if unauthenticated)."""
    if user_id:
        query = "SELECT id, status, blob_size, max_downloads, downloads, expires_at, created_at FROM drops WHERE owner_id = ? ORDER BY created_at DESC"
        params = (user_id,)
    else:
        query = "SELECT id, status, blob_size, max_downloads, downloads, expires_at, created_at FROM drops WHERE owner_id IS NULL ORDER BY created_at DESC"
        params = ()

    async with db.execute(query, params) as cur:
        rows = await cur.fetchall()
        return [
            DropItem(
                id=row["id"],
                status=row["status"],
                blob_size=row["blob_size"] or 0,
                max_downloads=row["max_downloads"],
                downloads=row["downloads"],
                expires_at=row["expires_at"],
                created_at=row["created_at"],
            )
            for row in rows
        ]


@router.get("/{drop_id}/audit", response_model=List[AuditEntry])
async def get_drop_audit(
    drop_id: str,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Retrieves immutable audit timeline for a drop."""
    trail = await get_audit_trail(db, drop_id)
    return [
        AuditEntry(
            timestamp=entry["timestamp"],
            event=entry["event"],
            outcome=entry["outcome"],
            ip_hash=entry["ip_hash"],
        )
        for entry in trail
    ]
