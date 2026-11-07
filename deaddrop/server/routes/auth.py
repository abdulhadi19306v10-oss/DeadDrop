"""Authentication routes (Registration, Login with TOTP, JWT issuance)."""

import secrets
import time
from typing import Optional
import aiosqlite
import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, status
import argon2.exceptions
import argon2.low_level
from deaddrop.server.config import JWT_ALGORITHM, JWT_EXPIRATION_MINUTES, JWT_SECRET
from deaddrop.server.crypto_server import decrypt_at_rest, encrypt_at_rest
from deaddrop.server.database import get_db
from deaddrop.server.models import LoginRequest, RegisterRequest, RegisterResponse, TokenResponse
from deaddrop.server.totp import generate_totp_secret, get_provisioning_uri, verify_totp

router = APIRouter(prefix="/auth", tags=["auth"])
pwd_hasher = argon2.PasswordHasher()


def create_access_token(user_id: str) -> str:
    """Creates a signed JWT access token."""
    expire = int(time.time()) + (JWT_EXPIRATION_MINUTES * 60)
    payload = {"sub": user_id, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user_optional(
    authorization: Optional[str] = Header(None),
    db: aiosqlite.Connection = Depends(get_db),
) -> Optional[str]:
    """Extracts user ID from Authorization Bearer token, or returns None if omitted."""
    if not authorization or not authorization.startswith("Bearer "):
        return None

    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        return user_id
    except jwt.PyJWTError:
        return None


async def require_current_user(
    authorization: Optional[str] = Header(None),
    db: aiosqlite.Connection = Depends(get_db),
) -> str:
    """Enforces valid user session token."""
    user = await get_current_user_optional(authorization, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@router.post("/register", response_model=RegisterResponse)
async def register(req: RegisterRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Registers a new sender account with password + TOTP enrollment."""
    # Check if email exists
    async with db.execute("SELECT id FROM users WHERE email = ?", (req.email,)) as cur:
        if await cur.fetchone():
            raise HTTPException(status_code=400, detail="Account with this email already exists.")

    user_id = secrets.token_hex(16)
    pw_hash = pwd_hasher.hash(req.password)
    totp_secret = generate_totp_secret()
    totp_enc = encrypt_at_rest(totp_secret.encode("utf-8"))
    created_at = int(time.time())

    await db.execute(
        """
        INSERT INTO users (id, email, pw_hash, totp_enc, totp_last_step, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
        """,
        (user_id, req.email, pw_hash, totp_enc, created_at),
    )
    await db.commit()

    totp_uri = get_provisioning_uri(totp_secret, user_id, issuer="DeadDrop-Account")
    return RegisterResponse(user_id=user_id, totp_secret=totp_secret, totp_uri=totp_uri)


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Logs in using account password + 6-digit TOTP code."""
    async with db.execute(
        "SELECT id, pw_hash, totp_enc, totp_last_step FROM users WHERE email = ?",
        (req.email,),
    ) as cur:
        user = await cur.fetchone()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    # 1. Verify Password
    try:
        pwd_hasher.verify(user["pw_hash"], req.password)
    except argon2.exceptions.VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    # 2. Verify TOTP
    totp_secret = decrypt_at_rest(user["totp_enc"]).decode("utf-8")
    is_valid, new_step, msg = verify_totp(totp_secret, req.totp_code, user["totp_last_step"])
    if not is_valid:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {msg}")

    # Update last step to prevent replay
    await db.execute(
        "UPDATE users SET totp_last_step = ? WHERE id = ?",
        (new_step, user["id"]),
    )
    await db.commit()

    token = create_access_token(user["id"])
    return TokenResponse(access_token=token)
