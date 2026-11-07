"""Pydantic schemas for DeadDrop API requests and responses."""

from typing import List, Optional
from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=8)


class RegisterResponse(BaseModel):
    user_id: str
    totp_secret: str
    totp_uri: str


class LoginRequest(BaseModel):
    email: str
    password: str
    totp_code: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CreateDropRequest(BaseModel):
    max_downloads: int = Field(default=1, ge=1, le=100)
    expires_hours: int = Field(default=24, ge=1, le=168)  # 1 hour to 7 days


class CreateDropResponse(BaseModel):
    drop_id: str
    ss_hex: str
    totp_secret: str
    totp_uri: str
    backup_codes: List[str]
    expires_at: int


class FinalizeDropRequest(BaseModel):
    salt_hex: str
    wrapped_fk_hex: str


class UnlockDropRequest(BaseModel):
    totp_code: Optional[str] = None
    backup_code: Optional[str] = None


class UnlockDropResponse(BaseModel):
    ss_hex: str
    salt_hex: str
    wrapped_fk_hex: str
    download_token: str


class DropItem(BaseModel):
    id: str
    status: str
    blob_size: Optional[int] = 0
    max_downloads: int
    downloads: int
    expires_at: int
    created_at: int


class AuditEntry(BaseModel):
    timestamp: int
    event: str
    outcome: str
    ip_hash: str
