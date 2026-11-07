"""Tests for DeadDrop Relay Server API and Lifecycle."""

import os
import secrets
import tempfile
import pytest
import pytest_asyncio
import pyotp
from httpx import ASGITransport, AsyncClient

from deaddrop.server.database import init_db
from deaddrop.server.main import app
from deaddrop.client.crypto_core import (
    decrypt_file,
    derive_kek,
    derive_wk,
    encrypt_file,
    generate_file_key,
    generate_link_secret,
    generate_salt,
    unwrap_fk,
    wrap_fk,
)


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_health():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_auth_register_and_login():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        email = f"user_{secrets.token_hex(4)}@test.com"
        reg_res = await client.post(
            "/auth/register",
            json={"email": email, "password": "SecurePassword123!"},
        )
        assert reg_res.status_code == 200
        reg_data = reg_res.json()
        assert "totp_secret" in reg_data

        # Generate TOTP code
        totp = pyotp.TOTP(reg_data["totp_secret"])
        code = totp.now()

        login_res = await client.post(
            "/auth/login",
            json={"email": email, "password": "SecurePassword123!", "totp_code": code},
        )
        assert login_res.status_code == 200
        login_data = login_res.json()
        assert "access_token" in login_data


@pytest.mark.asyncio
async def test_full_drop_lifecycle(tmp_path):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Step 1: Create Drop
        create_res = await client.post(
            "/drops",
            json={"max_downloads": 1, "expires_hours": 24},
        )
        assert create_res.status_code == 200
        drop_data = create_res.json()
        drop_id = drop_data["drop_id"]
        ss_bytes = bytes.fromhex(drop_data["ss_hex"])
        totp_secret = drop_data["totp_secret"]

        # 2. Client side crypto setup
        password = "LabPassword2026!"
        salt = generate_salt()
        ls = generate_link_secret()
        fk = generate_file_key()
        kek = derive_kek(password, salt)
        wk = derive_wk(kek, ss_bytes, ls, drop_id)
        wrapped_fk = wrap_fk(wk, fk, drop_id)

        # Prepare payload file
        src_file = tmp_path / "original_file.txt"
        payload_content = b"Top secret exam solution information security lab"
        src_file.write_bytes(payload_content)

        # Encrypt file locally into memory buffer
        import io
        blob_buf = io.BytesIO()
        encrypt_file(src_file, blob_buf, fk, drop_id)
        blob_bytes = blob_buf.getvalue()

        # 3. Step 2: Upload Ciphertext Blob
        upload_res = await client.put(
            f"/drops/{drop_id}/blob",
            content=blob_bytes,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert upload_res.status_code == 200

        # 4. Step 3: Finalize Drop
        fin_res = await client.post(
            f"/drops/{drop_id}/finalize",
            json={
                "salt_hex": salt.hex(),
                "wrapped_fk_hex": wrapped_fk.hex(),
            },
        )
        assert fin_res.status_code == 200

        # 5. Step 4: Unlock Drop with TOTP
        totp = pyotp.TOTP(totp_secret)
        code = totp.now()

        unlock_res = await client.post(
            f"/drops/{drop_id}/unlock",
            json={"totp_code": code},
        )
        assert unlock_res.status_code == 200
        unlock_data = unlock_res.json()
        assert unlock_data["ss_hex"] == ss_bytes.hex()
        download_token = unlock_data["download_token"]

        # 6. Step 5: Download Ciphertext Blob using token
        dl_res = await client.get(
            f"/drops/{drop_id}/blob",
            params={"token": download_token},
        )
        assert dl_res.status_code == 200
        downloaded_ciphertext = dl_res.content
        assert downloaded_ciphertext == blob_bytes

        # 7. Recipient Decrypts
        rec_salt = bytes.fromhex(unlock_data["salt_hex"])
        rec_wrapped_fk = bytes.fromhex(unlock_data["wrapped_fk_hex"])
        rec_ss = bytes.fromhex(unlock_data["ss_hex"])

        rec_kek = derive_kek(password, rec_salt)
        rec_wk = derive_wk(rec_kek, rec_ss, ls, drop_id)
        rec_fk = unwrap_fk(rec_wk, rec_wrapped_fk, drop_id)
        assert rec_fk == fk

        dest_file = tmp_path / "decrypted_file.txt"
        dl_stream = io.BytesIO(downloaded_ciphertext)
        decrypt_file(dl_stream, dest_file, rec_fk, drop_id)
        assert dest_file.read_bytes() == payload_content

        # 8. Verify Burn-After-Read (max_downloads=1 reached)
        # Attempting second download with a new token or old token fails
        unlock_again = await client.post(
            f"/drops/{drop_id}/unlock",
            json={"totp_code": totp.now()},
        )
        assert unlock_again.status_code in (400, 429)
