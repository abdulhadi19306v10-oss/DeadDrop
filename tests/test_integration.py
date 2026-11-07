"""End-to-End Integration Tests for DeadDrop."""

import hashlib
import io
import os
import secrets
import tempfile
from pathlib import Path
import pytest
import pytest_asyncio
import pyotp
from httpx import ASGITransport, AsyncClient

from deaddrop.client.api import DeadDropClient
from deaddrop.client.crypto_core import (
    CryptoIntegrityError,
    decrypt_file,
    derive_kek,
    derive_wk,
    encrypt_file,
    format_drop_code,
    generate_file_key,
    generate_link_secret,
    generate_salt,
    parse_drop_code,
    unwrap_fk,
    wrap_fk,
)
from deaddrop.server.database import init_db
from deaddrop.server.main import app


@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    await init_db()


@pytest.mark.asyncio
async def test_end_to_end_exchange(tmp_path):
    """Simulates a full real-world file exchange between Sender and Recipient."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        # Step 1: Sender prepares file
        original_file = tmp_path / "research_paper.pdf"
        # 128 KiB of pseudo-random bytes
        data = os.urandom(128 * 1024)
        original_file.write_bytes(data)
        original_hash = hashlib.sha256(data).hexdigest()

        # Step 2: Sender registers drop on relay
        res = await http_client.post("/drops", json={"max_downloads": 1, "expires_hours": 24})
        assert res.status_code == 200
        drop_data = res.json()
        drop_id = drop_data["drop_id"]
        ss_bytes = bytes.fromhex(drop_data["ss_hex"])
        totp_secret = drop_data["totp_secret"]

        # Step 3: Sender performs local crypto
        password = "ExamPassword#2026!"
        salt = generate_salt()
        ls = generate_link_secret()
        fk = generate_file_key()

        kek = derive_kek(password, salt)
        wk = derive_wk(kek, ss_bytes, ls, drop_id)
        wrapped_fk = wrap_fk(wk, fk, drop_id)

        blob_stream = io.BytesIO()
        encrypt_file(original_file, blob_stream, fk, drop_id, chunk_size=32 * 1024)
        blob_bytes = blob_stream.getvalue()

        # Step 4: Sender uploads and finalizes
        upload_res = await http_client.put(f"/drops/{drop_id}/blob", content=blob_bytes)
        assert upload_res.status_code == 200

        fin_res = await http_client.post(
            f"/drops/{drop_id}/finalize",
            json={"salt_hex": salt.hex(), "wrapped_fk_hex": wrapped_fk.hex()},
        )
        assert fin_res.status_code == 200

        drop_code = format_drop_code(drop_id, ls)

        # Step 5: Recipient receives drop_code, password, and TOTP
        rec_drop_id, rec_ls = parse_drop_code(drop_code)
        assert rec_drop_id == drop_id
        assert rec_ls == ls

        totp = pyotp.TOTP(totp_secret)
        recipient_totp = totp.now()

        # Step 6: Recipient unlocks drop
        unlock_res = await http_client.post(
            f"/drops/{drop_id}/unlock",
            json={"totp_code": recipient_totp},
        )
        assert unlock_res.status_code == 200
        unlock_data = unlock_res.json()
        rec_ss = bytes.fromhex(unlock_data["ss_hex"])
        rec_salt = bytes.fromhex(unlock_data["salt_hex"])
        rec_wrapped_fk = bytes.fromhex(unlock_data["wrapped_fk_hex"])
        dl_token = unlock_data["download_token"]

        # Step 7: Recipient unwrap keys locally
        rec_kek = derive_kek(password, rec_salt)
        rec_wk = derive_wk(rec_kek, rec_ss, rec_ls, rec_drop_id)
        rec_fk = unwrap_fk(rec_wk, rec_wrapped_fk, rec_drop_id)
        assert rec_fk == fk

        # Step 8: Recipient downloads and decrypts
        dl_res = await http_client.get(f"/drops/{drop_id}/blob", params={"token": dl_token})
        assert dl_res.status_code == 200
        downloaded_blob = dl_res.content

        restored_file = tmp_path / "restored_paper.pdf"
        dl_stream = io.BytesIO(downloaded_blob)
        meta = decrypt_file(dl_stream, restored_file, rec_fk, rec_drop_id)

        assert meta["name"] == "research_paper.pdf"
        assert meta["size"] == len(data)
        restored_bytes = restored_file.read_bytes()
        assert hashlib.sha256(restored_bytes).hexdigest() == original_hash

        # Step 9: Verify Burn-After-Read (drop is destroyed after 1 download)
        dl_again = await http_client.get(f"/drops/{drop_id}/blob", params={"token": dl_token})
        assert dl_again.status_code in (403, 404)
