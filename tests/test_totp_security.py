"""Tests for DeadDrop TOTP security, replay protection, and lockout defenses."""

import pytest
import pytest_asyncio
import pyotp
from httpx import ASGITransport, AsyncClient

from deaddrop.server.database import init_db
from deaddrop.server.main import app


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_totp_replay_prevention():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create drop
        c_res = await client.post("/drops", json={"max_downloads": 5, "expires_hours": 1})
        drop = c_res.json()
        drop_id = drop["drop_id"]

        # Fake finalize to make drop active
        await client.put(f"/drops/{drop_id}/blob", content=b"dummy blob data")
        await client.post(
            f"/drops/{drop_id}/finalize",
            json={"salt_hex": "00" * 16, "wrapped_fk_hex": "11" * 60},
        )

        totp = pyotp.TOTP(drop["totp_secret"])
        code = totp.now()

        # 1st attempt with code: Success
        res1 = await client.post(f"/drops/{drop_id}/unlock", json={"totp_code": code})
        assert res1.status_code == 200

        # 2nd attempt with EXACT SAME code: Replay failure!
        res2 = await client.post(f"/drops/{drop_id}/unlock", json={"totp_code": code})
        assert res2.status_code == 400


@pytest.mark.asyncio
async def test_backup_code_single_use():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        c_res = await client.post("/drops", json={"max_downloads": 5, "expires_hours": 1})
        drop = c_res.json()
        drop_id = drop["drop_id"]
        backup_code = drop["backup_codes"][0]

        # Fake finalize
        await client.put(f"/drops/{drop_id}/blob", content=b"dummy blob")
        await client.post(
            f"/drops/{drop_id}/finalize",
            json={"salt_hex": "00" * 16, "wrapped_fk_hex": "11" * 60},
        )

        # 1st attempt: Valid
        res1 = await client.post(f"/drops/{drop_id}/unlock", json={"backup_code": backup_code})
        assert res1.status_code == 200

        # 2nd attempt with same backup code: Fails
        res2 = await client.post(f"/drops/{drop_id}/unlock", json={"backup_code": backup_code})
        assert res2.status_code == 400


@pytest.mark.asyncio
async def test_lockout_after_five_failed_attempts():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        c_res = await client.post("/drops", json={"max_downloads": 5, "expires_hours": 1})
        drop = c_res.json()
        drop_id = drop["drop_id"]

        # Fake finalize
        await client.put(f"/drops/{drop_id}/blob", content=b"dummy blob")
        await client.post(
            f"/drops/{drop_id}/finalize",
            json={"salt_hex": "00" * 16, "wrapped_fk_hex": "11" * 60},
        )

        # 4 wrong attempts: return 400
        for _ in range(4):
            res = await client.post(f"/drops/{drop_id}/unlock", json={"totp_code": "000000"})
            assert res.status_code == 400

        # 5th wrong attempt: triggers 429 Lockout
        res5 = await client.post(f"/drops/{drop_id}/unlock", json={"totp_code": "000000"})
        assert res5.status_code == 429
        assert "locked" in res5.json()["detail"].lower()

        # Even with valid TOTP code now, drop remains locked
        totp = pyotp.TOTP(drop["totp_secret"])
        res_valid = await client.post(f"/drops/{drop_id}/unlock", json={"totp_code": totp.now()})
        assert res_valid.status_code == 429
