"""Unit tests for DeadDrop crypto_core."""

import io
import os
import secrets
import tempfile
from pathlib import Path
import pytest

from deaddrop.client.crypto_core import (
    CryptoIntegrityError,
    InvalidDropCodeError,
    decrypt_bytes,
    decrypt_file,
    derive_kek,
    derive_wk,
    encrypt_bytes,
    encrypt_file,
    format_drop_code,
    generate_file_key,
    generate_link_secret,
    generate_salt,
    parse_drop_code,
    unwrap_fk,
    wrap_fk,
    zero_bytes,
)


@pytest.fixture
def keys_and_secrets():
    drop_id = secrets.token_hex(16)
    password = "SuperSecretLabPassword123!"
    salt = generate_salt()
    fk = generate_file_key()
    ss = secrets.token_bytes(32)
    ls = generate_link_secret()
    kek = derive_kek(password, salt)
    wk = derive_wk(kek, ss, ls, drop_id)
    return {
        "drop_id": drop_id,
        "password": password,
        "salt": salt,
        "fk": fk,
        "ss": ss,
        "ls": ls,
        "kek": kek,
        "wk": wk,
    }


def test_drop_code_roundtrip():
    drop_id = secrets.token_hex(16)
    ls = generate_link_secret()
    code = format_drop_code(drop_id, ls)
    assert code.startswith("DD1-")

    parsed_id, parsed_ls = parse_drop_code(code)
    assert parsed_id == drop_id
    assert parsed_ls == ls


def test_invalid_drop_code():
    with pytest.raises(InvalidDropCodeError):
        parse_drop_code("INVALID-CODE")
    with pytest.raises(InvalidDropCodeError):
        parse_drop_code("DD1-too-short")
    with pytest.raises(InvalidDropCodeError):
        parse_drop_code("DD1-12345678-nothex")


def test_wrap_unwrap_fk_success(keys_and_secrets):
    ctx = keys_and_secrets
    wrapped = wrap_fk(ctx["wk"], ctx["fk"], ctx["drop_id"])
    assert len(wrapped) == 12 + 32 + 16  # 60 bytes

    unwrapped = unwrap_fk(ctx["wk"], wrapped, ctx["drop_id"])
    assert unwrapped == ctx["fk"]


def test_unwrap_fk_fails_with_wrong_password(keys_and_secrets):
    ctx = keys_and_secrets
    wrapped = wrap_fk(ctx["wk"], ctx["fk"], ctx["drop_id"])

    # Wrong password produces wrong KEK, thus wrong WK
    wrong_kek = derive_kek("WrongPassword!", ctx["salt"])
    wrong_wk = derive_wk(wrong_kek, ctx["ss"], ctx["ls"], ctx["drop_id"])

    with pytest.raises(CryptoIntegrityError):
        unwrap_fk(wrong_wk, wrapped, ctx["drop_id"])


def test_unwrap_fk_fails_with_wrong_drop_id(keys_and_secrets):
    ctx = keys_and_secrets
    wrapped = wrap_fk(ctx["wk"], ctx["fk"], ctx["drop_id"])

    different_drop_id = secrets.token_hex(16)
    with pytest.raises(CryptoIntegrityError):
        unwrap_fk(ctx["wk"], wrapped, different_drop_id)


def test_roundtrip_empty_file(keys_and_secrets, tmp_path):
    ctx = keys_and_secrets
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    blob_stream = io.BytesIO()
    meta = encrypt_file(empty_file, blob_stream, ctx["fk"], ctx["drop_id"])
    assert meta["size"] == 0

    blob_data = blob_stream.getvalue()
    blob_stream.seek(0)

    out_file = tmp_path / "restored_empty.txt"
    dec_meta = decrypt_file(blob_stream, out_file, ctx["fk"], ctx["drop_id"])

    assert dec_meta["size"] == 0
    assert out_file.read_bytes() == b""


def test_roundtrip_small_file(keys_and_secrets, tmp_path):
    ctx = keys_and_secrets
    payload = b"Hello Kali Linux Security Lab! Zero Knowledge DeadDrop 2026."
    src_file = tmp_path / "sample.txt"
    src_file.write_bytes(payload)

    blob_stream = io.BytesIO()
    meta = encrypt_file(src_file, blob_stream, ctx["fk"], ctx["drop_id"])
    assert meta["size"] == len(payload)

    blob_stream.seek(0)
    out_file = tmp_path / "restored_sample.txt"
    decrypt_file(blob_stream, out_file, ctx["fk"], ctx["drop_id"])

    assert out_file.read_bytes() == payload


def test_roundtrip_chunk_boundary_and_multichunk(keys_and_secrets, tmp_path):
    ctx = keys_and_secrets
    # Test 64 KiB chunks with 150 KiB file (spans 3 chunks: 64 + 64 + 22 KiB)
    chunk_size = 64 * 1024
    payload = os.urandom(150 * 1024)

    src_file = tmp_path / "multichunk.bin"
    src_file.write_bytes(payload)

    blob_stream = io.BytesIO()
    encrypt_file(src_file, blob_stream, ctx["fk"], ctx["drop_id"], chunk_size=chunk_size)

    blob_stream.seek(0)
    out_file = tmp_path / "restored_multichunk.bin"
    decrypt_file(blob_stream, out_file, ctx["fk"], ctx["drop_id"])

    assert out_file.read_bytes() == payload


def test_tampered_single_bit_fails(keys_and_secrets, tmp_path):
    ctx = keys_and_secrets
    payload = b"Sensitive top secret lab intelligence data"
    src_file = tmp_path / "secret.txt"
    src_file.write_bytes(payload)

    blob_stream = io.BytesIO()
    encrypt_file(src_file, blob_stream, ctx["fk"], ctx["drop_id"])
    blob_bytes = bytearray(blob_stream.getvalue())

    # Tamper with 1 bit in the ciphertext payload (after header)
    blob_bytes[35] ^= 0x01

    tampered_stream = io.BytesIO(blob_bytes)
    out_file = tmp_path / "should_not_exist.txt"

    with pytest.raises(CryptoIntegrityError):
        decrypt_file(tampered_stream, out_file, ctx["fk"], ctx["drop_id"])

    # Verify no partial output is left behind
    assert not out_file.exists()


def test_truncated_blob_fails(keys_and_secrets, tmp_path):
    ctx = keys_and_secrets
    payload = os.urandom(100 * 1024)
    src_file = tmp_path / "large.bin"
    src_file.write_bytes(payload)

    blob_stream = io.BytesIO()
    encrypt_file(src_file, blob_stream, ctx["fk"], ctx["drop_id"], chunk_size=32 * 1024)
    blob_bytes = blob_stream.getvalue()

    # Truncate final 500 bytes
    truncated_stream = io.BytesIO(blob_bytes[:-500])
    out_file = tmp_path / "out_trunc.bin"

    with pytest.raises(CryptoIntegrityError):
        decrypt_file(truncated_stream, out_file, ctx["fk"], ctx["drop_id"])

    assert not out_file.exists()


def test_zero_bytes():
    buf = bytearray(b"SecretTransientRAMKey1234567890!")
    zero_bytes(buf)
    assert buf == bytearray(len(buf))
