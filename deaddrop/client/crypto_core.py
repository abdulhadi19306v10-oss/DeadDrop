"""DeadDrop Cryptographic Core Engine.

Implements:
- Chunked AES-256-GCM file container framing with DDRP header
- Argon2id password key derivation (KEK)
- HKDF-SHA256 multi-party wrapping key derivation (WK)
- File key wrapping and unwrapping (AES-256-GCM)
- Drop code formatting and parsing (DD1-<drop_id>-<LS>)
- Tamper, reorder, truncation, and single-bit modification rejection
"""

import json
import mimetypes
import os
import secrets
import struct
from pathlib import Path
from typing import BinaryIO, Callable, Dict, Optional, Tuple, Union

import argon2.low_level
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"DDRP"
VERSION = 1
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB chunk size
SALT_SIZE = 16  # 16 bytes for Argon2id salt
KEY_SIZE = 32  # 256 bits (AES-256)
LS_SIZE = 16  # 128 bits Link Secret
HEADER_SIZE = 18  # magic(4) + version(2) + chunk_size(4) + nonce_prefix(8)


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class CryptoIntegrityError(CryptoError):
    """Raised when authentication tag verification fails, chunk is tampered, or container is corrupt."""
    pass


class InvalidDropCodeError(CryptoError):
    """Raised when drop code format is invalid."""
    pass


def zero_bytes(buf: bytearray) -> None:
    """Overwrites a mutable bytearray with zeroes in memory."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def generate_file_key() -> bytes:
    """Generates a cryptographically secure 256-bit File Key (FK)."""
    return secrets.token_bytes(KEY_SIZE)


def generate_salt() -> bytes:
    """Generates a cryptographically secure 16-byte salt for Argon2id."""
    return secrets.token_bytes(SALT_SIZE)


def generate_link_secret() -> bytes:
    """Generates a cryptographically secure 128-bit Link Secret (LS)."""
    return secrets.token_bytes(LS_SIZE)


def derive_kek(password: str, salt: bytes) -> bytes:
    """Derives a Key Encryption Key (KEK) using Argon2id.

    Parameters:
    - Memory: 64 MiB (65536 KiB)
    - Time cost: 3 iterations
    - Parallelism: 1 thread
    - Output length: 32 bytes (256 bits)
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    return argon2.low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=KEY_SIZE,
        type=argon2.low_level.Type.ID,
    )


def derive_wk(kek: bytes, ss: bytes, ls: bytes, drop_id: str) -> bytes:
    """Derives the Wrapping Key (WK) using HKDF-SHA256.

    Combines:
    - KEK (client password-derived key)
    - SS (server-held 256-bit share, released after 2FA)
    - LS (128-bit link secret embedded in drop code)
    - info = "deaddrop-wrap-v1" + drop_id
    """
    if len(kek) != KEY_SIZE:
        raise ValueError(f"KEK must be {KEY_SIZE} bytes.")
    if len(ss) != KEY_SIZE:
        raise ValueError(f"SS must be {KEY_SIZE} bytes.")
    if len(ls) != LS_SIZE:
        raise ValueError(f"LS must be {LS_SIZE} bytes.")

    ikm = kek + ss + ls
    info = b"deaddrop-wrap-v1" + drop_id.encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=None,
        info=info,
    )
    return hkdf.derive(ikm)


def wrap_fk(wk: bytes, fk: bytes, drop_id: str) -> bytes:
    """Wraps the File Key (FK) using AES-256-GCM under WK.

    AAD binds the drop_id to prevent drop swap attacks.
    Output format: 12-byte IV + ciphertext + 16-byte tag (60 bytes total).
    """
    if len(wk) != KEY_SIZE:
        raise ValueError(f"WK must be {KEY_SIZE} bytes.")
    if len(fk) != KEY_SIZE:
        raise ValueError(f"FK must be {KEY_SIZE} bytes.")

    iv = secrets.token_bytes(12)
    aesgcm = AESGCM(wk)
    aad = drop_id.encode("utf-8")
    ct = aesgcm.encrypt(iv, fk, aad)
    return iv + ct


def unwrap_fk(wk: bytes, wrapped_fk: bytes, drop_id: str) -> bytes:
    """Unwraps the File Key (FK) using AES-256-GCM under WK.

    Raises CryptoIntegrityError if tag verification fails (e.g. wrong password,
    invalid SS/LS, or modified drop_id).
    """
    if len(wk) != KEY_SIZE:
        raise ValueError(f"WK must be {KEY_SIZE} bytes.")
    if len(wrapped_fk) < 28:  # 12 B IV + 16 B tag minimum
        raise CryptoIntegrityError("Wrapped FK data is truncated.")

    iv = wrapped_fk[:12]
    ct = wrapped_fk[12:]
    aesgcm = AESGCM(wk)
    aad = drop_id.encode("utf-8")

    try:
        fk = aesgcm.decrypt(iv, ct, aad)
        if len(fk) != KEY_SIZE:
            raise CryptoIntegrityError("Decrypted FK length mismatch.")
        return fk
    except InvalidTag as e:
        raise CryptoIntegrityError("Authentication tag failure: invalid password, keys, or corrupted drop.") from e


def format_drop_code(drop_id: str, ls: bytes) -> str:
    """Formats a user-facing drop code: DD1-<drop_id>-<ls_hex>."""
    return f"DD1-{drop_id}-{ls.hex()}"


def parse_drop_code(code: str) -> Tuple[str, bytes]:
    """Parses a user-facing drop code. Returns (drop_id, ls_bytes)."""
    cleaned = code.strip()
    parts = cleaned.split("-")
    if len(parts) != 3 or parts[0] != "DD1":
        raise InvalidDropCodeError("Invalid drop code format. Expected DD1-<drop_id>-<link_secret>.")

    drop_id = parts[1]
    ls_hex = parts[2]
    if not drop_id or len(drop_id) < 8:
        raise InvalidDropCodeError("Invalid drop ID in drop code.")

    try:
        ls_bytes = bytes.fromhex(ls_hex)
        if len(ls_bytes) != LS_SIZE:
            raise InvalidDropCodeError(f"Link secret must be {LS_SIZE} bytes ({LS_SIZE * 2} hex characters).")
        return drop_id, ls_bytes
    except ValueError as e:
        raise InvalidDropCodeError("Invalid hexadecimal in link secret.") from e


def _make_chunk_nonce(prefix: bytes, chunk_index: int) -> bytes:
    """Constructs 12-byte GCM nonce: 8-byte CSPRNG prefix || 4-byte big-endian chunk index."""
    return prefix + struct.pack(">I", chunk_index)


def _make_chunk_aad(drop_id: str, chunk_index: int, is_final: bool) -> bytes:
    """Constructs AAD binding drop_id, chunk_index, and final chunk status."""
    return drop_id.encode("utf-8") + struct.pack(">IB", chunk_index, 1 if is_final else 0)


def encrypt_file(
    source_path: Union[str, Path],
    dest_stream: BinaryIO,
    fk: bytes,
    drop_id: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Union[str, int]]:
    """Encrypts a file in 1 MiB chunks into the DDRP container format.

    Container Structure:
    - Header (18 bytes):
        magic: b"DDRP" (4 B)
        version: uint16 (2 B)
        chunk_size: uint32 (4 B)
        nonce_prefix: 8 B
    - Chunk 0: Encrypted metadata JSON {name, size, mime, created}
        uint32(length) + ciphertext_and_tag
    - Chunk 1..N: Encrypted data chunks
        uint32(length) + ciphertext_and_tag
    """
    path = Path(source_path)
    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {source_path}")

    file_size = path.stat().st_size
    mime_type, _ = mimetypes.guess_type(path.name)
    metadata = {
        "name": path.name,
        "size": file_size,
        "mime": mime_type or "application/octet-stream",
        "created": int(path.stat().st_ctime),
    }

    metadata_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    nonce_prefix = secrets.token_bytes(8)
    aesgcm = AESGCM(fk)

    # 1. Write Header
    header = struct.pack(">4sHI8s", MAGIC, VERSION, chunk_size, nonce_prefix)
    dest_stream.write(header)

    # 2. Write Chunk 0 (Metadata)
    meta_nonce = _make_chunk_nonce(nonce_prefix, 0)
    meta_is_final = (file_size == 0)
    meta_aad = _make_chunk_aad(drop_id, 0, meta_is_final)
    meta_ct = aesgcm.encrypt(meta_nonce, metadata_bytes, meta_aad)
    dest_stream.write(struct.pack(">I", len(meta_ct)))
    dest_stream.write(meta_ct)

    # 3. Stream and Encrypt File Chunks
    bytes_read_total = 0
    chunk_idx = 1

    if file_size == 0:
        if progress_callback:
            progress_callback(1, 1)
        return metadata

    with open(path, "rb") as f_in:
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break

            bytes_read_total += len(chunk)
            is_final = (bytes_read_total >= file_size)

            nonce = _make_chunk_nonce(nonce_prefix, chunk_idx)
            aad = _make_chunk_aad(drop_id, chunk_idx, is_final)
            enc_chunk = aesgcm.encrypt(nonce, chunk, aad)

            dest_stream.write(struct.pack(">I", len(enc_chunk)))
            dest_stream.write(enc_chunk)

            if progress_callback:
                progress_callback(bytes_read_total, file_size)

            chunk_idx += 1

    return metadata


def decrypt_file(
    src_stream: BinaryIO,
    dest_path: Union[str, Path],
    fk: bytes,
    drop_id: str,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Union[str, int]]:
    """Decrypts a DDRP container stream and writes plaintext to dest_path.

    Guarantees:
    - Atomicity: Plaintext is written to a temporary file first.
    - Verification: Only moved to dest_path if EVERY chunk tag passes and final chunk is reached.
    - Zero leaks on failure: On any tampering, truncation, or reordering, temp file is removed.
    """
    target_path = Path(dest_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_target = target_path.with_suffix(f"{target_path.suffix}.tmp.{secrets.token_hex(6)}")

    aesgcm = AESGCM(fk)

    try:
        # 1. Read and verify Header
        header_bytes = src_stream.read(HEADER_SIZE)
        if len(header_bytes) != HEADER_SIZE:
            raise CryptoIntegrityError("Truncated header: stream ended prematurely.")

        magic, version, chunk_size, nonce_prefix = struct.unpack(">4sHI8s", header_bytes)
        if magic != MAGIC:
            raise CryptoIntegrityError(f"Invalid magic bytes: expected {MAGIC}, got {magic}.")
        if version != VERSION:
            raise CryptoIntegrityError(f"Unsupported container version: {version}.")

        # 2. Read Chunk 0 (Metadata)
        len_buf = src_stream.read(4)
        if len(len_buf) != 4:
            raise CryptoIntegrityError("Truncated container: missing metadata chunk length.")
        (meta_len,) = struct.unpack(">I", len_buf)

        meta_ct = src_stream.read(meta_len)
        if len(meta_ct) != meta_len:
            raise CryptoIntegrityError("Truncated container: incomplete metadata payload.")

        # Attempt to decrypt metadata assuming file is not empty first
        meta_nonce = _make_chunk_nonce(nonce_prefix, 0)
        metadata = None
        try:
            meta_aad = _make_chunk_aad(drop_id, 0, is_final=False)
            meta_plain = aesgcm.decrypt(meta_nonce, meta_ct, meta_aad)
            metadata = json.loads(meta_plain.decode("utf-8"))
        except InvalidTag:
            # Check if this was a 0-byte file (is_final=True)
            try:
                meta_aad = _make_chunk_aad(drop_id, 0, is_final=True)
                meta_plain = aesgcm.decrypt(meta_nonce, meta_ct, meta_aad)
                metadata = json.loads(meta_plain.decode("utf-8"))
            except InvalidTag as e:
                raise CryptoIntegrityError("Authentication tag failure in metadata (chunk 0).") from e

        expected_size = metadata.get("size", 0)
        bytes_written = 0
        chunk_idx = 1
        reached_final = (expected_size == 0)

        with open(temp_target, "wb") as f_out:
            if expected_size > 0:
                while True:
                    len_buf = src_stream.read(4)
                    if not len_buf:
                        break  # EOF reached
                    if len(len_buf) != 4:
                        raise CryptoIntegrityError("Corrupt stream: truncated chunk length prefix.")

                    (chunk_len,) = struct.unpack(">I", len_buf)
                    chunk_ct = src_stream.read(chunk_len)
                    if len(chunk_ct) != chunk_len:
                        raise CryptoIntegrityError("Corrupt stream: truncated chunk payload.")

                    nonce = _make_chunk_nonce(nonce_prefix, chunk_idx)

                    # Try decrypting as intermediate chunk first
                    decrypted_chunk = None
                    aad_intermediate = _make_chunk_aad(drop_id, chunk_idx, is_final=False)
                    try:
                        decrypted_chunk = aesgcm.decrypt(nonce, chunk_ct, aad_intermediate)
                        is_final = False
                    except InvalidTag:
                        # Try decrypting as final chunk
                        aad_final = _make_chunk_aad(drop_id, chunk_idx, is_final=True)
                        try:
                            decrypted_chunk = aesgcm.decrypt(nonce, chunk_ct, aad_final)
                            is_final = True
                        except InvalidTag as e:
                            raise CryptoIntegrityError(f"Authentication tag failure at chunk {chunk_idx}.") from e

                    f_out.write(decrypted_chunk)
                    bytes_written += len(decrypted_chunk)

                    if progress_callback:
                        progress_callback(bytes_written, expected_size)

                    if is_final:
                        reached_final = True
                        break

                    chunk_idx += 1

        if not reached_final:
            raise CryptoIntegrityError("Stream truncated: did not receive the authenticated final chunk.")

        if bytes_written != expected_size:
            raise CryptoIntegrityError(
                f"File size mismatch: metadata specified {expected_size} bytes, but {bytes_written} bytes decrypted."
            )

        # Safely move temporary file to target path
        if target_path.exists():
            target_path.unlink()
        temp_target.replace(target_path)
        return metadata

    except Exception:
        # Secure cleanup: remove any temporary output
        if temp_target.exists():
            try:
                temp_target.unlink()
            except OSError:
                pass
        raise


def encrypt_bytes(data: bytes, filename: str, fk: bytes, drop_id: str) -> bytes:
    """Helper to encrypt bytes directly in memory (for testing or small payloads)."""
    import io
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_name = tmp.name

    try:
        out_stream = io.BytesIO()
        encrypt_file(tmp_name, out_stream, fk, drop_id)
        return out_stream.getvalue()
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def decrypt_bytes(blob: bytes, fk: bytes, drop_id: str) -> Tuple[bytes, Dict[str, Union[str, int]]]:
    """Helper to decrypt bytes directly in memory (for testing or small payloads)."""
    import io
    import tempfile

    in_stream = io.BytesIO(blob)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_name = tmp.name

    try:
        meta = decrypt_file(in_stream, tmp_name, fk, drop_id)
        with open(tmp_name, "rb") as f:
            plain = f.read()
        return plain, meta
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
