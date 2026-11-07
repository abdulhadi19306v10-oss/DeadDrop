"""PySide6 QThread background workers for non-blocking cryptography and network operations."""

import io
from pathlib import Path
from typing import Optional
from PySide6.QtCore import QThread, Signal

from deaddrop.client.api import DeadDropClient, RelayAPIError
from deaddrop.client.crypto_core import (
    CryptoError,
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
    zero_bytes,
)


class EncryptUploadWorker(QThread):
    """Background worker for encrypting a file locally and uploading to the relay server."""

    progress = Signal(int, int, str)  # current, total, message
    success = Signal(dict)  # share package dict
    error = Signal(str)

    def __init__(
        self,
        api_client: DeadDropClient,
        file_path: str,
        password: str,
        expires_hours: int = 24,
        max_downloads: int = 1,
    ):
        super().__init__()
        self.api = api_client
        self.file_path = file_path
        self.password = password
        self.expires_hours = expires_hours
        self.max_downloads = max_downloads

    def run(self):
        fk = None
        kek = None
        wk = None
        try:
            self.progress.emit(0, 100, "Contacting relay to reserve drop...")
            drop_info = self.api.create_drop(
                expires_hours=self.expires_hours,
                max_downloads=self.max_downloads,
            )

            drop_id = drop_info["drop_id"]
            ss_bytes = bytes.fromhex(drop_info["ss_hex"])
            totp_secret = drop_info["totp_secret"]
            totp_uri = drop_info["totp_uri"]
            backup_codes = drop_info["backup_codes"]

            self.progress.emit(10, 100, "Deriving encryption keys with Argon2id...")
            salt = generate_salt()
            ls = generate_link_secret()
            fk = generate_file_key()

            kek = derive_kek(self.password, salt)
            wk = derive_wk(kek, ss_bytes, ls, drop_id)
            wrapped_fk = wrap_fk(wk, fk, drop_id)

            self.progress.emit(30, 100, "Encrypting file in 1 MiB chunks (AES-256-GCM)...")
            blob_stream = io.BytesIO()

            def crypto_prog(curr, tot):
                pct = int(30 + (curr / tot) * 35) if tot > 0 else 30
                self.progress.emit(pct, 100, f"Encrypting: {curr // 1024} KB / {tot // 1024} KB")

            encrypt_file(
                source_path=self.file_path,
                dest_stream=blob_stream,
                fk=fk,
                drop_id=drop_id,
                progress_callback=crypto_prog,
            )

            blob_bytes = blob_stream.getvalue()
            total_blob_len = len(blob_bytes)

            self.progress.emit(65, 100, "Uploading ciphertext blob to relay...")

            def upload_prog(curr, tot):
                pct = int(65 + (curr / tot) * 25) if tot > 0 else 65
                self.progress.emit(pct, 100, f"Uploading: {curr // 1024} KB / {tot // 1024} KB")

            self.api.upload_blob(
                drop_id=drop_id,
                blob_source=blob_bytes,
                progress_callback=upload_prog,
            )

            self.progress.emit(90, 100, "Finalizing drop policies on relay...")
            self.api.finalize_drop(
                drop_id=drop_id,
                salt_hex=salt.hex(),
                wrapped_fk_hex=wrapped_fk.hex(),
            )

            drop_code = format_drop_code(drop_id, ls)
            self.progress.emit(100, 100, "Drop activated successfully!")

            share_package = {
                "drop_code": drop_code,
                "password": self.password,
                "totp_secret": totp_secret,
                "totp_uri": totp_uri,
                "backup_codes": backup_codes,
                "drop_id": drop_id,
                "expires_at": drop_info.get("expires_at"),
            }
            self.success.emit(share_package)

        except (RelayAPIError, CryptoError, Exception) as e:
            self.error.emit(str(e))
        finally:
            # Secure memory hygiene
            if fk:
                zero_bytes(bytearray(fk))
            if kek:
                zero_bytes(bytearray(kek))
            if wk:
                zero_bytes(bytearray(wk))


class UnlockDownloadWorker(QThread):
    """Background worker for unlocking, downloading, and decrypting a drop."""

    progress = Signal(int, int, str)
    success = Signal(str, dict)  # output_path, metadata
    error = Signal(str)

    def __init__(
        self,
        api_client: DeadDropClient,
        drop_code: str,
        password: str,
        totp_code: Optional[str] = None,
        backup_code: Optional[str] = None,
        output_directory: Optional[str] = None,
    ):
        super().__init__()
        self.api = api_client
        self.drop_code = drop_code
        self.password = password
        self.totp_code = totp_code
        self.backup_code = backup_code
        self.output_directory = output_directory or str(Path.home() / "Downloads")

    def run(self):
        fk = None
        kek = None
        wk = None
        try:
            self.progress.emit(5, 100, "Parsing drop code...")
            drop_id, ls = parse_drop_code(self.drop_code)

            self.progress.emit(15, 100, "Verifying 2FA credentials with relay...")
            unlock_resp = self.api.unlock_drop(
                drop_id=drop_id,
                totp_code=self.totp_code,
                backup_code=self.backup_code,
            )

            ss = bytes.fromhex(unlock_resp["ss_hex"])
            salt = bytes.fromhex(unlock_resp["salt_hex"])
            wrapped_fk = bytes.fromhex(unlock_resp["wrapped_fk_hex"])
            download_token = unlock_resp["download_token"]

            self.progress.emit(35, 100, "Deriving key encryption key (Argon2id)...")
            kek = derive_kek(self.password, salt)
            wk = derive_wk(kek, ss, ls, drop_id)

            self.progress.emit(50, 100, "Unwrapping file encryption key...")
            try:
                fk = unwrap_fk(wk, wrapped_fk, drop_id)
            except CryptoIntegrityError:
                raise CryptoIntegrityError("Decryption failed: Incorrect password provided.")

            self.progress.emit(65, 100, "Downloading ciphertext blob...")

            def dl_prog(curr, tot):
                pct = int(65 + (curr / tot) * 20) if tot > 0 else 65
                self.progress.emit(pct, 100, f"Downloading: {curr // 1024} KB")

            blob_bytes = self.api.download_blob(
                drop_id=drop_id,
                download_token=download_token,
                progress_callback=dl_prog,
            )

            self.progress.emit(85, 100, "Verifying AES-256-GCM chunks and decrypting...")
            blob_stream = io.BytesIO(blob_bytes)

            temp_dest = Path(self.output_directory) / f"temp_{secrets.token_hex(4)}.dat"
            metadata = decrypt_file(blob_stream, temp_dest, fk, drop_id)

            original_filename = metadata.get("name", "deaddrop_received.bin")
            final_dest = Path(self.output_directory) / original_filename

            # Avoid overwriting by appending counter if file already exists
            counter = 1
            stem = final_dest.stem
            suffix = final_dest.suffix
            while final_dest.exists():
                final_dest = Path(self.output_directory) / f"{stem}_{counter}{suffix}"
                counter += 1

            temp_dest.replace(final_dest)

            self.progress.emit(100, 100, "File decrypted and verified successfully!")
            self.success.emit(str(final_dest), metadata)

        except (RelayAPIError, CryptoError, Exception) as e:
            self.error.emit(str(e))
        finally:
            if fk:
                zero_bytes(bytearray(fk))
            if kek:
                zero_bytes(bytearray(kek))
            if wk:
                zero_bytes(bytearray(wk))
