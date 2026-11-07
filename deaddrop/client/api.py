"""HTTP Client communicating with DeadDrop Relay Server."""

import io
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
import httpx


class RelayAPIError(Exception):
    """Exception raised on relay API communication or response failures."""

    def __init__(self, message: str, status_code: Optional[int] = None, detail: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail or message


class DeadDropClient:
    """Client for DeadDrop Relay Server."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", session_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.session_token = session_token
        self.timeout = httpx.Timeout(connect=10.0, read=60.0, write=60.0, pool=10.0)

    def _headers(self) -> Dict[str, str]:
        headers = {}
        if self.session_token:
            headers["Authorization"] = f"Bearer {self.session_token}"
        return headers

    def create_drop(self, expires_hours: int = 24, max_downloads: int = 1) -> Dict[str, Any]:
        """Creates a new drop on relay and obtains drop_id, SS, and TOTP secret."""
        url = f"{self.base_url}/drops"
        payload = {"expires_hours": expires_hours, "max_downloads": max_downloads}
        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(url, json=payload, headers=self._headers())
            if res.status_code != 200:
                raise RelayAPIError(
                    f"Create drop failed ({res.status_code}): {res.text}",
                    status_code=res.status_code,
                    detail=res.json().get("detail") if res.headers.get("content-type") == "application/json" else res.text,
                )
            return res.json()

    def upload_blob(
        self,
        drop_id: str,
        blob_source: Union[bytes, io.BytesIO, Path, str],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Uploads encrypted ciphertext blob to relay."""
        url = f"{self.base_url}/drops/{drop_id}/blob"

        if isinstance(blob_source, bytes):
            data_bytes = blob_source
        elif isinstance(blob_source, io.BytesIO):
            data_bytes = blob_source.getvalue()
        else:
            with open(blob_source, "rb") as f:
                data_bytes = f.read()

        total_bytes = len(data_bytes)

        # Upload with progress tracking
        def data_generator():
            chunk_size = 64 * 1024
            uploaded = 0
            for i in range(0, total_bytes, chunk_size):
                chunk = data_bytes[i : i + chunk_size]
                uploaded += len(chunk)
                if progress_callback:
                    progress_callback(uploaded, total_bytes)
                yield chunk

        with httpx.Client(timeout=self.timeout) as client:
            res = client.put(
                url,
                content=data_generator(),
                headers={"Content-Type": "application/octet-stream", **self._headers()},
            )
            if res.status_code != 200:
                raise RelayAPIError(
                    f"Blob upload failed ({res.status_code}): {res.text}",
                    status_code=res.status_code,
                    detail=res.text,
                )
            return res.json()

    def finalize_drop(self, drop_id: str, salt_hex: str, wrapped_fk_hex: str) -> Dict[str, Any]:
        """Finalizes drop by storing salt and wrapped_fk, marking drop active."""
        url = f"{self.base_url}/drops/{drop_id}/finalize"
        payload = {"salt_hex": salt_hex, "wrapped_fk_hex": wrapped_fk_hex}
        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(url, json=payload, headers=self._headers())
            if res.status_code != 200:
                raise RelayAPIError(
                    f"Finalize failed ({res.status_code}): {res.text}",
                    status_code=res.status_code,
                    detail=res.text,
                )
            return res.json()

    def unlock_drop(
        self,
        drop_id: str,
        totp_code: Optional[str] = None,
        backup_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Unlocks drop using TOTP or backup code and returns SS, salt, wrapped_fk, download token."""
        url = f"{self.base_url}/drops/{drop_id}/unlock"
        payload = {}
        if totp_code:
            payload["totp_code"] = totp_code
        elif backup_code:
            payload["backup_code"] = backup_code
        else:
            raise ValueError("Either totp_code or backup_code must be provided.")

        with httpx.Client(timeout=self.timeout) as client:
            res = client.post(url, json=payload, headers=self._headers())
            if res.status_code != 200:
                detail = "Unlock rejected."
                try:
                    detail = res.json().get("detail", res.text)
                except Exception:
                    detail = res.text
                raise RelayAPIError(f"Unlock failed ({res.status_code}): {detail}", status_code=res.status_code, detail=detail)
            return res.json()

    def download_blob(
        self,
        drop_id: str,
        download_token: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bytes:
        """Streams encrypted blob using single-use download token."""
        url = f"{self.base_url}/drops/{drop_id}/blob"
        with httpx.Client(timeout=self.timeout) as client:
            with client.stream("GET", url, params={"token": download_token}) as res:
                if res.status_code != 200:
                    raise RelayAPIError(f"Download failed with status {res.status_code}.", status_code=res.status_code)

                total_str = res.headers.get("content-length")
                total_bytes = int(total_str) if total_str and total_str.isdigit() else 0

                chunks = []
                downloaded = 0
                for chunk in res.iter_bytes(chunk_size=64 * 1024):
                    chunks.append(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback(downloaded, total_bytes if total_bytes > 0 else downloaded)

                return b"".join(chunks)

    def burn_drop(self, drop_id: str) -> Dict[str, Any]:
        """Shreds drop on relay server."""
        url = f"{self.base_url}/drops/{drop_id}"
        with httpx.Client(timeout=self.timeout) as client:
            res = client.delete(url, headers=self._headers())
            if res.status_code != 200:
                raise RelayAPIError(f"Burn failed ({res.status_code}): {res.text}", status_code=res.status_code)
            return res.json()

    def list_drops(self) -> List[Dict[str, Any]]:
        """Lists active drops."""
        url = f"{self.base_url}/drops"
        with httpx.Client(timeout=self.timeout) as client:
            res = client.get(url, headers=self._headers())
            if res.status_code != 200:
                raise RelayAPIError(f"List drops failed ({res.status_code}).", status_code=res.status_code)
            return res.json()

    def get_audit(self, drop_id: str) -> List[Dict[str, Any]]:
        """Fetches audit trail for a drop."""
        url = f"{self.base_url}/drops/{drop_id}/audit"
        with httpx.Client(timeout=self.timeout) as client:
            res = client.get(url, headers=self._headers())
            if res.status_code != 200:
                raise RelayAPIError(f"Audit log fetch failed ({res.status_code}).", status_code=res.status_code)
            return res.json()
