# DeadDrop ✦ Zero-Knowledge 2FA Secure File Exchange

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Qt 6 / PySide6](https://img.shields.io/badge/GUI-PySide6%20Qt6-brightgreen.svg)](https://wiki.qt.io/Qt_for_Python)
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-teal.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Desktop application for **Kali Linux** (and cross-platform desktop). Encrypts files locally, shares them through an untrusted cloud relay server, and unlocks them only with **Password + Google Authenticator TOTP**.

> **Course Project**: Information Security Lab

---

## 1. Overview & Architecture

DeadDrop provides true **zero-knowledge asynchronous file exchange**:
- **Client**: PySide6 desktop GUI with Kali Linux cyberpunk styling. All encryption and decryption occur locally in RAM.
- **Relay Server**: FastAPI backend managing encrypted blobs, TOTP verification, lockout defenses, and audit logging. The relay **never** sees plaintext, filenames, passwords, or file encryption keys.
- **2FA Access Control**: RFC 6238 TOTP via Google Authenticator with replay protection and exponential lockout.

```
 Sender (Kali Desktop)          Relay Server (Cloud)          Recipient (Kali Desktop)
 ┌─────────────────┐          ┌─────────────────────┐        ┌─────────────────┐
 │ PySide6 GUI     │          │ FastAPI + SQLite    │        │ PySide6 GUI     │
 │ crypto_core     │──TLS 1.3▶│ Opaque Blob Store   │◀─TLS───│ crypto_core     │
 │ encrypt & wrap  │          │ TOTP verify, limits │        │ unwrap & decrypt│
 └─────────────────┘          │ Append-only audit   │        └─────────────────┘
                              └─────────────────────┘
```

---

## 2. Cryptographic Design

| Key / Primitive | Definition | Held By |
|---|---|---|
| **FK** | Random 256-bit File Key | Client in transient RAM |
| **SS** | Random 256-bit Server Share | Server (encrypted under master key, released after TOTP) |
| **LS** | Random 128-bit Link Secret (in drop code) | Sender $\rightarrow$ Recipient out-of-band |
| **KEK** | `Argon2id(password, salt)` (64 MiB, t=3, p=1) | Client transient RAM |
| **WK** | `HKDF-SHA256(KEK ‖ SS ‖ LS, info="deaddrop-wrap-v1" ‖ drop_id)` | Client transient RAM |
| **WrappedFK**| `AES-GCM(WK, FK, aad=drop_id)` | Server |
| **Container** | 1 MiB chunked AES-256-GCM (`DDRP` magic header) | Server blob store |

### Security Guarantees:
- **Server DB Leak**: Attacker obtains only ciphertext and cannot decrypt without the Link Secret and password.
- **Stolen Phone (TOTP only)**: Attacker obtains Server Share (SS) but cannot decrypt without the password and Link Secret.
- **Stolen Password only**: Attacker cannot derive WK without the Server Share (which requires valid TOTP).
- **Tampering / Reordering**: AES-256-GCM chunk tags, bound with chunk index and final flags, cause atomic abort if modified.

---

## 3. Quick Start & Installation

### Requirements:
- Python 3.11+
- Virtual environment (recommended)

```bash
# Clone the repository
git clone https://github.com/abdulhadi19306v10-oss/DeadDrop.git
cd DeadDrop

# Setup virtual environment
python -m venv .venv

# Activate environment
# On Linux / Kali:
source .venv/bin/activate
# On Windows:
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 4. Running DeadDrop

### Step 1: Start the Relay Server
In a terminal, start the FastAPI relay backend:
```bash
python -m deaddrop.server.main
```
The server will start on `http://127.0.0.1:8000`. You can inspect the health endpoint at `http://127.0.0.1:8000/health`.

### Step 2: Launch the PySide6 Desktop GUI
In a separate terminal, launch the desktop application:
```bash
python -m deaddrop.client.app
```

---

## 5. Desktop Application Tabs

1. **📤 Send Drop**:
   - Drag and drop any file.
   - Use the **Diceware Passphrase Generator** and real-time **zxcvbn strength meter**.
   - Configure expiry (1h to 7d) and download limits (default: Burn after read).
   - Generates the **Share Package** with a Google Authenticator QR code, manual base32 secret, and single-use backup codes.
2. **📥 Receive Drop**:
   - Paste the Drop Code (`DD1-...`).
   - Enter password and 6-digit TOTP code (or toggle for backup code).
   - Verifies integrity, unwraps the File Key locally, downloads and writes plaintext atomically.
3. **📋 My Drops**:
   - Monitor active drops, download counts, and expiration.
   - Trigger immediate **Manual Burn** (shreds ciphertext blob with zeroes).
   - Inspect the **Append-Only Audit Timeline** with salted IP hashes.
4. **🔬 Security Lab**:
   - Side-by-side comparison of **What Relay Stores** vs **What Client Holds**.
   - Interactive live attack simulations:
     - *Wrong TOTP Guess*
     - *Replayed TOTP Attack*
     - *Tampered Ciphertext Bit-Flip*
     - *5-Attempt Lockout Defense*
     - *Brute-Force Benchmark against flawed "TOTP-as-Key" designs*
5. **⚙ Settings**:
   - Relay server endpoint and TLS pinning configuration.

---

## 6. Command-Line Interface (CLI)

DeadDrop also includes a fully functional CLI sharing the identical cryptographic core:

```bash
# Send a file
python -m deaddrop.client.cli send secret_document.pdf --expires 24 --downloads 1

# Receive a file
python -m deaddrop.client.cli receive DD1-<drop_id>-<link_secret> --out ./downloads

# List active drops
python -m deaddrop.client.cli list

# Burn a drop immediately
python -m deaddrop.client.cli burn <drop_id>
```

---

## 7. Running the Automated Test Suite

Run the full automated test suite with `pytest`:
```bash
pytest tests/ -v
```

Tests cover:
- Core AES-256-GCM chunk framing, multi-chunk, and empty file boundaries.
- Tampered single-bit and truncated blob rejection.
- TOTP verification, 30s replay guard, and single-use backup code invalidation.
- Exponential lockout backoff (5 failed attempts).
- Full client-to-server end-to-end send, unlock, and burn lifecycle.

---

## 8. Deployment

To deploy the relay server with Docker and Docker Compose:
```bash
cd deploy
docker compose up -d
```
