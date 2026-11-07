# DeadDrop

Desktop application for Kali Linux. Encrypts files locally, shares them through a cloud relay server, and unlocks them only with password + Google Authenticator code.

Course: Information Security lab project

---

## 1. Overview

- **Client**: Python desktop app (PySide6/Qt) on Kali Linux. All encryption and decryption happen here.
- **Relay server**: Cloud-hosted backend (FastAPI). Stores encrypted blobs, verifies 2FA, enforces expiry and download limits. Never sees plaintext, filename, or password.
- **Sharing model**: Sender uploads encrypted file to relay. Recipient pulls it with a drop code, password, and TOTP code.
- **2FA**: TOTP (RFC 6238) via Google Authenticator.

### Why relay, not peer-to-peer
Recipient and sender are rarely online together and sit behind NAT. Relay gives asynchronous delivery, expiry, and central enforcement of 2FA and rate limits. Relay holds only ciphertext.

## 2. Features

**File protection**
- AES-256-GCM encryption, chunked for large files.
- Random per-file key.
- Filename, size, type encrypted inside the blob.
- Tamper, reorder, truncation detection.

**Access control**
- Password-derived key (Argon2id).
- Per-drop TOTP secret enrolled in Google Authenticator via QR.
- Server-held key share released only after valid TOTP.
- Single-use backup codes.
- Replay protection on TOTP codes.
- Lockout and exponential backoff on failed attempts.

**Drop policy**
- Expiry: 1 hour to 7 days.
- Max downloads (default 1).
- Burn after read.
- Manual burn from dashboard.
- Secure delete of blob, key share, wrapped key, TOTP secret.

**Application**
- Desktop GUI: Send, Receive, My Drops, Security Lab, Settings.
- Optional CLI using same crypto core.
- TLS certificate pinning to relay.
- Local audit view per drop.

## 3. Architecture

```
 Sender (Kali desktop)          Relay Server (cloud)          Recipient (Kali desktop)
 ┌─────────────────┐          ┌─────────────────────┐        ┌─────────────────┐
 │ PySide6 GUI     │          │ FastAPI + Nginx     │        │ PySide6 GUI     │
 │ crypto_core     │──TLS 1.3▶│ SQLite/Postgres     │◀─TLS───│ crypto_core     │
 │ encrypt/wrap    │          │ blob store          │        │ unwrap/decrypt  │
 └─────────────────┘          │ TOTP verify, limits │        └─────────────────┘
                              │ audit log           │
                              └─────────────────────┘
```

Server stores: ciphertext, salt, wrapped file key, encrypted server share, encrypted TOTP secret, policy, audit events.
Server never stores: plaintext, password, file key, key-encryption key, link secret.

## 4. Cryptographic Design

### Primitives
| Purpose | Algorithm |
|---------|-----------|
| File encryption | AES-256-GCM, 1 MiB chunks |
| Password KDF | Argon2id (64 MiB, t=3, p=1 minimum), 16-byte salt |
| Key combination | HKDF-SHA256 |
| 2FA | TOTP, SHA-1, 6 digits, 30 s |
| Server-side secrets at rest | AES-256-GCM under master key (env var / KMS) |
| Backup code storage | Salted hash |
| RNG | OS CSPRNG |
| Optional recipient mode | X25519 + Ed25519 |

### Keys
| Key | Description | Held by |
|-----|-------------|---------|
| FK | Random 256-bit file key | Client (wrapped copy on server) |
| SS | Random 256-bit server share | Server, released after TOTP |
| LS | Random 128-bit link secret, embedded in drop code | Sender → recipient only |
| KEK | `Argon2id(password, salt)` | Client, transient |
| WK | `HKDF(KEK ‖ SS ‖ LS, info = "deaddrop-wrap-v1" ‖ drop_id)` | Client, transient |
| WrappedFK | `AES-GCM(WK, FK, aad = drop_id)` | Server |

### File format
```
header : magic "DDRP" | version | chunk_size | nonce_prefix (8 B)
chunk 0: encrypted metadata JSON {name, size, mime, created}
chunk i: AES-GCM(FK, nonce = prefix ‖ uint32(i),
                 aad = drop_id ‖ i ‖ is_final, data_i)
```

### Security properties
| Attacker obtains | Outcome |
|------------------|---------|
| Relay database and blobs | Cannot decrypt: lacks LS and password |
| Password only | Cannot obtain SS without valid TOTP |
| Phone (TOTP) only | Obtains SS; lacks password and LS |
| Network capture | TLS 1.3 + AEAD |
| Modified ciphertext | GCM tag verification fails, no output written |
| Drop ID | Random 128-bit; gives nothing without TOTP |

## 5. How It Works

### 5.1 Sending
1. Sender logs in (account password + account TOTP).
2. Selects file, sets drop password, expiry, download limit.
3. App requests new drop from relay. Relay returns `drop_id`, `SS`, per-drop TOTP secret, backup codes.
4. App generates `FK`, `salt`, `LS`. Derives `KEK` and `WK`. Encrypts file in chunks. Wraps `FK`.
5. App uploads ciphertext, then `salt` and `WrappedFK`. Relay activates drop.
6. App wipes `FK`, `KEK`, `WK`, `SS` from memory.
7. App shows **Share Package** (displayed once):
   - **Drop code**: `DD1-<drop_id>-<LS>`
   - **Password** (to send over a different channel)
   - **TOTP QR** + manual key (recipient scans into Google Authenticator)
   - **Backup codes**

### 5.2 Receiving
1. Recipient scanned TOTP QR earlier into Google Authenticator.
2. Opens **Receive** tab, pastes drop code, enters password and current 6-digit TOTP.
3. Relay checks: drop exists, not expired, downloads remaining, not locked, TOTP valid, time-step unused.
4. Relay returns `SS`, `salt`, `WrappedFK`, 60-second download token.
5. App derives `KEK`, `WK`, unwraps `FK`. Wrong password fails here, locally.
6. App streams ciphertext, verifies and decrypts each chunk, writes file only if all tags pass.
7. Relay increments download count and deletes drop when limit reached or expired.

### 5.3 Failure handling
| Event | Behavior |
|-------|----------|
| Wrong or replayed TOTP | Generic "invalid" response, attempt counted |
| 5 failed attempts | Drop locked 15 min; doubles on repeat |
| Expired, deleted, nonexistent | Identical generic response |
| Wrong password | Local unwrap failure, relay unaware |
| Tampered blob | Download aborted, nothing saved |

## 6. Server Security

- TLS 1.3 only, HSTS, Let's Encrypt.
- Per-IP and per-drop rate limiting.
- Constant-time comparisons.
- Random blob filenames, upload size cap, blobs never executed.
- Master key from environment or KMS; all stored secrets encrypted.
- Append-only audit log: timestamp, hashed drop ID, event, outcome, salted IP hash.
- Generic errors and uniform response timing.
- Session cookies/tokens: short-lived, scoped.

## 7. Desktop Application

**Platform**: Kali Linux, Python 3.11+, PySide6 (Qt 6).

### Screens

**Send**
```
┌──────────────────────────────────────────────┐
│ DeadDrop   [Send][Receive][My Drops][Lab][⚙] │
├──────────────────────────────────────────────┤
│  ┌────────────────────────────────────┐      │
│  │   Drop file here / Browse...       │      │
│  └────────────────────────────────────┘      │
│  Password: [************]  [Generate]         │
│  Strength: ████████░░ Strong                 │
│  Expires: [24 h ▾]   Max downloads: [1 ▾]    │
│  [ Encrypt & Upload ]                        │
│  ▓▓▓▓▓▓░░░░ Encrypting 62%                   │
└──────────────────────────────────────────────┘
```

**Share Package** (modal, shown once)
- Drop code with copy button.
- Password with copy button.
- TOTP QR, manual key.
- Backup codes, save to file.
- Checkbox "Saved everything" required to close.

**Receive**
- Drop code field, password field, six-box TOTP input, "use backup code" toggle.
- States: lockout countdown, generic error, progress bar.
- Save-as dialog on success.

**My Drops**
- Table: short ID, status, expiry countdown, downloads used/max.
- Actions: Burn now, View audit timeline.

**Security Lab**
- Side-by-side view: what relay stores vs what client holds.
- Demo buttons: wrong TOTP, replayed TOTP, tampered blob, expired drop, lockout. Each shows outcome.

**Settings**
- Relay URL, pinned certificate fingerprint, default expiry/limits, CLI path.

### UX rules
- Password and TOTP fields cleared after submit.
- Secrets never written to disk or logs.
- Weak password warning (zxcvbn).
- Diceware passphrase generator.
- Background worker threads; UI stays responsive.

## 8. Database Schema (relay)

```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  totp_enc BLOB NOT NULL,
  totp_last_step INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE drops (
  id TEXT PRIMARY KEY,
  owner_id TEXT REFERENCES users(id),
  blob_path TEXT NOT NULL,
  blob_size INTEGER,
  salt BLOB,
  wrapped_fk BLOB,
  ss_enc BLOB NOT NULL,
  totp_enc BLOB NOT NULL,
  totp_last_step INTEGER DEFAULT 0,
  max_downloads INTEGER NOT NULL DEFAULT 1,
  downloads INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL
);

CREATE TABLE backup_codes (
  drop_id TEXT REFERENCES drops(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  drop_hash TEXT,
  event TEXT NOT NULL,
  outcome TEXT NOT NULL,
  ip_hash TEXT
);
```

## 9. Relay API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | /auth/register | none | Create account, return TOTP enrollment |
| POST | /auth/login | password + TOTP | Issue session token |
| POST | /drops | session | Create drop: id, SS, TOTP URI, backup codes |
| PUT | /drops/{id}/blob | session | Upload ciphertext (streamed) |
| POST | /drops/{id}/finalize | session | Store salt, WrappedFK, policy |
| POST | /drops/{id}/unlock | TOTP or backup code | Release SS, salt, WrappedFK, download token |
| GET | /drops/{id}/blob | download token | Stream ciphertext |
| DELETE | /drops/{id} | session | Burn drop |
| GET | /drops | session | List owner's drops |
| GET | /drops/{id}/audit | session | Owner's events for drop |

## 10. Tech Stack

| Layer | Choice |
|-------|--------|
| Desktop GUI | PySide6 (Qt 6) |
| Client crypto | `cryptography`, `argon2-cffi` |
| Password strength | `zxcvbn` |
| QR display | `qrcode` + Pillow |
| HTTP client | `httpx` (TLS pinning) |
| Server | FastAPI, uvicorn |
| 2FA | `pyotp` |
| DB | SQLite (lab) / Postgres |
| Rate limiting | `slowapi` / Nginx `limit_req` |
| Deploy | Cloud VPS, Nginx, Let's Encrypt, systemd or Docker |
| Tests | pytest, hypothesis |
| Packaging | venv + `pip`, optional PyInstaller / `.deb` |

### Kali setup
```bash
sudo apt update && sudo apt install -y python3-venv libxcb-cursor0
python3 -m venv .venv && source .venv/bin/activate
pip install PySide6 cryptography argon2-cffi httpx pyotp qrcode pillow zxcvbn
python -m deaddrop.app
```

## 11. Project Structure

```
deaddrop/
├── client/
│   ├── app.py                 # entry point
│   ├── ui/ (send.py, receive.py, drops.py, lab.py, settings.py, widgets.py)
│   ├── crypto_core.py         # KDF, chunk AEAD, wrap/unwrap
│   ├── api.py                 # relay client, TLS pinning
│   ├── workers.py             # background threads
│   └── cli.py
├── server/
│   ├── main.py
│   ├── routes/ (auth.py, drops.py)
│   ├── crypto_server.py       # master-key encryption of stored secrets
│   ├── totp.py                # verification + replay guard
│   ├── ratelimit.py
│   ├── models.py
│   └── audit.py
├── deploy/ (nginx.conf, docker-compose.yml, deaddrop.service)
├── tests/
└── docs/ (protocol.md, security_model.md)
```

## 12. Security Model

**Protected against**
- Relay database or blob theft.
- Network eavesdropping and modification.
- Stolen password alone or stolen phone alone.
- Online guessing of TOTP and passwords.
- TOTP replay.
- Ciphertext tampering, chunk reordering, truncation.
- Drop ID guessing and enumeration.

**Assumptions / out of scope**
- Sender and recipient endpoints are uncompromised.
- Drop code and password travel over separate channels.
- Coercion and large-scale denial of service.

## 13. Testing and Demo

**Tests**
- Encrypt/decrypt roundtrip: empty file, one byte, exact chunk boundary, multi-GB.
- Single-bit ciphertext flip, chunk swap, truncation: all rejected.
- TOTP: valid, ±1 step drift, expired, replay, backup code reuse.
- Lockout and backoff timing.
- Expiry and download limit enforcement.
- Nonexistent vs expired drop: identical response.

**Demo flow**
1. Send file; show relay storage is opaque.
2. Receive with correct password + TOTP.
3. Wrong TOTP, replayed TOTP, lockout (Security Lab).
4. Tamper with stored blob; client rejects.
5. Burn after read.
6. Contrast with "TOTP as key" scheme: brute-forced in seconds by script.

## 14. Roadmap

| Phase | Deliverable |
|-------|-------------|
| 1 | `crypto_core.py`, CLI local encrypt/decrypt, tests |
| 2 | Relay: create, upload, unlock, download |
| 3 | TOTP, replay guard, lockout, backup codes |
| 4 | PySide6 GUI: Send, Receive, My Drops |
| 5 | Hardening: TLS pinning, rate limits, audit, cloud deploy |
| 6 | Security Lab, report, demo |
| Stretch | Recipient public-key mode, signed drops, size padding |

## 15. References

- RFC 6238 (TOTP), RFC 5869 (HKDF), RFC 9106 (Argon2)
- NIST SP 800-38D (GCM)
- OWASP ASVS, Cryptographic Storage Cheat Sheet
