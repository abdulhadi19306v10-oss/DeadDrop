# DeadDrop Security Model & Threat Analysis

## 1. Trust Assumptions & Boundaries

### Trusted
- **Sender Endpoint**: Operating system and hardware running PySide6 client are uncompromised.
- **Recipient Endpoint**: Hardware and authenticator app (Google Authenticator) are uncompromised.
- **Out-of-Band Channels**: Drop Code (`DD1-...`) and Passphrase travel over separate communication channels.

### Untrusted
- **Cloud Relay Server**: The relay server, its SQLite/Postgres database, and file storage may be compromised, subpoenaed, or leaked.
- **Network Transport**: Untrusted network intermediaries, malicious proxies, and Wi-Fi sniffers (protected via TLS 1.3 and AEAD payload encryption).

---

## 2. Threat Analysis & Mitigations

### 2.1 Server Database Leak or Malicious Operator
- **Threat**: Attacker dumps SQLite database and all ciphertext blobs.
- **Mitigation**:
  - The server holds only ciphertext, public salt, and `WrappedFK`.
  - To compute `WK`, an attacker requires $\text{KEK} \parallel \text{SS} \parallel \text{LS}$.
  - The Link Secret (LS) is never sent to the server.
  - The password is never sent to the server.
  - Plaintext cannot be decrypted without client credentials.

### 2.2 Stolen Phone (TOTP Only)
- **Threat**: Attacker steals recipient phone and extracts TOTP code.
- **Mitigation**:
  - Attacker can call `POST /drops/{id}/unlock` and obtain `SS`.
  - Attacker cannot unwrap `FK` without the password (KEK) and Link Secret (LS).

### 2.3 Stolen Password Only
- **Threat**: Attacker overhears or cracks the password.
- **Mitigation**:
  - Attacker cannot derive `WK` without `SS` and `LS`.
  - The relay will refuse to release `SS` without a valid 6-digit TOTP code.

### 2.4 Online Password / TOTP Guessing
- **Threat**: Botnet brute-forces 6-digit TOTP codes or passwords.
- **Mitigation**:
  - Relay enforces lockout after 5 failed attempts (15-minute lock, doubling exponentially).
  - Relay returns uniform generic error responses (`HTTP 400: Drop unavailable or invalid verification`) to prevent timing and drop enumeration.
  - Password unwrap occurs strictly locally on the client; relay is unaware of password guesses.

### 2.5 TOTP Token Replay
- **Threat**: Man-in-the-middle captures valid 6-digit TOTP code and replays it.
- **Mitigation**:
  - Relay records `totp_last_step`.
  - Any code corresponding to a time-step $\le \text{totp\_last\_step}$ is rejected immediately.

### 2.6 Ciphertext Tampering & Chunk Swapping
- **Threat**: Malicious relay or network actor tampers with stored bytes or reorders chunks.
- **Mitigation**:
  - AES-256-GCM authenticated encryption.
  - Nonces and AAD bind `drop_id`, `chunk_index`, and `is_final` flag.
  - Decryption fails immediately upon any tag mismatch; temporary files are wiped.

---

## 3. Cryptographic Storage & Sanitization
- All transient keys (`FK`, `KEK`, `WK`, `SS`) are overwritten in RAM using `zero_bytes()` upon completion.
- Secrets on the relay server (`SS` and `TOTP secret`) are encrypted at rest with AES-256-GCM under `MASTER_KEY`.
- Manual or automatic burning overwrites blob files with zeroes before unlinking from the filesystem.
