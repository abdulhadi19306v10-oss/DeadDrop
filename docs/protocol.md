# DeadDrop Protocol & Cryptographic Specification

## 1. Overview
The DeadDrop protocol enables zero-knowledge, asynchronous encrypted file delivery across untrusted cloud relay servers. Plaintext files, passwords, Link Secrets, and unencrypted File Keys never leave the client endpoints.

---

## 2. Cryptographic Primitives

| Purpose | Primitive / Algorithm | Parameters |
|---|---|---|
| **File Chunk Cipher** | AES-256-GCM | 1 MiB chunk size, 16-byte tag |
| **Password KDF** | Argon2id (RFC 9106) | $m=64\text{ MiB}$, $t=3$, $p=1$, 16-byte salt, 32-byte output |
| **Wrapping Key KDF** | HKDF-SHA256 (RFC 5869) | $L=32\text{ bytes}$, $\text{info} = \text{"deaddrop-wrap-v1"} \parallel \text{drop\_id}$ |
| **Two-Factor Auth** | TOTP (RFC 6238) | SHA-1, 6 digits, 30-second time-step, $\pm 1$ step window |
| **Secrets At Rest** | AES-256-GCM | Master key (env var or KMS) protecting `ss_enc` and `totp_enc` |
| **Random Number Gen** | OS CSPRNG | `secrets.token_bytes` |

---

## 3. Key Hierarchy & Derivation

```
                [User Password]          [Random Salt (16 B)]
                       │                          │
                       ▼                          ▼
               ┌──────────────────────────────────────┐
               │              Argon2id                │
               └──────────────────────────────────────┘
                                  │
                                  ▼
               ┌──────────────────────────────────────┐
               │                 KEK                  │ (32 B)
               └──────────────────────────────────────┘
                                  │
[Server Share (SS)] ──────────────┼────────────── [Link Secret (LS)]
     (32 B)                       │                     (16 B)
                                  ▼
               ┌──────────────────────────────────────┐
               │             HKDF-SHA256              │ Info: "deaddrop-wrap-v1" || drop_id
               └──────────────────────────────────────┘
                                  │
                                  ▼
               ┌──────────────────────────────────────┐
               │           Wrapping Key (WK)          │ (32 B)
               └──────────────────────────────────────┘
                                  │
                                  ▼
               ┌──────────────────────────────────────┐
               │          AES-256-GCM Wrap            │ Encrypts random File Key (FK)
               └──────────────────────────────────────┘ AAD: drop_id
                                  │
                                  ▼
                            [WrappedFK] (60 B: 12 B IV + 32 B CT + 16 B Tag)
```

---

## 4. DDRP Container Format (Streamed AES-256-GCM)

```
Offset   Size     Description
──────   ────     ───────────
0        4 B      Magic identifier: b"DDRP"
4        2 B      Version (uint16 big-endian, currently 1)
6        4 B      Chunk size (uint32 big-endian, default 1,048,576 B)
10       8 B      Nonce prefix (random CSPRNG)

--- CHUNK 0: METADATA ---
18       4 B      Length of encrypted Chunk 0
22       Var      AES-GCM(FK, Nonce = prefix || uint32(0), AAD = drop_id || 0 || is_final, JSON metadata)

--- CHUNK i (1..N): FILE DATA ---
Var      4 B      Length of encrypted Chunk i
Var      Var      AES-GCM(FK, Nonce = prefix || uint32(i), AAD = drop_id || i || is_final, data_i)
```

### Tamper Defenses:
- **Chunk Modification**: AES-GCM 16-byte Poly1305/GHASH tag verification fails on any bit flip.
- **Chunk Swapping / Reordering**: Chunk index `i` is bound inside the Additional Authenticated Data (AAD) and the nonce.
- **Premature Truncation**: `is_final` flag (0 or 1) in AAD verifies that stream completes on the true final chunk.
- **Atomic Disk Writes**: Client streams into a random temporary file, validating each tag before renaming. If any tag fails, the temporary file is shredded and 0 bytes are emitted.

---

## 5. Relay Server Wire Protocol

### `POST /drops`
- **Request**: `{"expires_hours": 24, "max_downloads": 1}`
- **Response**: `{"drop_id": "...", "ss_hex": "...", "totp_secret": "...", "totp_uri": "...", "backup_codes": [...]}`

### `PUT /drops/{id}/blob`
- **Request**: Stream of `application/octet-stream` DDRP container bytes.
- **Response**: `{"status": "uploaded", "blob_size": int}`

### `POST /drops/{id}/finalize`
- **Request**: `{"salt_hex": "...", "wrapped_fk_hex": "..."}`
- **Response**: `{"status": "active"}`

### `POST /drops/{id}/unlock`
- **Request**: `{"totp_code": "123456"}` or `{"backup_code": "ABCD-1234"}`
- **Response**: `{"ss_hex": "...", "salt_hex": "...", "wrapped_fk_hex": "...", "download_token": "..."}`
- **Rate Limit**: 5 consecutive failures triggers a 15-minute lockout (exponential on repeats).

### `GET /drops/{id}/blob?token={download_token}`
- **Response**: Streamed ciphertext blob.
- **Post-condition**: Single-use token deleted; if `downloads == max_downloads`, drop is automatically burned.
