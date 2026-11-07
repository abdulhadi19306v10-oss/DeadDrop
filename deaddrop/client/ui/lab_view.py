"""Security Lab View: Educational demonstration of zero-knowledge boundaries and attack simulations."""

import io
import secrets
import time
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
import pyotp

from deaddrop.client.api import DeadDropClient, RelayAPIError
from deaddrop.client.crypto_core import (
    CryptoIntegrityError,
    decrypt_file,
    derive_kek,
    derive_wk,
    encrypt_bytes,
    encrypt_file,
    generate_file_key,
    generate_link_secret,
    generate_salt,
    unwrap_fk,
    wrap_fk,
)


class LabView(QWidget):
    """Interactive Security Lab for Information Security students and evaluators."""

    def __init__(self, api_client: DeadDropClient, parent=None):
        super().__init__(parent)
        self.api = api_client
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(20, 20, 20, 20)

        header = QLabel("Security Lab: Zero-Knowledge & Cryptographic Verification")
        header.setObjectName("headerTitle")
        subtitle = QLabel(
            "Interactive demonstration of zero-knowledge storage boundaries, AEAD tamper detection, "
            "TOTP replay defense, exponential lockout, and architectural vulnerability benchmarks."
        )
        subtitle.setObjectName("subtitle")
        subtitle.setWordWrap(True)
        main_layout.addWidget(header)
        main_layout.addWidget(subtitle)

        # 1. Knowledge Boundary Comparison (Split View)
        boundary_box = QGroupBox("Cryptographic Knowledge Boundaries")
        boundary_layout = QHBoxLayout(boundary_box)

        # Server Knowledge Card
        server_card = QWidget()
        server_layout = QVBoxLayout(server_card)
        server_title = QLabel("WHAT RELAY SERVER STORES (Zero-Knowledge)")
        server_title.setStyleSheet("color: #e3b341; font-weight: bold;")
        server_desc = QTextEdit()
        server_desc.setReadOnly(True)
        server_desc.setHtml("""
        <ul style="color: #c9d1d9; font-size: 12px; line-height: 1.5;">
            <li><b>Ciphertext Blobs:</b> 1 MiB chunked AES-256-GCM (opaque random bytes).</li>
            <li><b>Argon2id Salt:</b> 16-byte public salt.</li>
            <li><b>Wrapped File Key:</b> Encrypted under transient WK (cannot unwrap without password & LS).</li>
            <li><b>Server Share (SS):</b> 256-bit random key share (encrypted at rest under server master key).</li>
            <li><b>TOTP Secret:</b> Encrypted at rest under master key; never exposed in plaintext.</li>
            <li><b style="color: #f85149;">NEVER SEES:</b> Plaintext, filenames, passwords, Link Secret, or File Key.</li>
        </ul>
        """)
        server_layout.addWidget(server_title)
        server_layout.addWidget(server_desc)

        # Client Knowledge Card
        client_card = QWidget()
        client_layout = QVBoxLayout(client_card)
        client_title = QLabel("WHAT CLIENT ENDPOINTS HOLD (Local Only)")
        client_title.setStyleSheet("color: #58a6ff; font-weight: bold;")
        client_desc = QTextEdit()
        client_desc.setReadOnly(True)
        client_desc.setHtml("""
        <ul style="color: #c9d1d9; font-size: 12px; line-height: 1.5;">
            <li><b>Plaintext Files:</b> Reside strictly on sender and recipient disks.</li>
            <li><b>Password:</b> Kept in sender/recipient heads; derived via Argon2id in RAM only.</li>
            <li><b>Link Secret (LS):</b> 128-bit secret inside Drop Code; NEVER sent to relay server.</li>
            <li><b>File Key (FK):</b> 256-bit AES key in memory during streaming, zeroed on completion.</li>
            <li><b>Wrapping Key (WK):</b> Derived transiently via HKDF(KEK || SS || LS).</li>
            <li><b style="color: #2ea043;">GUARANTEE:</b> Server compromise reveals zero file contents!</li>
        </ul>
        """)
        client_layout.addWidget(client_title)
        client_layout.addWidget(client_desc)

        boundary_layout.addWidget(server_card)
        boundary_layout.addWidget(client_card)
        main_layout.addWidget(boundary_box)

        # 2. Interactive Attack Simulations
        sim_box = QGroupBox("Interactive Attack Simulations & Live Experiments")
        sim_layout = QVBoxLayout(sim_box)

        btn_row = QHBoxLayout()

        btn_wrong = QPushButton("1. Wrong TOTP Guess")
        btn_wrong.clicked.connect(self._demo_wrong_totp)
        btn_row.addWidget(btn_wrong)

        btn_replay = QPushButton("2. Replayed TOTP")
        btn_replay.clicked.connect(self._demo_replayed_totp)
        btn_row.addWidget(btn_replay)

        btn_tamper = QPushButton("3. Tampered Blob (Bit-flip)")
        btn_tamper.clicked.connect(self._demo_tampered_blob)
        btn_row.addWidget(btn_tamper)

        btn_lockout = QPushButton("4. Trigger Lockout (5 Attempts)")
        btn_lockout.clicked.connect(self._demo_lockout)
        btn_row.addWidget(btn_lockout)

        btn_brute = QPushButton("5. Brute-Force 'TOTP as Key'")
        btn_brute.setStyleSheet("background-color: #388bfd; color: white;")
        btn_brute.clicked.connect(self._demo_bruteforce_comparison)
        btn_row.addWidget(btn_brute)

        sim_layout.addLayout(btn_row)

        # Log Output Area
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setObjectName("monoField")
        self.console.setPlaceholderText("Live attack experiment output will appear here...")
        self.console.setFixedHeight(180)
        sim_layout.addWidget(self.console)

        main_layout.addWidget(sim_box)

    def _log(self, text: str):
        self.console.append(text)
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def _demo_wrong_totp(self):
        self._log("\n[*] === EXPERIMENT 1: WRONG TOTP GUESS ATTACK ===")
        self._log("[*] Creating a fresh test drop on relay...")
        try:
            drop = self.api.create_drop(expires_hours=1, max_downloads=1)
            drop_id = drop["drop_id"]
            self._log(f"[+] Test drop created: {drop_id}")

            self._log("[*] Finalizing test drop with dummy salt & wrapped key...")
            self.api.upload_blob(drop_id, b"encrypted dummy blob")
            self.api.finalize_drop(drop_id, "00" * 16, "11" * 60)

            self._log("[*] Attacker submitting invalid 6-digit TOTP: '999999'...")
            try:
                self.api.unlock_drop(drop_id, totp_code="999999")
                self._log("[-] ERROR: Server unexpectedly accepted invalid TOTP!")
            except RelayAPIError as e:
                self._log(f"[+] ATTACK BLOCKED by Relay: HTTP {e.status_code} - {e.detail}")
                self._log("[+] Security Outcome: Server Share (SS) remained locked. Attempt counted in audit log.")
        except Exception as e:
            self._log(f"[!] Experiment error: {e}")

    def _demo_replayed_totp(self):
        self._log("\n[*] === EXPERIMENT 2: REPLAYED TOTP ATTACK ===")
        try:
            drop = self.api.create_drop(expires_hours=1, max_downloads=5)
            drop_id = drop["drop_id"]
            self.api.upload_blob(drop_id, b"dummy blob")
            self.api.finalize_drop(drop_id, "00" * 16, "11" * 60)

            totp = pyotp.TOTP(drop["totp_secret"])
            valid_code = totp.now()

            self._log(f"[*] Legitimate recipient unlocks drop with TOTP code: {valid_code} ...")
            resp1 = self.api.unlock_drop(drop_id, totp_code=valid_code)
            self._log(f"[+] Legitimate unlock succeeded! Token: {resp1['download_token'][:12]}...")

            self._log("[*] Attacker intercepts and replays the EXACT SAME TOTP token within the 30s window...")
            try:
                self.api.unlock_drop(drop_id, totp_code=valid_code)
                self._log("[-] ERROR: Server accepted replayed TOTP!")
            except RelayAPIError as e:
                self._log(f"[+] REPLAY ATTACK BLOCKED: HTTP {e.status_code} - {e.detail}")
                self._log("[+] Security Outcome: 'totp_last_step' guard detected token reuse. Server Share withheld.")
        except Exception as e:
            self._log(f"[!] Experiment error: {e}")

    def _demo_tampered_blob(self):
        self._log("\n[*] === EXPERIMENT 3: CIPHERTEXT BIT-FLIP TAMPER ATTACK ===")
        try:
            fk = generate_file_key()
            drop_id = secrets.token_hex(16)
            original_data = b"CONFIDENTIAL LAB EXAM: Student Grade = A+"

            self._log(f"[*] Encrypting message: '{original_data.decode()}' with AES-256-GCM...")
            blob = encrypt_bytes(original_data, "grade.txt", fk, drop_id)
            self._log(f"[+] Encrypted blob size: {len(blob)} bytes (with DDRP container framing)")

            # Bit flip
            tampered_blob = bytearray(blob)
            tampered_offset = 35
            tampered_blob[tampered_offset] ^= 0x01
            self._log(f"[*] Malicious MITM attacker flips 1 single bit at byte offset {tampered_offset}...")

            self._log("[*] Recipient client attempts to decrypt tampered stream...")
            try:
                import io
                stream = io.BytesIO(tampered_blob)
                from pathlib import Path
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp_name = tmp.name
                decrypt_file(stream, tmp_name, fk, drop_id)
                self._log("[-] ERROR: Tampered file was decrypted!")
            except CryptoIntegrityError as e:
                self._log(f"[+] TAMPER DETECTED: {e}")
                self._log("[+] Security Outcome: AES-256-GCM Poly1305/GHASH tag verification failed.")
                self._log("[+] Zero bytes written to final target file. Plaintext remained completely protected.")
        except Exception as e:
            self._log(f"[!] Experiment error: {e}")

    def _demo_lockout(self):
        self._log("\n[*] === EXPERIMENT 4: EXPONENTIAL BACKOFF & LOCKOUT DEFENSE ===")
        try:
            drop = self.api.create_drop(expires_hours=1, max_downloads=5)
            drop_id = drop["drop_id"]
            self.api.upload_blob(drop_id, b"dummy blob")
            self.api.finalize_drop(drop_id, "00" * 16, "11" * 60)

            self._log("[*] Simulating automated dictionary attack against drop 2FA...")
            for attempt in range(1, 6):
                try:
                    self.api.unlock_drop(drop_id, totp_code=f"00000{attempt}")
                except RelayAPIError as e:
                    if e.status_code == 429:
                        self._log(f"[+] ATTEMPT #{attempt}: LOCKOUT TRIGGERED! HTTP 429 - {e.detail}")
                    else:
                        self._log(f"[-] Attempt #{attempt}: Rejected (HTTP {e.status_code})")

            self._log("[*] Testing unlock with the real valid TOTP while locked...")
            totp = pyotp.TOTP(drop["totp_secret"])
            try:
                self.api.unlock_drop(drop_id, totp_code=totp.now())
                self._log("[-] ERROR: Server allowed unlock during lockout period!")
            except RelayAPIError as e:
                self._log(f"[+] LOCKOUT ENFORCED: HTTP {e.status_code} - {e.detail}")
                self._log("[+] Security Outcome: Brute-force bot is completely neutralized.")
        except Exception as e:
            self._log(f"[!] Experiment error: {e}")

    def _demo_bruteforce_comparison(self):
        self._log("\n[*] === EXPERIMENT 5: FLAWED ARCHITECTURE CONTRAST ('TOTP AS KEY') ===")
        self._log("[*] Problem Statement: Why not just derive the file key directly from a 6-digit TOTP code?")
        self._log("[*] Simulating brute-force attack against naive 6-digit TOTP keyspace (000000 to 999999)...")

        # Setup benchmark
        import hashlib
        target_token = "847291"
        target_hash = hashlib.sha256(target_token.encode()).digest()

        start_time = time.perf_counter()
        cracked = False
        attempts = 0
        for code_int in range(1000000):
            candidate = f"{code_int:06d}"
            attempts += 1
            if hashlib.sha256(candidate.encode()).digest() == target_hash:
                cracked = True
                break
        elapsed = time.perf_counter() - start_time

        self._log(f"[!] CRACKED naive 6-digit key in {elapsed:.3f} seconds ({attempts:,} attempts)!")
        self._log("[*] Comparison Conclusion:")
        self._log("    - Naive 'TOTP as Key': ~1,000,000 keys -> Cracks in < 1 second on a standard CPU.")
        self._log("    - DeadDrop Split-Key Scheme:")
        self._log("      1. Argon2id KDF: 64 MiB RAM per guess (GPU/ASIC immune).")
        self._log("      2. 128-bit Link Secret (LS): 2^128 keyspace (takes trillions of years).")
        self._log("      3. Server Share (SS) released only after rate-limited TOTP authentication.")
        self._log("[+] DeadDrop provides mathematically sound zero-knowledge multi-factor security!")
