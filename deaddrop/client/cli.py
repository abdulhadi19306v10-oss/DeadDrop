"""Command Line Interface for DeadDrop.

Supports:
- deaddrop send <file> [--password <pwd>] [--expires <hrs>] [--downloads <n>] [--server <url>] [--no-qr]
- deaddrop receive <drop_code> [--password <pwd>] [--totp <code>] [--backup <code>] [--out <dest>] [--server <url>]
- deaddrop list [--server <url>]
- deaddrop burn <drop_id> [--server <url>]
- deaddrop audit <drop_id> [--server <url>]
- deaddrop server [--host <host>] [--port <port>] [--reload]
- deaddrop gui [--server <url>]
- deaddrop lab
"""

import argparse
import datetime
import getpass
import io
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional

import pyotp
import qrcode

from deaddrop.client.api import DeadDropClient, RelayAPIError
from deaddrop.client.crypto_core import (
    CryptoError,
    CryptoIntegrityError,
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
)
from deaddrop.client.ui.widgets import generate_passphrase

# Ensure UTF-8 output in Windows consoles for box characters and QR codes
try:
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BANNER = r"""
 ██████╗ ███████╗ █████╗ ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ 
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
 ██║  ██║█████╗  ███████║██║  ██║██║  ██║██████╔╝██║   ██║██████╔╝
 ██║  ██║██╔══╝  ██╔══██║██║  ██║██║  ██║██╔══██╗██║   ██║██╔═══╝ 
 ██████╔╝███████╗██║  ██║██████╔╝██████╔╝██║  ██║╚██████╔╝██║     
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     
    ✦ Zero-Knowledge 2FA Secure File Exchange [Kali Linux / Desktop] ✦
"""


def _print_banner():
    print(BANNER)


def cmd_send(args):
    """CLI send command: Encrypts file locally and uploads to relay."""
    _print_banner()
    file_path = Path(args.file)
    if not file_path.exists() or not file_path.is_file():
        print(f"[!] Error: File '{file_path}' does not exist or is not a file.")
        sys.exit(1)

    password = args.password
    if not password:
        suggested = generate_passphrase(4)
        print(f"[*] Suggested secure Diceware passphrase: {suggested}")
        choice = input(f"Use suggested passphrase? [Y/n]: ").strip().lower()
        if choice in ("", "y", "yes"):
            password = suggested
        else:
            password = getpass.getpass("Enter encryption password: ")
            confirm = getpass.getpass("Confirm encryption password: ")
            if password != confirm:
                print("[!] Error: Passwords do not match.")
                sys.exit(1)

    client = DeadDropClient(base_url=args.server)
    print(f"[*] Connecting to relay at {args.server} ...")

    try:
        drop_data = client.create_drop(expires_hours=args.expires, max_downloads=args.downloads)
    except RelayAPIError as e:
        print(f"[!] Relay rejection: {e.detail}")
        sys.exit(1)

    drop_id = drop_data["drop_id"]
    ss = bytes.fromhex(drop_data["ss_hex"])
    totp_secret = drop_data["totp_secret"]
    totp_uri = drop_data["totp_uri"]
    backup_codes = drop_data["backup_codes"]

    print("[*] Deriving cryptographic keys (Argon2id + HKDF-SHA256)...")
    salt = generate_salt()
    ls = generate_link_secret()
    fk = generate_file_key()

    kek = derive_kek(password, salt)
    wk = derive_wk(kek, ss, ls, drop_id)
    wrapped_fk = wrap_fk(wk, fk, drop_id)

    print(f"[*] Encrypting '{file_path.name}' ({file_path.stat().st_size} bytes) in 1 MiB chunks (AES-256-GCM)...")
    blob_stream = io.BytesIO()

    def prog(curr, tot):
        pct = int((curr / tot) * 100) if tot > 0 else 100
        print(f"\r    [Progress] Encrypting: {curr // 1024} KB / {tot // 1024} KB ({pct}%)", end="", flush=True)

    encrypt_file(file_path, blob_stream, fk, drop_id, progress_callback=prog)
    print()

    blob_bytes = blob_stream.getvalue()
    print(f"[*] Uploading encrypted blob ({len(blob_bytes)} bytes)...")
    client.upload_blob(drop_id, blob_bytes)

    print("[*] Finalizing drop policies on relay...")
    client.finalize_drop(drop_id, salt.hex(), wrapped_fk.hex())

    drop_code = format_drop_code(drop_id, ls)

    print("\n" + "=" * 68)
    print("                 ✦ DEADDROP SHARE PACKAGE ✦                 ")
    print("=" * 68)
    print(f"Drop Code    : {drop_code}")
    print(f"Password     : {password}")
    print(f"TOTP Secret  : {totp_secret}")
    print(f"TOTP URI     : {totp_uri}")
    print("Backup Codes :")
    for code in backup_codes:
        print(f"  • {code}")
    print("=" * 68)

    # Print ASCII QR code in terminal
    if not args.no_qr:
        print("\nScan this QR code with Google Authenticator:")
        try:
            qr = qrcode.QRCode()
            qr.add_data(totp_uri)
            qr.print_ascii(invert=True)
        except Exception:
            print("  (Terminal does not support ASCII QR rendering; use manual TOTP secret above)")

    print("\n[!] SECURITY ADVISORY: Send Drop Code and Password over SEPARATE communication channels!\n")


def cmd_receive(args):
    """CLI receive command: Unlocks, downloads, and decrypts a file."""
    _print_banner()
    drop_code = args.drop_code
    try:
        drop_id, ls = parse_drop_code(drop_code)
    except Exception as e:
        print(f"[!] Invalid drop code: {e}")
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Enter drop decryption password: ")

    totp_code = args.totp
    backup_code = args.backup

    if not totp_code and not backup_code:
        totp_code = input("Enter 6-digit Google Authenticator code (or press Enter to use backup code): ").strip()
        if not totp_code:
            backup_code = input("Enter single-use backup code: ").strip()

    client = DeadDropClient(base_url=args.server)
    print(f"[*] Authenticating with relay ({args.server})...")

    try:
        unlock_resp = client.unlock_drop(drop_id, totp_code=totp_code, backup_code=backup_code)
    except RelayAPIError as e:
        print(f"[!] Unlock rejected by relay: {e.detail}")
        sys.exit(1)

    ss = bytes.fromhex(unlock_resp["ss_hex"])
    salt = bytes.fromhex(unlock_resp["salt_hex"])
    wrapped_fk = bytes.fromhex(unlock_resp["wrapped_fk_hex"])
    token = unlock_resp["download_token"]

    print("[*] Deriving KEK (Argon2id) & unwrapping File Key (AES-256-GCM)...")
    kek = derive_kek(password, salt)
    wk = derive_wk(kek, ss, ls, drop_id)

    try:
        fk = unwrap_fk(wk, wrapped_fk, drop_id)
    except CryptoIntegrityError as e:
        print(f"[!] Decryption failure: Incorrect password or corrupted drop.")
        sys.exit(1)

    print("[*] Downloading encrypted ciphertext blob...")
    blob_bytes = client.download_blob(drop_id, token)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    temp_dest = out_dir / f"download_{drop_id}.tmp"

    print("[*] Verifying AEAD chunk authentication tags and writing plaintext...")
    try:
        blob_stream = io.BytesIO(blob_bytes)
        meta = decrypt_file(blob_stream, temp_dest, fk, drop_id)
        original_name = meta.get("name", f"deaddrop_{drop_id}.bin")
        final_dest = out_dir / original_name

        counter = 1
        stem = final_dest.stem
        suffix = final_dest.suffix
        while final_dest.exists():
            final_dest = out_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        temp_dest.replace(final_dest)

        import hashlib
        file_sha256 = hashlib.sha256(final_dest.read_bytes()).hexdigest()

        print("\n" + "=" * 68)
        print("                 ✦ FILE DECRYPTED SUCCESSFULLY ✦            ")
        print("=" * 68)
        print(f"Filename    : {final_dest.name}")
        print(f"Size        : {meta.get('size')} bytes")
        print(f"MIME Type   : {meta.get('mime')}")
        print(f"SHA-256     : {file_sha256}")
        print(f"Saved Path  : {final_dest.resolve()}")
        print("=" * 68 + "\n")

    except CryptoError as e:
        print(f"[!] Tamper / Integrity verification failed: {e}")
        if temp_dest.exists():
            temp_dest.unlink()
        sys.exit(1)


def cmd_list(args):
    """CLI list active drops."""
    _print_banner()
    client = DeadDropClient(base_url=args.server)
    try:
        drops = client.list_drops()
    except RelayAPIError as e:
        print(f"[!] Failed to fetch drops: {e.detail}")
        sys.exit(1)

    if not drops:
        print("[*] No active drops found.")
        return

    print(f"{'Drop ID':<36} {'Status':<10} {'Downloads':<12} {'Expires At (UTC)'}")
    print("-" * 76)
    for d in drops:
        exp_dt = datetime.datetime.fromtimestamp(d["expires_at"], tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")
        print(f"{d['id']:<36} {d['status'].upper():<10} {d['downloads']}/{d['max_downloads']:<12} {exp_dt}")
    print("-" * 76)


def cmd_burn(args):
    """CLI burn drop."""
    _print_banner()
    client = DeadDropClient(base_url=args.server)
    try:
        res = client.burn_drop(args.drop_id)
        print(f"[+] Success: Drop {args.drop_id} was securely shredded: {res}")
    except RelayAPIError as e:
        print(f"[!] Burn failed: {e.detail}")
        sys.exit(1)


def cmd_audit(args):
    """CLI view audit log."""
    _print_banner()
    client = DeadDropClient(base_url=args.server)
    try:
        logs = client.get_audit(args.drop_id)
    except RelayAPIError as e:
        print(f"[!] Failed to fetch audit trail: {e.detail}")
        sys.exit(1)

    print(f"[*] Immutable Audit Trail for Drop: {args.drop_id}")
    print(f"{'Timestamp (UTC)':<22} {'Event':<18} {'Outcome':<26} {'Salted IP Hash'}")
    print("-" * 80)
    for item in logs:
        dt = datetime.datetime.fromtimestamp(item["timestamp"], tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{dt:<22} {item['event']:<18} {item['outcome']:<26} {item['ip_hash']}")
    print("-" * 80)


def cmd_server(args):
    """CLI start relay server."""
    _print_banner()
    import uvicorn
    print(f"[*] Starting DeadDrop Relay Server on http://{args.host}:{args.port} ...")
    uvicorn.run("deaddrop.server.main:app", host=args.host, port=args.port, reload=args.reload)


def cmd_gui(args):
    """CLI launch PySide6 desktop application."""
    _print_banner()
    from deaddrop.client.app import main as run_gui
    os.environ["DEADDROP_SERVER_URL"] = args.server
    print("[*] Launching DeadDrop Desktop GUI (Kali Linux Dark Theme)...")
    run_gui()


def cmd_lab(args):
    """CLI run security lab simulations."""
    _print_banner()
    print("=" * 68)
    print("         ✦ DEADDROP SECURITY LAB: CLI ATTACK SIMULATIONS ✦         ")
    print("=" * 68)

    client = DeadDropClient(base_url=args.server)
    server_online = False
    try:
        import httpx
        with httpx.Client(timeout=2.0) as hc:
            r = hc.get(f"{client.base_url}/health")
            if r.status_code == 200:
                server_online = True
    except Exception:
        server_online = False

    # 1. Bit-Flip Ciphertext Tamper (Local cryptographic test)
    print("\n[+] SIMULATION 1: Ciphertext Bit-Flip Tampering Attack (AES-256-GCM AEAD)")
    try:
        fk = generate_file_key()
        drop_id = secrets.token_hex(16)
        data = b"TOP SECRET EXAM SOLUTION 2026"
        blob = encrypt_bytes(data, "test.txt", fk, drop_id)

        tampered = bytearray(blob)
        tampered[35] ^= 0x01

        temp_out = Path("tamper_test.tmp")
        try:
            decrypt_file(io.BytesIO(tampered), temp_out, fk, drop_id)
            print("    [-] ERROR: Tampered ciphertext was decrypted!")
        except CryptoIntegrityError as e:
            print(f"    [✔] PASSED: GCM Authentication tag failed: {e}")
            print(f"    [✔] PASSED: Zero bytes emitted (temp file removed: {not temp_out.exists()})")
        finally:
            if temp_out.exists():
                temp_out.unlink()
    except Exception as e:
        print(f"    [!] Error: {e}")

    # 2. Brute-Force Comparison
    print("\n[+] SIMULATION 2: Naive 'TOTP-as-Key' vs DeadDrop Split-Key Benchmark")
    import hashlib
    target_token = "847291"
    target_hash = hashlib.sha256(target_token.encode()).digest()
    start_time = time.perf_counter()
    attempts = 0
    for code_int in range(1000000):
        attempts += 1
        if hashlib.sha256(f"{code_int:06d}".encode()).digest() == target_hash:
            break
    elapsed = time.perf_counter() - start_time
    print(f"    [✔] Naive 6-digit TOTP key cracked in {elapsed:.3f}s ({attempts:,} attempts)!")
    print("    [✔] DeadDrop Defense: Uses Argon2id (64 MiB RAM per guess) + 128-bit Link Secret.")

    if not server_online:
        print(f"\n[!] Note: Relay server is not running on {args.server}.")
        print("    Run 'deaddrop server' in another terminal to test live network attack simulations.")
    else:
        # 3. Wrong TOTP
        print("\n[+] SIMULATION 3: Wrong TOTP Guessing Attack (Relay)")
        try:
            drop = client.create_drop(expires_hours=1, max_downloads=1)
            client.upload_blob(drop["drop_id"], b"dummy")
            client.finalize_drop(drop["drop_id"], "00" * 16, "11" * 60)
            try:
                client.unlock_drop(drop["drop_id"], totp_code="999999")
                print("    [-] ERROR: Server accepted wrong code!")
            except RelayAPIError as e:
                print(f"    [✔] PASSED: Server rejected invalid TOTP: HTTP {e.status_code} ({e.detail})")
        except Exception as e:
            print(f"    [!] Error: {e}")

        # 4. Replayed TOTP
        print("\n[+] SIMULATION 4: TOTP Token Replay Attack (Relay)")
        try:
            drop = client.create_drop(expires_hours=1, max_downloads=5)
            client.upload_blob(drop["drop_id"], b"dummy")
            client.finalize_drop(drop["drop_id"], "00" * 16, "11" * 60)
            totp = pyotp.TOTP(drop["totp_secret"])
            code = totp.now()

            res1 = client.unlock_drop(drop["drop_id"], totp_code=code)
            print(f"    [*] Legitimate unlock succeeded (Token: {res1['download_token'][:10]}...)")
            try:
                client.unlock_drop(drop["drop_id"], totp_code=code)
                print("    [-] ERROR: Replay accepted!")
            except RelayAPIError as e:
                print(f"    [✔] PASSED: Replay blocked by time-step guard: HTTP {e.status_code} ({e.detail})")
        except Exception as e:
            print(f"    [!] Error: {e}")

        # 5. Lockout
        print("\n[+] SIMULATION 5: 5-Attempt Exponential Lockout Defense (Relay)")
        try:
            drop = client.create_drop(expires_hours=1, max_downloads=5)
            client.upload_blob(drop["drop_id"], b"dummy")
            client.finalize_drop(drop["drop_id"], "00" * 16, "11" * 60)
            for attempt in range(1, 6):
                try:
                    client.unlock_drop(drop["drop_id"], totp_code=f"00000{attempt}")
                except RelayAPIError as e:
                    if e.status_code == 429:
                        print(f"    [✔] Attempt #{attempt}: LOCKOUT TRIGGERED! HTTP 429 ({e.detail})")
                    else:
                        print(f"    [*] Attempt #{attempt}: Rejected (HTTP {e.status_code})")
        except Exception as e:
            print(f"    [!] Error: {e}")

    print("\n" + "=" * 68)
    print("         ✦ ALL SECURITY SIMULATIONS COMPLETED SUCCESSFULLY ✦         ")
    print("=" * 68 + "\n")


def main():
    parser = argparse.ArgumentParser(
        prog="deaddrop",
        description="DeadDrop: Zero-Knowledge 2FA Secure File Exchange",
    )
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Relay server URL (default: http://127.0.0.1:8000)")
    subparsers = parser.add_subparsers(dest="command")

    # send
    p_send = subparsers.add_parser("send", help="Encrypt and upload a file")
    p_send.add_argument("file", help="Path to file to encrypt and send")
    p_send.add_argument("--password", "-p", help="Passphrase for Argon2id key derivation")
    p_send.add_argument("--expires", "-e", type=int, default=24, help="Expiration in hours (default: 24)")
    p_send.add_argument("--downloads", "-d", type=int, default=1, help="Max downloads (default: 1, burn after read)")
    p_send.add_argument("--no-qr", action="store_true", help="Do not render ASCII QR code in terminal")

    # receive
    p_rec = subparsers.add_parser("receive", help="Unlock, download, and decrypt a file")
    p_rec.add_argument("drop_code", help="Drop code (DD1-<drop_id>-<link_secret>)")
    p_rec.add_argument("--password", "-p", help="Decryption password")
    p_rec.add_argument("--totp", "-t", help="6-digit Google Authenticator TOTP code")
    p_rec.add_argument("--backup", "-b", help="Single-use backup code")
    p_rec.add_argument("--out", "-o", default=".", help="Output directory (default: current directory)")

    # list
    subparsers.add_parser("list", help="List active drops on relay")

    # burn
    p_burn = subparsers.add_parser("burn", help="Securely shred a drop")
    p_burn.add_argument("drop_id", help="Drop ID to burn")

    # audit
    p_audit = subparsers.add_parser("audit", help="View immutable audit log for a drop")
    p_audit.add_argument("drop_id", help="Drop ID")

    # server
    p_srv = subparsers.add_parser("server", help="Launch the DeadDrop Relay Server")
    p_srv.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    p_srv.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    p_srv.add_argument("--reload", action="store_true", help="Enable reload")

    # gui
    subparsers.add_parser("gui", help="Launch the DeadDrop PySide6 Desktop GUI")

    # lab
    subparsers.add_parser("lab", help="Run interactive security lab attack benchmarks")

    args = parser.parse_args()
    if args.command == "send":
        cmd_send(args)
    elif args.command == "receive":
        cmd_receive(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "burn":
        cmd_burn(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "server":
        cmd_server(args)
    elif args.command == "gui":
        cmd_gui(args)
    elif args.command == "lab":
        cmd_lab(args)
    else:
        _print_banner()
        parser.print_help()


if __name__ == "__main__":
    main()
