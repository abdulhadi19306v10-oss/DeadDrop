"""Command Line Interface for DeadDrop."""

import argparse
import getpass
import io
import sys
import time
from pathlib import Path
import pyotp

from deaddrop.client.api import DeadDropClient, RelayAPIError
from deaddrop.client.crypto_core import (
    CryptoError,
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
)


def cmd_send(args):
    """CLI send command."""
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"[!] Error: File '{file_path}' does not exist.")
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm encryption password: ")
        if password != confirm:
            print("[!] Error: Passwords do not match.")
            sys.exit(1)

    client = DeadDropClient(base_url=args.server)
    print(f"[*] Requesting drop creation from relay: {args.server} ...")

    try:
        drop_data = client.create_drop(expires_hours=args.expires, max_downloads=args.downloads)
    except RelayAPIError as e:
        print(f"[!] Relay error: {e}")
        sys.exit(1)

    drop_id = drop_data["drop_id"]
    ss = bytes.fromhex(drop_data["ss_hex"])
    totp_secret = drop_data["totp_secret"]
    totp_uri = drop_data["totp_uri"]
    backup_codes = drop_data["backup_codes"]

    print("[*] Deriving cryptographic keys (Argon2id + HKDF)...")
    salt = generate_salt()
    ls = generate_link_secret()
    fk = generate_file_key()

    kek = derive_kek(password, salt)
    wk = derive_wk(kek, ss, ls, drop_id)
    wrapped_fk = wrap_fk(wk, fk, drop_id)

    print(f"[*] Encrypting '{file_path.name}' into DDRP chunks (AES-256-GCM)...")
    blob_stream = io.BytesIO()
    encrypt_file(file_path, blob_stream, fk, drop_id)
    blob_bytes = blob_stream.getvalue()

    print(f"[*] Uploading ciphertext blob ({len(blob_bytes)} bytes)...")
    client.upload_blob(drop_id, blob_bytes)

    print("[*] Finalizing drop on relay...")
    client.finalize_drop(drop_id, salt.hex(), wrapped_fk.hex())

    drop_code = format_drop_code(drop_id, ls)

    print("\n" + "=" * 60)
    print("           DEADDROP SHARE PACKAGE (SAVE CAREFULLY)           ")
    print("=" * 60)
    print(f"Drop Code    : {drop_code}")
    print(f"Password     : {password}")
    print(f"TOTP Secret  : {totp_secret}")
    print(f"TOTP URI     : {totp_uri}")
    print("Backup Codes :")
    for code in backup_codes:
        print(f"  - {code}")
    print("=" * 60)
    print("Send Drop Code and Password over SEPARATE communication channels!\n")


def cmd_receive(args):
    """CLI receive command."""
    drop_code = args.drop_code
    try:
        drop_id, ls = parse_drop_code(drop_code)
    except Exception as e:
        print(f"[!] Invalid drop code: {e}")
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Enter drop password: ")

    totp_code = args.totp
    backup_code = args.backup

    if not totp_code and not backup_code:
        totp_code = input("Enter 6-digit Google Authenticator TOTP (or press Enter for backup code): ").strip()
        if not totp_code:
            backup_code = input("Enter single-use backup code: ").strip()

    client = DeadDropClient(base_url=args.server)
    print(f"[*] Unlocking drop {drop_id} with relay...")

    try:
        unlock_resp = client.unlock_drop(drop_id, totp_code=totp_code, backup_code=backup_code)
    except RelayAPIError as e:
        print(f"[!] Unlock failed: {e.detail}")
        sys.exit(1)

    ss = bytes.fromhex(unlock_resp["ss_hex"])
    salt = bytes.fromhex(unlock_resp["salt_hex"])
    wrapped_fk = bytes.fromhex(unlock_resp["wrapped_fk_hex"])
    token = unlock_resp["download_token"]

    print("[*] Unwrapping File Encryption Key (FK)...")
    kek = derive_kek(password, salt)
    wk = derive_wk(kek, ss, ls, drop_id)

    try:
        fk = unwrap_fk(wk, wrapped_fk, drop_id)
    except CryptoError as e:
        print(f"[!] Local Decryption Error: {e} (Check password!)")
        sys.exit(1)

    print("[*] Downloading encrypted ciphertext blob...")
    blob_bytes = client.download_blob(drop_id, token)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    temp_dest = out_dir / f"download_{drop_id}.tmp"

    print("[*] Verifying integrity and decrypting file...")
    try:
        blob_stream = io.BytesIO(blob_bytes)
        meta = decrypt_file(blob_stream, temp_dest, fk, drop_id)
        final_dest = out_dir / meta.get("name", f"deaddrop_{drop_id}.bin")
        if final_dest.exists():
            final_dest = out_dir / f"{final_dest.stem}_{int(time.time())}{final_dest.suffix}"
        temp_dest.replace(final_dest)
        print(f"[+] SUCCESS: Decrypted '{final_dest.name}' ({meta.get('size')} bytes)")
        print(f"[+] Saved to: {final_dest.resolve()}")
    except CryptoError as e:
        print(f"[!] Decryption / Tamper verification failed: {e}")
        if temp_dest.exists():
            temp_dest.unlink()
        sys.exit(1)


def cmd_list(args):
    """CLI list active drops."""
    client = DeadDropClient(base_url=args.server)
    drops = client.list_drops()
    print(f"{'Drop ID':<34} {'Status':<10} {'Downloads':<12} {'Created'}")
    print("-" * 75)
    for d in drops:
        print(f"{d['id']:<34} {d['status']:<10} {d['downloads']}/{d['max_downloads']:<10} {d['created_at']}")


def cmd_burn(args):
    """CLI burn drop."""
    client = DeadDropClient(base_url=args.server)
    res = client.burn_drop(args.drop_id)
    print(f"[+] Drop {args.drop_id} securely burned: {res}")


def main():
    parser = argparse.ArgumentParser(description="DeadDrop Secure File Exchange CLI")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Relay server URL")
    subparsers = parser.add_subparsers(dest="command")

    # Send
    send_p = subparsers.add_parser("send", help="Encrypt and upload a file")
    send_p.add_argument("file", help="File to send")
    send_p.add_argument("--password", help="Password for encryption")
    send_p.add_argument("--expires", type=int, default=24, help="Expiration in hours (default 24)")
    send_p.add_argument("--downloads", type=int, default=1, help="Max downloads (default 1)")

    # Receive
    rec_p = subparsers.add_parser("receive", help="Unlock and download a file")
    rec_p.add_argument("drop_code", help="Drop code (DD1-...)")
    rec_p.add_argument("--password", help="Password for decryption")
    rec_p.add_argument("--totp", help="6-digit TOTP code")
    rec_p.add_argument("--backup", help="Single-use backup code")
    rec_p.add_argument("--out", default=".", help="Output directory")

    # List
    subparsers.add_parser("list", help="List active drops")

    # Burn
    burn_p = subparsers.add_parser("burn", help="Burn and shred a drop")
    burn_p.add_argument("drop_id", help="Drop ID to shred")

    args = parser.parse_args()
    if args.command == "send":
        cmd_send(args)
    elif args.command == "receive":
        cmd_receive(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "burn":
        cmd_burn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
