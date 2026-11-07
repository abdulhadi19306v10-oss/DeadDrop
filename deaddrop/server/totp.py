"""TOTP generation, verification, and replay protection."""

import secrets
import time
from typing import List, Tuple
import pyotp


def generate_totp_secret() -> str:
    """Generates a random base32 TOTP secret (160 bits / 20 bytes standard)."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, drop_id: str, issuer: str = "DeadDrop") -> str:
    """Generates otpauth:// URI for scanning with Google Authenticator."""
    totp = pyotp.TOTP(secret, interval=30)
    label = f"Drop-{drop_id[:8]}"
    return totp.provisioning_uri(name=label, issuer_name=issuer)


def generate_backup_codes(count: int = 5) -> List[str]:
    """Generates human-friendly 8-character single-use backup codes (e.g. ABCD-1234)."""
    codes = []
    chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # Avoid 0, 1, I, O ambiguity
    for _ in range(count):
        part1 = "".join(secrets.choice(chars) for _ in range(4))
        part2 = "".join(secrets.choice(chars) for _ in range(4))
        codes.append(f"{part1}-{part2}")
    return codes


def verify_totp(secret: str, code: str, last_step: int, current_time: int = None) -> Tuple[bool, int, str]:
    """Verifies a 6-digit TOTP token with replay protection.

    Allows valid_window=1 (current step +/- 1 step).
    Rejects any code whose corresponding time-step is <= last_step.

    Returns:
    (is_valid, new_last_step, message)
    """
    if current_time is None:
        current_time = int(time.time())

    clean_code = code.strip().replace(" ", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False, last_step, "Invalid code format (must be 6 digits)."

    totp = pyotp.TOTP(secret, interval=30)
    current_step = current_time // 30

    # Test steps: current, -1, +1
    for step_offset in (0, -1, 1):
        step = current_step + step_offset
        step_time = step * 30
        expected = totp.at(step_time)
        if clean_code == expected:
            # Replay check: step must be strictly greater than last_step used
            if step <= last_step:
                return False, last_step, "TOTP token replay detected. Please wait for the next 30-second token."
            return True, step, "Valid TOTP"

    return False, last_step, "Incorrect TOTP code."
