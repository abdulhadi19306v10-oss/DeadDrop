"""Rate limiting, failed attempt tracking, and exponential lockout."""

import time
from typing import Tuple
from deaddrop.server.config import MAX_FAILED_ATTEMPTS, BASE_LOCKOUT_SECONDS


def check_lockout(locked_until: int, current_time: int = None) -> Tuple[bool, int]:
    """Checks if a drop is currently locked out.

    Returns:
    (is_locked, remaining_seconds)
    """
    if current_time is None:
        current_time = int(time.time())

    if locked_until > current_time:
        return True, locked_until - current_time
    return False, 0


def record_failed_attempt(
    current_failed: int,
    current_time: int = None,
) -> Tuple[int, int, int]:
    """Increments failed attempt count and applies exponential lockout if threshold reached.

    Threshold: 5 failed attempts -> 15 min lock (doubles on consecutive failures).

    Returns:
    (new_failed_count, new_locked_until, lock_duration_applied)
    """
    if current_time is None:
        current_time = int(time.time())

    new_count = current_failed + 1
    new_locked_until = 0
    lock_duration = 0

    if new_count >= MAX_FAILED_ATTEMPTS:
        # Consecutive failed attempts beyond threshold exponentially scale
        scale_exponent = min(new_count - MAX_FAILED_ATTEMPTS, 6)
        lock_duration = BASE_LOCKOUT_SECONDS * (2 ** scale_exponent)
        new_locked_until = current_time + lock_duration

    return new_count, new_locked_until, lock_duration
