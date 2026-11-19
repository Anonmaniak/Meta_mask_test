"""
Dedicated Admin Console login (`/Admin456`).

Security properties:
- Credentials live ONLY in backend environment variables (`ADMIN_LOGIN_ID`, `ADMIN_LOGIN_PASSWORD`);
  they are never sent to or bundled in the frontend. If either is unset, login is disabled (fail closed).
- Constant-time comparison (`hmac.compare_digest` over SHA-256 digests); BOTH id and password are always
  evaluated so response timing never reveals which field was wrong.
- Credential strength policy (fail closed): login stays DISABLED while the configured ID/password are weak
  (see `credential_problems`). A weak password is the easiest way into an admin console, so the server refuses
  to accept it instead of merely warning.
- Brute-force protection: per-client-IP failure counters with temporary lockout, a fixed delay on every failed
  attempt, and a cap on simultaneous login attempts. There is deliberately NO global lockout: a global lockout
  would let any stranger lock the real admin out just by failing logins on purpose.
  Generic error message only ("Invalid credentials").
- Sessions are 256-bit random bearer tokens held server-side in memory as SHA-256 hashes, with an
  absolute expiry and an idle timeout; logout revokes immediately. No SQL is used by this module.
- Secrets are never logged.
"""

import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("admin_auth")

SESSION_ABSOLUTE_TTL_SEC = 4 * 3600
SESSION_IDLE_TTL_SEC = 30 * 60
MAX_ACTIVE_SESSIONS = 20

MAX_FAILURES_PER_IP = 5
IP_LOCKOUT_SEC = 15 * 60
IP_FAILURE_WINDOW_SEC = 15 * 60
FAILED_ATTEMPT_DELAY_SEC = 0.6
# At most this many login attempts are evaluated at the same time. Excess attempts get an immediate 429, so
# an attacker spraying logins can neither lock the real admin out nor tie up the server's worker threads.
MAX_CONCURRENT_ATTEMPTS = 4

# Credential strength policy
MIN_LOGIN_ID_LEN = 8
MIN_PASSWORD_LEN = 14
MIN_PASSWORD_DISTINCT_CHARS = 8
PASSPHRASE_LEN = 20  # long passphrases are accepted even without mixed character classes
_COMMON_FRAGMENTS = (
    "password", "passw0rd", "qwerty", "123456", "letmein", "welcome",
    "changeme", "iloveyou", "admin123", "abc123", "000000", "111111",
)

_lock = threading.Lock()
# token_hash -> (created_monotonic, last_seen_monotonic)
_sessions: Dict[str, Tuple[float, float]] = {}
# ip_hash -> list of failure timestamps
_ip_failures: Dict[str, list] = {}
_ip_locked_until: Dict[str, float] = {}
_attempt_slots = threading.BoundedSemaphore(MAX_CONCURRENT_ATTEMPTS)


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _ip_key(client_ip: str) -> str:
    return hashlib.sha256(("admin-login:" + (client_ip or "unknown")).encode("utf-8")).hexdigest()


def _configured_raw() -> Tuple[str, str]:
    return (os.getenv("ADMIN_LOGIN_ID") or "").strip(), (os.getenv("ADMIN_LOGIN_PASSWORD") or "")


def credential_problems(login_id: Optional[str] = None, password: Optional[str] = None) -> List[str]:
    """Why the configured (or given) admin credentials are too weak. Never includes the values themselves."""
    if login_id is None or password is None:
        login_id, password = _configured_raw()
    problems: List[str] = []
    if not login_id or not password:
        return ["ADMIN_LOGIN_ID / ADMIN_LOGIN_PASSWORD are not both set"]
    if len(login_id) < MIN_LOGIN_ID_LEN:
        problems.append(f"ADMIN_LOGIN_ID is shorter than {MIN_LOGIN_ID_LEN} characters")
    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"ADMIN_LOGIN_PASSWORD is shorter than {MIN_PASSWORD_LEN} characters")
    classes = sum(
        bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    if classes < 3 and len(password) < PASSPHRASE_LEN:
        problems.append("ADMIN_LOGIN_PASSWORD needs at least 3 of: lowercase, UPPERCASE, digits, symbols (or 20+ characters)")
    if len(set(password)) < MIN_PASSWORD_DISTINCT_CHARS:
        problems.append(f"ADMIN_LOGIN_PASSWORD uses fewer than {MIN_PASSWORD_DISTINCT_CHARS} different characters")
    low = password.lower()
    if login_id and login_id.lower() in low:
        problems.append("ADMIN_LOGIN_PASSWORD contains the login ID")
    if any(frag in low for frag in _COMMON_FRAGMENTS):
        problems.append("ADMIN_LOGIN_PASSWORD contains a very common password pattern")
    return problems


def credentials_configured() -> bool:
    """True only when both values are set AND meet the strength policy (fail closed)."""
    return not credential_problems()


def _check_credentials(login_id: str, password: str) -> bool:
    expected_id = (os.getenv("ADMIN_LOGIN_ID") or "").strip()
    expected_pw = os.getenv("ADMIN_LOGIN_PASSWORD") or ""
    if not expected_id or not expected_pw:
        return False
    id_ok = hmac.compare_digest(_digest(login_id), _digest(expected_id))
    pw_ok = hmac.compare_digest(_digest(password), _digest(expected_pw))
    return bool(id_ok & pw_ok)


def _purge_expired(now: float) -> None:
    dead = [
        h
        for h, (created, last_seen) in _sessions.items()
        if now - created > SESSION_ABSOLUTE_TTL_SEC or now - last_seen > SESSION_IDLE_TTL_SEC
    ]
    for h in dead:
        _sessions.pop(h, None)


class LoginError(Exception):
    """status: 401 (bad creds), 429 (locked out), 503 (login not configured)."""

    def __init__(self, status: int, detail: str, retry_after: int = 0):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.retry_after = retry_after


def attempt_login(login_id: str, password: str, client_ip: str) -> str:
    """Return a new session token or raise LoginError."""
    raw_id, raw_pw = _configured_raw()
    if not raw_id or not raw_pw:
        raise LoginError(503, "Admin login is not configured on the server")
    if credential_problems(raw_id, raw_pw):
        raise LoginError(
            503,
            "Admin login is disabled: the configured credentials do not meet the security policy. "
            "See the server log for what to change.",
        )

    now = time.monotonic()
    ip_key = _ip_key(client_ip)

    with _lock:
        if now < _ip_locked_until.get(ip_key, 0.0):
            raise LoginError(
                429, "Too many attempts. Try again later.", int(_ip_locked_until[ip_key] - now) + 1
            )

    # Cap simultaneous attempts (protects worker threads; cannot lock the real admin out).
    if not _attempt_slots.acquire(blocking=False):
        raise LoginError(429, "Server is busy. Try again in a few seconds.", 3)
    try:
        ok = _check_credentials(login_id or "", password or "")
        if not ok:
            time.sleep(FAILED_ATTEMPT_DELAY_SEC)
    finally:
        _attempt_slots.release()

    if not ok:
        with _lock:
            now = time.monotonic()
            hits = [t for t in _ip_failures.get(ip_key, []) if now - t < IP_FAILURE_WINDOW_SEC]
            hits.append(now)
            _ip_failures[ip_key] = hits
            locked = len(hits) >= MAX_FAILURES_PER_IP
            if locked:
                _ip_locked_until[ip_key] = now + IP_LOCKOUT_SEC
                _ip_failures[ip_key] = []

            # Bound memory used by tracking tables safely without wiping active lockouts.
            if len(_ip_failures) > 5000:
                expired_f = [k for k, v in _ip_failures.items() if not v or (now - v[-1] >= IP_FAILURE_WINDOW_SEC)]
                for k in expired_f:
                    _ip_failures.pop(k, None)
            if len(_ip_locked_until) > 5000:
                expired_l = [k for k, v in _ip_locked_until.items() if now >= v]
                for k in expired_l:
                    _ip_locked_until.pop(k, None)
        # Log a short, non-reversible client marker (never the credentials) so attacks are visible in the logs.
        logger.warning("admin login FAILED client=%s%s", ip_key[:8], " (locked out)" if locked else "")
        raise LoginError(401, "Invalid credentials")

    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _lock:
        now = time.monotonic()
        _ip_failures.pop(ip_key, None)
        _ip_locked_until.pop(ip_key, None)
        _purge_expired(now)
        if len(_sessions) >= MAX_ACTIVE_SESSIONS:
            oldest = min(_sessions, key=lambda h: _sessions[h][0])
            _sessions.pop(oldest, None)
        _sessions[token_hash] = (now, now)
    logger.info("admin login OK client=%s", ip_key[:8])
    return token


def verify_session(token: Optional[str]) -> bool:
    if not token or len(token) > 256:
        return False
    token_hash = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
    with _lock:
        now = time.monotonic()
        _purge_expired(now)
        entry = _sessions.get(token_hash)
        if not entry:
            return False
        _sessions[token_hash] = (entry[0], now)
        return True


def revoke_session(token: Optional[str]) -> None:
    if not token:
        return
    token_hash = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
    with _lock:
        _sessions.pop(token_hash, None)


def _reset_for_tests() -> None:
    with _lock:
        _sessions.clear()
        _ip_failures.clear()
        _ip_locked_until.clear()