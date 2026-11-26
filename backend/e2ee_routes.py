"""
FastAPI Router & WebSocket Hub for High-Security End-to-End Encryption (Section 17).

Protocols & Guarantees:
- Private 1-to-1 & Multi-Device Messaging: Olm v2 (Signal 3DH + Double Ratchet via Vodozemac)
- Group Messaging: IETF RFC 9420 Messaging Layer Security (MLS TreeKEM via ts-mls)
- Permanent Account Identifier: Immutable `user_id` separated from wallet authentication
  and completely separated from device encryption keys.
- Zero Plaintext & Zero Private Keys: Strict Pydantic schemas (`extra="forbid"`), Ed25519
  cryptographic bundle verification, atomic prekey/KeyPackage consumption, optimistic
  epoch concurrency control, and strict ciphertext retrieval authorization.
"""

import os
import re
import json
import time
import base64
import hashlib
import secrets
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set

from pydantic import BaseModel, Field, field_validator
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

import chat_db
import e2ee_db
import auth_cache
import platform_db
import chat_features_db
import capacity
import read_markers_db

router = APIRouter(prefix="/api/e2ee", tags=["e2ee"])
ws_router = APIRouter(tags=["e2ee-ws"])

APP_DOMAIN = os.getenv("APP_DOMAIN", "zyphra.in")
APP_URI = os.getenv("FRONTEND_URL", f"https://{APP_DOMAIN}").split(",")[0].strip().rstrip("/")
SESSION_COOKIE_NAME = "zyphra_session"
AUTH_CHALLENGE_TTL_SECONDS = 300
SESSION_TTL_HOURS = 24
OLM_PROTOCOL_ID = "OLM_V2_DOUBLE_RATCHET"
MLS_CIPHERSUITE_ID = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024  # 5 MiB ciphertext cap per attachment
# Per member, rolling 24 hours, private chats + groups together (kept in step with attachmentLimits.ts)
E2EE_DAILY_MAX_FILES = 100
E2EE_DAILY_MAX_BYTES = 250 * 1024 * 1024

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
DEVICE_ID_RE = re.compile(r"^dev_[a-zA-Z0-9_-]{8,48}$")

# Ephemeral salted rate-limiter state (never stores raw IP addresses)
_RATE_SALT = secrets.token_bytes(32)
_rate_buckets: Dict[str, List[float]] = {}


def _check_rate_limit(scope: str, identifier: str, max_hits: int, window_sec: float = 60.0) -> None:
    digest = hashlib.blake2b(
        f"{scope}:{identifier}".encode("utf-8"), key=_RATE_SALT, digest_size=16
    ).hexdigest()
    now = time.monotonic()
    if len(_rate_buckets) > 5000:
        stale_keys = [k for k, v in _rate_buckets.items() if not v or (now - v[-1] >= 300.0)]
        for k in stale_keys:
            _rate_buckets.pop(k, None)
    hits = [t for t in _rate_buckets.get(digest, []) if now - t < window_sec]
    if len(hits) >= max_hits:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded; please retry shortly.",
        )
    hits.append(now)
    _rate_buckets[digest] = hits


# ============================================================================
# Main event-loop handle (so sync route handlers running in the threadpool can
# push real-time events). `asyncio.get_running_loop()` raises inside a threadpool
# thread, which previously made every broadcast a silent no-op.
# ============================================================================

_MAIN_LOOP: Optional[asyncio.AbstractEventLoop] = None
_WS_SEND_TIMEOUT_SEC = 5.0


def capture_main_loop() -> None:
    """Remember the server's event loop. Safe to call repeatedly from async code."""
    global _MAIN_LOOP
    try:
        _MAIN_LOOP = asyncio.get_running_loop()
    except RuntimeError:
        pass


def _dispatch(coro_factory) -> None:
    """Run `coro_factory()` on the main loop from either async code or a worker thread."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro_factory())
        return
    except RuntimeError:
        pass
    loop = _MAIN_LOOP
    if loop is not None and loop.is_running():
        try:
            asyncio.run_coroutine_threadsafe(coro_factory(), loop)
        except Exception:
            pass


# ============================================================================
# Transient In-Memory WebSocket Hub (Zero Persistent Presence Metadata)
# ============================================================================

# Scaling knobs for the live-connection hub (defaults suit 100 to a few thousand online users).
_STATS_EXACT_LIMIT = int(os.getenv("STATS_EXACT_LIMIT", "300"))            # above this many sockets, online counts may be up to 1 s old
_STATS_TTL_SECS = float(os.getenv("STATS_TTL_SECS", "1.0"))
_PRESENCE_EXACT_LIMIT = int(os.getenv("PRESENCE_EXACT_LIMIT", "100"))      # up to this many people: presence updates are instant
_PRESENCE_MIN_INTERVAL_SECS = float(os.getenv("PRESENCE_MIN_INTERVAL_SECS", "1.0"))
_PRESENCE_SECS_PER_SOCKET = float(os.getenv("PRESENCE_SECS_PER_SOCKET", "0.001"))
_ADMIN_IDS_TTL_SECS = float(os.getenv("ADMIN_IDS_TTL_SECS", "30"))


class E2EERealtimeHub:
    def __init__(self) -> None:
        self._admin_ids_cache: Optional[Set[str]] = None
        self._admin_ids_at = 0.0
        self._e2ee_count = 0
        self._stats_cache: Dict[Any, Any] = {}
        self._presence_task: Optional["asyncio.Future[Any]"] = None
        self._presence_dirty = False
        self._connections: Dict[str, Set[WebSocket]] = {}
        self._public_connections: Set[WebSocket] = set()
        # Maps /ws/public-chat sockets that belong to MetaMask-connected members -> canonical member identity
        self._public_member_wallets: Dict[WebSocket, str] = {}
        # Maps /ws/member-presence sockets (system-wide connected MetaMask members) -> canonical member identity
        self._member_presence_sockets: Dict[WebSocket, str] = {}

    def _resolve_wallet_identity(self, wallet_or_ident: str, allow_db: bool = True) -> str:
        raw = (wallet_or_ident or "").strip()
        if not raw or raw == "pending_member":
            return "pending_member"
        if raw.startswith("user:"):
            return raw
        w_low = raw.lower()
        hit = auth_cache.get("wallet_ident", w_low)
        if hit:
            return hit
        if not allow_db:
            return f"wallet:{w_low}"
        try:
            gen = auth_cache.generation()
            u = e2ee_db.get_user_by_wallet(w_low)
            if u and u.get("user_id"):
                ident = f"user:{u['user_id']}"
                auth_cache.put("wallet_ident", w_low, ident, gen)
                return ident
        except Exception:
            pass
        return f"wallet:{w_low}"

    def register(self, user_id: str, ws: WebSocket) -> None:
        capture_main_loop()
        conns = self._connections.setdefault(user_id, set())
        if ws not in conns:
            conns.add(ws)
            self._e2ee_count += 1

    def unregister(self, user_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(user_id)
        if conns:
            if ws in conns:
                conns.discard(ws)
                self._e2ee_count = max(0, self._e2ee_count - 1)
            if not conns:
                self._connections.pop(user_id, None)

    # --- admission control: refuse new live connections when this server is full -------------
    def connection_counts(self) -> Dict[str, int]:
        return {
            "public_chat": len(self._public_connections),
            "member_presence": len(self._member_presence_sockets),
            "encrypted_channel": self._e2ee_count,
        }

    def at_capacity(self, kind: str) -> bool:
        """kind: 'public' | 'presence' | 'e2ee'. Capacity comes from the server's CPU/memory (capacity.py)."""
        cap = capacity.max_online_users()
        if cap <= 0:
            return False
        counts = self.connection_counts()
        key = {"public": "public_chat", "presence": "member_presence", "e2ee": "encrypted_channel"}[kind]
        return counts[key] >= cap

    def register_public(self, ws: WebSocket, member_ident: Optional[str] = None) -> None:
        capture_main_loop()
        self._public_connections.add(ws)
        if member_ident:
            self._public_member_wallets[ws] = self._resolve_wallet_identity(member_ident)
        else:
            self._public_member_wallets.pop(ws, None)

    def set_public_member_wallet(self, ws: WebSocket, member_ident: Optional[str]) -> None:
        if ws not in self._public_connections:
            return
        if member_ident:
            self._public_member_wallets[ws] = self._resolve_wallet_identity(member_ident)
        else:
            self._public_member_wallets.pop(ws, None)

    def is_public_member_socket(self, ws: WebSocket) -> bool:
        return ws in self._public_member_wallets

    def unregister_public(self, ws: WebSocket) -> None:
        self._public_connections.discard(ws)
        self._public_member_wallets.pop(ws, None)

    def register_member_presence(self, ws: WebSocket, member_ident: str) -> None:
        capture_main_loop()
        self._member_presence_sockets[ws] = self._resolve_wallet_identity(member_ident)

    def unregister_member_presence(self, ws: WebSocket) -> None:
        self._member_presence_sockets.pop(ws, None)

    def _configured_admin_wallets(self) -> Set[str]:
        raw = os.getenv("ADMIN_WALLET_ADDRESSES", "")
        return {
            w.strip().lower()
            for w in raw.split(",")
            if w.strip() and w.strip().lower() != "0x0000000000000000000000000000000000000000"
        }

    def _admin_ids(self) -> Set[str]:
        """All admin/moderator user ids from ONE small query, cached for _ADMIN_IDS_TTL_SECS.
        (Asking the database about every online user on every recount froze the live loop.)"""
        now = time.monotonic()
        if self._admin_ids_cache is not None and now - self._admin_ids_at < _ADMIN_IDS_TTL_SECS:
            return self._admin_ids_cache
        try:
            ids = platform_db.list_admin_user_ids()
        except Exception:
            ids = self._admin_ids_cache or set()
        self._admin_ids_cache, self._admin_ids_at = ids, now
        return ids

    def _is_admin_user_id(self, user_id: str) -> bool:
        uid = (user_id or "").strip()
        if not uid:
            return False
        if uid in self._admin_ids():
            return True
        admin_wallets = self._configured_admin_wallets()
        if admin_wallets:
            try:
                user = auth_cache.get("user", uid)  # cache only: never query the database from here
                if user:
                    pw = (user.get("primary_wallet") or "").strip().lower()
                    if pw and pw in admin_wallets:
                        return True
                    for w in user.get("wallets") or []:
                        addr = (w.get("wallet_address") or "").strip().lower()
                        if addr and addr in admin_wallets:
                            return True
            except Exception:
                pass
        return False

    def _is_admin_identity(self, ident: Optional[str]) -> bool:
        raw = (ident or "").strip()
        if not raw or raw == "pending_member":
            return False
        if raw.startswith("user:"):
            return self._is_admin_user_id(raw[len("user:") :])
        if raw.startswith("wallet:"):
            w_low = raw[len("wallet:") :].strip().lower()
            if w_low in self._configured_admin_wallets():
                return True
            resolved = self._resolve_wallet_identity(w_low, allow_db=False)  # cache only
            if resolved.startswith("user:"):
                return self._is_admin_user_id(resolved[len("user:") :])
            return False
        if raw.startswith("0x"):
            return raw.lower() in self._configured_admin_wallets()
        return False

    def is_user_online(self, user_id: str) -> bool:
        if self._is_admin_user_id(user_id):
            return False
        if self._connections.get(user_id):
            return True
        target_key = f"user:{user_id}"
        return (
            target_key in self._member_presence_sockets.values()
            or target_key in self._public_member_wallets.values()
        )

    def get_online_stats(self, include_active_live: bool = True, include_admins: bool = False) -> Dict[str, int]:
        # Exact for small servers; with many sockets the counts may be up to _STATS_TTL_SECS old,
        # because recounting everyone on every ping would cost more than the chat itself.
        size = len(self._public_connections) + len(self._member_presence_sockets) + len(self._connections)
        cache_key = (include_active_live, include_admins)
        if size > _STATS_EXACT_LIMIT:
            hit = self._stats_cache.get(cache_key)
            if hit and time.monotonic() - hit[0] < _STATS_TTL_SECS:
                return dict(hit[1])
            fresh = self._compute_online_stats(include_active_live, include_admins)
            self._stats_cache[cache_key] = (time.monotonic(), fresh)
            return dict(fresh)
        return self._compute_online_stats(include_active_live, include_admins)

    def _compute_online_stats(self, include_active_live: bool = True, include_admins: bool = False) -> Dict[str, int]:
        # Watching = non-connected people currently watching Open Public Chat
        watching_count = sum(
            1 for ws in self._public_connections if ws not in self._public_member_wallets
        )
        if not include_active_live:
            return {
                "watching": watching_count,
                "public_viewers": watching_count,
                "public_room_sockets": watching_count,
            }

        # Active Live = distinct MetaMask-connected members active anywhere in the system.
        # Admin wallets are hidden from members' view (include_admins=False) but the admin dashboard
        # passes include_admins=True so an admin using the chat is counted, and `admins_online` says how many.
        active_identities: Set[str] = set()
        admin_identities: Set[str] = set()
        for uid, conns in self._connections.items():
            if not conns:
                continue
            (admin_identities if self._is_admin_user_id(uid) else active_identities).add(f"user:{uid}")
        for ident in list(self._public_member_wallets.values()) + list(
            self._member_presence_sockets.values()
        ):
            if not ident or ident == "pending_member":
                continue
            resolved = (
                self._resolve_wallet_identity(ident[len("wallet:") :], allow_db=False)
                if ident.startswith("wallet:") and self._connections
                else ident
            )
            if self._is_admin_identity(resolved):
                admin_identities.add(resolved)
            else:
                active_identities.add(resolved)

        active_live_count = len(active_identities) + (len(admin_identities) if include_admins else 0)
        return {
            "watching": watching_count,
            "public_viewers": watching_count,
            "public_room_sockets": watching_count,
            "active_live": active_live_count,
            "authenticated_users": active_live_count,
            "authenticated_online": active_live_count,
            "online_count": watching_count + active_live_count,
            "admins_online": len(admin_identities),
        }

    async def _safe_send(self, ws: WebSocket, event: Dict[str, Any]) -> bool:
        try:
            await asyncio.wait_for(ws.send_json(event), timeout=_WS_SEND_TIMEOUT_SEC)
            return True
        except Exception:
            return False

    async def _safe_send_text(self, ws: WebSocket, payload: str) -> bool:
        try:
            await asyncio.wait_for(ws.send_text(payload), timeout=_WS_SEND_TIMEOUT_SEC)
            return True
        except Exception:
            return False

    async def notify_users(self, user_ids: List[str], event: Dict[str, Any]) -> None:
        # Ensure zero plaintext ever leaves over E2EE WebSocket
        e2ee_db.assert_zero_plaintext(event, "ws_event")
        targets = [(uid, ws) for uid in set(u for u in user_ids if u) for ws in list(self._connections.get(uid, ()))]
        if not targets:
            return
        results = await asyncio.gather(*(self._safe_send(ws, event) for _, ws in targets))
        for (uid, ws), ok in zip(targets, results):
            if not ok:
                self.unregister(uid, ws)

    async def broadcast_public_event(self, event: Dict[str, Any]) -> None:
        # Encode the message ONCE and send the same text to everyone (encoding per person was the
        # biggest cost of a chat message), concurrently so one slow client cannot delay the others.
        sockets = list(self._public_connections)
        if not sockets:
            return
        payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False, default=str)
        results = await asyncio.gather(*(self._safe_send_text(ws, payload) for ws in sockets))
        for ws, ok in zip(sockets, results):
            if not ok:
                self.unregister_public(ws)

    async def broadcast_public_presence(self, exclude_ws: Optional[WebSocket] = None) -> None:
        """Tell everyone the new online counts, without making every join cost O(everyone).

        Many joins in a short time are merged into ONE update. Up to _PRESENCE_EXACT_LIMIT people it is
        instant; above that, updates are at most one per interval, and the interval grows with the crowd.
        """
        self._presence_dirty = True
        task = self._presence_task
        if task is None or task.done():
            self._presence_task = asyncio.ensure_future(self._presence_worker())

    async def _presence_worker(self) -> None:
        try:
            while self._presence_dirty:
                self._presence_dirty = False
                await self._send_presence_now()
                n = len(self._public_connections)
                delay = 0.0 if n <= _PRESENCE_EXACT_LIMIT else max(_PRESENCE_MIN_INTERVAL_SECS, n * _PRESENCE_SECS_PER_SOCKET)
                await asyncio.sleep(delay)
        except Exception:
            pass

    async def _send_presence_now(self) -> None:
        sockets = list(self._public_connections)
        if not sockets:
            return
        member_payload = json.dumps({"type": "public_presence", "online": self.get_online_stats(True)}, separators=(",", ":"))
        guest_payload = json.dumps({"type": "public_presence", "online": self.get_online_stats(False)}, separators=(",", ":"))
        results = await asyncio.gather(
            *(
                self._safe_send_text(ws, member_payload if ws in self._public_member_wallets else guest_payload)
                for ws in sockets
            )
        )
        for ws, ok in zip(sockets, results):
            if not ok:
                self.unregister_public(ws)


realtime_hub = E2EERealtimeHub()


def _schedule_ws_notify(user_ids: List[str], event: Dict[str, Any]) -> None:
    _dispatch(lambda: realtime_hub.notify_users(user_ids, event))


def schedule_public_ws_broadcast(event: Dict[str, Any]) -> None:
    _dispatch(lambda: realtime_hub.broadcast_public_event(event))


# ============================================================================
# Cryptographic Format & Signature Verification Helpers
# ============================================================================

def _decode_b64_any(value: str, field_name: str) -> bytes:
    """Decodes unpadded or padded standard Base64 or Base64url strictly."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty")
    pad = "=" * (-len(cleaned) % 4)
    try:
        if "-" in cleaned or "_" in cleaned:
            return base64.urlsafe_b64decode(cleaned + pad)
        return base64.b64decode(cleaned + pad)
    except Exception as exc:
        raise ValueError(f"Invalid base64 encoding in {field_name}") from exc


def _validate_32byte_key(b64_key: str, field_name: str) -> bytes:
    raw = _decode_b64_any(b64_key, field_name)
    if len(raw) != 32:
        raise ValueError(f"{field_name} must decode to 32 bytes (got {len(raw)})")
    if raw == b"\x00" * 32:
        raise ValueError(f"{field_name} must not be all-zero low-order point")
    return raw


def build_canonical_device_bundle_payload(
    user_id: str,
    device_id: str,
    ed25519_identity_key: str,
    curve25519_identity_key: str,
    fallback_key_id: Optional[str],
    fallback_public_key: Optional[str],
) -> str:
    return (
        f"zyphra-e2ee-device-v1|{user_id}|{device_id}|"
        f"{ed25519_identity_key}|{curve25519_identity_key}|"
        f"{fallback_key_id or ''}|{fallback_public_key or ''}"
    )


def verify_device_ed25519_bundle_signature(
    ed25519_key_b64: str,
    signature_b64: str,
    canonical_payload: str,
) -> None:
    """
    Verifies a Vodozemac `Account.sign(...)` Ed25519 signature using Python's
    maintained `cryptography` library (OpenSSL Ed25519).
    """
    pub_bytes = _validate_32byte_key(ed25519_key_b64, "ed25519_identity_key")
    sig_bytes = _decode_b64_any(signature_b64, "bundle_signature")
    if len(sig_bytes) != 64:
        raise ValueError(f"Ed25519 signature must decode to 64 bytes (got {len(sig_bytes)})")
    pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    try:
        pub_key.verify(sig_bytes, canonical_payload.encode("utf-8"))
    except InvalidSignature as exc:
        raise ValueError("Ed25519 device bundle signature verification failed") from exc


# ============================================================================
# Session Extraction Dependency
# ============================================================================

def _extract_raw_token(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        tok = authorization[7:].strip()
        if tok:
            return tok
    cookie_tok = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_tok:
        return cookie_tok.strip()
    return None


def _enforce_not_suspended(user: Dict[str, Any]) -> Dict[str, Any]:
    status_val = user.get("account_status")
    if status_val in ("suspended", "muted"):
        until_str = user.get("suspended_until")
        if until_str:
            try:
                until_dt = datetime.fromisoformat(str(until_str).replace("Z", "+00:00"))
                if until_dt <= e2ee_db.now_utc():
                    restored = platform_db.admin_moderate_user_account(
                        target_user_id=user["user_id"],
                        action_type="restore",
                        reason="Automatic expiry of temporary suspension/mute",
                        moderator_user_id="system",
                    )
                    return restored
            except Exception:
                pass
        if status_val == "suspended":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account suspended: {user.get('suspension_reason') or 'Contact platform administrator'}",
            )
    return user


def get_optional_session(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Optional[Dict[str, Any]]:
    raw_token = _extract_raw_token(request, authorization)
    if not raw_token:
        return None
    sess = e2ee_db.get_session_by_token(raw_token)
    if not sess:
        return None
    user = e2ee_db.get_user_by_id(sess["user_id"])
    if not user or user.get("account_status") == "suspended":
        return None
    return {"session": sess, "user": user, "raw_token": raw_token}


def require_authenticated_session(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    raw_token = _extract_raw_token(request, authorization)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: valid session token missing",
        )
    sess = e2ee_db.get_session_by_token(raw_token)
    if not sess:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked session token",
        )
    user = e2ee_db.get_user_by_id(sess["user_id"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account not found for session",
        )
    user = _enforce_not_suspended(user)
    return {"session": sess, "user": user, "raw_token": raw_token}


def require_paid_member(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Authenticated session AND paid platform membership (admins/moderators bypass).

    Used for everything that makes up the premium product: public chat, DMs, groups,
    attachments, user search. Sign-in, payment and membership-status endpoints keep using
    `require_authenticated_session` so an unpaid user can still sign in and pay.
    """
    ctx = require_authenticated_session(request, authorization)
    if not platform_db.has_user_paid_platform_entry(ctx["user"]["user_id"]):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Membership payment required to use this feature.",
        )
    return ctx


# ============================================================================
# Pydantic Request Schemas (Strict `extra = "forbid"`)
# ============================================================================

class StrictModel(BaseModel):
    model_config = {"extra": "forbid"}


class AuthChallengeRequest(StrictModel):
    wallet_address: str
    purpose: str = Field("login", pattern=r"^(login|link_wallet|reset_lost_identity)$")
    chain_id: int = Field(1, ge=1)

    @field_validator("wallet_address")
    @classmethod
    def check_wallet(cls, v: str) -> str:
        if not Web3.is_address(v):
            raise ValueError("Invalid Ethereum wallet address")
        return Web3.to_checksum_address(v)


class AuthVerifyRequest(StrictModel):
    challenge_id: str = Field(..., min_length=12, max_length=80)
    wallet_address: str
    signature: str = Field(..., min_length=130, max_length=136)

    @field_validator("wallet_address")
    @classmethod
    def check_wallet(cls, v: str) -> str:
        if not Web3.is_address(v):
            raise ValueError("Invalid Ethereum wallet address")
        return Web3.to_checksum_address(v)


class UsernameUpdateRequest(StrictModel):
    username: str = Field(..., min_length=3, max_length=32)

    @field_validator("username")
    @classmethod
    def check_username(cls, v: str) -> str:
        cleaned = v.strip()
        if not USERNAME_RE.match(cleaned):
            raise ValueError("Username must be 3-32 alphanumeric or underscore characters")
        return cleaned


class WalletLinkRequest(StrictModel):
    challenge_id: str = Field(..., min_length=12, max_length=80)
    new_wallet_address: str
    signature: str = Field(..., min_length=130, max_length=136)
    make_primary: bool = True
    revoke_previous_wallets: bool = False

    @field_validator("new_wallet_address")
    @classmethod
    def check_wallet(cls, v: str) -> str:
        if not Web3.is_address(v):
            raise ValueError("Invalid Ethereum wallet address")
        return Web3.to_checksum_address(v)


class MlsKeyPackageUploadItem(StrictModel):
    package_id: Optional[str] = Field(None, max_length=64)
    ciphersuite: str = Field(MLS_CIPHERSUITE_ID)
    key_package_b64: str = Field(..., min_length=32, max_length=16384)
    key_package_ref: str = Field(..., min_length=16, max_length=128)


class DeviceRegisterRequest(StrictModel):
    device_id: str = Field(..., min_length=12, max_length=52)
    device_label: str = Field("Browser E2EE Vault", min_length=1, max_length=64)
    ed25519_identity_key: str = Field(..., min_length=40, max_length=64)
    curve25519_identity_key: str = Field(..., min_length=40, max_length=64)
    fallback_key_id: Optional[str] = Field(None, max_length=64)
    fallback_public_key: Optional[str] = Field(None, max_length=64)
    bundle_signature: str = Field(..., min_length=80, max_length=128)
    one_time_keys: Dict[str, str] = Field(default_factory=dict)
    mls_key_packages: List[MlsKeyPackageUploadItem] = Field(default_factory=list)

    @field_validator("device_id")
    @classmethod
    def check_device_id(cls, v: str) -> str:
        if not DEVICE_ID_RE.match(v):
            raise ValueError("device_id must match dev_<alphanumeric>")
        return v


class PrekeyReplenishRequest(StrictModel):
    fallback_key_id: Optional[str] = Field(None, max_length=64)
    fallback_public_key: Optional[str] = Field(None, max_length=64)
    bundle_signature: str = Field(..., min_length=80, max_length=128)
    one_time_keys: Dict[str, str] = Field(default_factory=dict)
    mls_key_packages: List[MlsKeyPackageUploadItem] = Field(default_factory=list)


class PrekeyClaimRequest(StrictModel):
    target_user_id: str = Field(..., min_length=8, max_length=64)
    target_device_ids: Optional[List[str]] = None


class LostIdentityResetRequest(StrictModel):
    challenge_id: str = Field(..., min_length=12, max_length=80)
    wallet_address: str
    signature: str = Field(..., min_length=130, max_length=136)
    confirm_irrecoverable_history: bool
    new_device: DeviceRegisterRequest

    @field_validator("wallet_address")
    @classmethod
    def check_wallet(cls, v: str) -> str:
        if not Web3.is_address(v):
            raise ValueError("Invalid Ethereum wallet address")
        return Web3.to_checksum_address(v)


class OlmDeviceCiphertextEntry(StrictModel):
    message_type: int = Field(..., ge=0, le=1, description="0=PreKey message, 1=Normal ratchet message")
    ciphertext_b64: str = Field(..., min_length=24, max_length=65536)


class DmCiphertextSubmitRequest(StrictModel):
    message_id: str = Field(..., min_length=10, max_length=64)
    recipient_user_id: str = Field(..., min_length=8, max_length=64)
    sender_device_id: str = Field(..., min_length=12, max_length=52)
    protocol: str = Field(OLM_PROTOCOL_ID)
    device_ciphertexts: Dict[str, OlmDeviceCiphertextEntry]
    attachment_ids: List[str] = Field(default_factory=list, max_length=10)
    # 'control' = an encrypted reaction / edit / poll vote: never counted unread or notified
    event_kind: str = Field("message", pattern=r"^(message|control)$")


class MlsKeyPackageClaimRequest(StrictModel):
    target_user_id: str = Field(..., min_length=8, max_length=64)


class GroupCreateRequest(StrictModel):
    model_config = {"extra": "ignore"}  # older app versions may still send the removed avatar_url / min_level / history_sharing_mode
    name: str = Field(..., min_length=1, max_length=80)
    mls_group_id_b64: str = Field(..., min_length=8, max_length=128)
    creator_device_id: str = Field(..., min_length=12, max_length=52)
    ciphersuite: str = Field(MLS_CIPHERSUITE_ID)
    description: str = Field("", max_length=500)
    visibility: str = Field("invite_only", pattern=r"^(public|invite_only)$")
    min_eth_balance_wei: str = Field("0", pattern=r"^[0-9]{1,36}$")
    require_invitation: bool = True
    # Platform admin only: create the group as a paid group (price in USD, paid in ETH)
    is_paid: bool = False
    entry_fee_usd: Optional[float] = Field(None, ge=0, le=100000)
    entry_fee_yearly_usd: Optional[float] = Field(None, ge=0, le=1000000)  # 0 / empty = 12 x monthly


class AddedGroupMemberModel(StrictModel):
    user_id: str = Field(..., min_length=8, max_length=64)
    device_id: str = Field(..., min_length=12, max_length=52)
    leaf_index: Optional[int] = Field(None, ge=0)
    role: str = Field("member", pattern=r"^(admin|member)$")


class RemovedGroupMemberModel(StrictModel):
    user_id: str = Field(..., min_length=8, max_length=64)
    device_id: Optional[str] = Field(None, min_length=12, max_length=52)


class GroupWelcomeEnvelopeModel(StrictModel):
    target_user_id: str = Field(..., min_length=8, max_length=64)
    target_device_id: str = Field(..., min_length=12, max_length=52)
    mls_welcome_b64: str = Field(..., min_length=24, max_length=262144)
    ratchet_tree_b64: Optional[str] = Field(None, max_length=262144)


class GroupCommitSubmitRequest(StrictModel):
    committer_device_id: str = Field(..., min_length=12, max_length=52)
    expected_epoch: int = Field(..., ge=0)
    commit_type: str = Field(..., pattern=r"^(add|remove|update)$")
    mls_commit_b64: str = Field(..., min_length=24, max_length=262144)
    ratchet_tree_b64: Optional[str] = Field(None, max_length=262144)
    added_members: List[AddedGroupMemberModel] = Field(default_factory=list)
    removed_members: List[RemovedGroupMemberModel] = Field(default_factory=list)
    welcomes: List[GroupWelcomeEnvelopeModel] = Field(default_factory=list)


class GroupMessageSubmitRequest(StrictModel):
    message_id: str = Field(..., min_length=10, max_length=64)
    sender_device_id: str = Field(..., min_length=12, max_length=52)
    epoch: int = Field(..., ge=0)
    mls_ciphertext_b64: str = Field(..., min_length=24, max_length=131072)
    attachment_ids: List[str] = Field(default_factory=list, max_length=10)
    event_kind: str = Field("message", pattern=r"^(message|control)$")
    # Who the (encrypted) message @mentions, so they get a "mentioned you" notice. Only ids, never text.
    mention_user_ids: List[str] = Field(default_factory=list, max_length=50)


class EncryptedAttachmentUploadRequest(StrictModel):
    scope_type: str = Field(..., pattern=r"^(dm|group)$")
    scope_id: str = Field(..., min_length=6, max_length=64)
    uploader_device_id: str = Field(..., min_length=12, max_length=52)
    algorithm: str = Field("AES-256-GCM")
    ciphertext_b64: str = Field(..., min_length=24, max_length=14_000_000)
    ciphertext_sha256: str = Field(..., min_length=64, max_length=64)


# ============================================================================
# 1. AUTHENTICATION & PERMANENT USER IDENTITY ENDPOINTS
# ============================================================================


@router.post("/auth/challenge")
def request_e2ee_auth_challenge(
    payload: AuthChallengeRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """
    Issues a standardized EIP-4361 (Sign-In with Ethereum / SIWE) challenge message
    with a cryptographically random, single-use, time-limited nonce.
    """
    # Rate limit per WALLET address only: the server never looks at the caller's IP or any other visitor data.
    _check_rate_limit("auth_challenge", payload.wallet_address.lower(), max_hits=25, window_sec=60.0)

    bound_user_id: Optional[str] = None
    if payload.purpose in ("link_wallet", "reset_lost_identity"):
        ctx = require_authenticated_session(request, authorization)
        bound_user_id = ctx["user"]["user_id"]
        if payload.purpose == "reset_lost_identity":
            user_doc = e2ee_db.get_user_by_id(bound_user_id) or {}
            user_wallets = [w["wallet_address"].lower() for w in user_doc.get("wallets", [])]
            if payload.wallet_address.lower() not in user_wallets:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Challenge wallet is not an active linked wallet for this account",
                )

    nonce = secrets.token_hex(16)
    now = e2ee_db.now_utc()
    exp = now + timedelta(seconds=AUTH_CHALLENGE_TTL_SECONDS)

    statement = (
        f"Authenticate with {APP_DOMAIN} Chat Platform ({payload.purpose}). "
        f"Wallet signatures authenticate your session only and are never used as encryption keys."
    )
    resources_lines = [f"- urn:zyphra:purpose:{payload.purpose}"]
    if bound_user_id:
        resources_lines.append(f"- urn:zyphra:user:{bound_user_id}")
    resources_block = "Resources:\n" + "\n".join(resources_lines)

    message = (
        f"{APP_DOMAIN} wants you to sign in with your Ethereum account:\n"
        f"{payload.wallet_address}\n\n"
        f"{statement}\n\n"
        f"URI: {APP_URI}\n"
        f"Version: 1\n"
        f"Chain ID: {payload.chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {now.isoformat()}\n"
        f"Expiration Time: {exp.isoformat()}\n"
        f"{resources_block}"
    )

    rec = e2ee_db.create_auth_challenge(
        wallet_address=payload.wallet_address,
        purpose=payload.purpose,
        nonce=nonce,
        message=message,
        expires_at=exp.isoformat(),
        user_id=bound_user_id,
    )
    return rec


def _verify_and_consume_challenge(
    challenge_id: str,
    expected_wallet: str,
    expected_purpose: str,
    signature: str,
    expected_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    chal = e2ee_db.consume_auth_challenge_atomic(challenge_id)
    if not chal:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Challenge not found or already consumed (replay rejected)",
        )
    if chal["purpose"] != expected_purpose:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Challenge purpose mismatch",
        )
    if chal["wallet_address"].lower() != expected_wallet.lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Challenge wallet mismatch",
        )
    if expected_user_id and chal.get("user_id") != expected_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Challenge user_id mismatch",
        )

    msg_text = str(chal["message"] or "")
    expected_header = f"{APP_DOMAIN} wants you to sign in with your Ethereum account:\n"
    if (
        not msg_text.startswith(expected_header)
        or f"URI: {APP_URI}" not in msg_text
        or "Version: 1" not in msg_text
        or f"Nonce: {chal['nonce']}" not in msg_text
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SIWE (EIP-4361) domain/URI/nonce integrity validation failed",
        )

    exp_dt = datetime.fromisoformat(chal["expires_at"].replace("Z", "+00:00"))
    if exp_dt <= e2ee_db.now_utc():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication challenge expired",
        )

    try:
        msghash = encode_defunct(text=msg_text)
        recovered = Account.recover_message(msghash, signature=signature)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid wallet signature encoding",
        )

    if recovered.lower() != expected_wallet.lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signature verification failed: signer does not match wallet",
        )
    return chal


@router.post("/auth/verify")
def verify_e2ee_auth_challenge(
    payload: AuthVerifyRequest,
    request: Request,
    response: Response,
):
    _verify_and_consume_challenge(
        challenge_id=payload.challenge_id,
        expected_wallet=payload.wallet_address,
        expected_purpose="login",
        signature=payload.signature,
    )

    user, created = e2ee_db.get_or_create_user_for_wallet(payload.wallet_address)
    user = _enforce_not_suspended(user)
    platform_db.bootstrap_admin_if_configured(user["user_id"], payload.wallet_address)
    # Re-verify payment status directly against the database on every login (never rely on cached state).
    is_paid = platform_db.has_user_paid_platform_entry(user["user_id"], fresh=True)
    platform_sub = platform_db.get_subscription(user["user_id"], "platform", "platform")
    user = e2ee_db.get_user_by_id(user["user_id"]) or user
    user = {
        **user,
        "is_platform_paid": is_paid,
        "platform_paid_until": (platform_sub or {}).get("paid_until"),
    }

    expires_at = (e2ee_db.now_utc() + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    raw_token, sess = e2ee_db.create_auth_session(
        user_id=user["user_id"],
        wallet_address=payload.wallet_address,
        expires_at=expires_at,
    )

    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=is_https,
        samesite="none" if is_https else "lax",
        max_age=SESSION_TTL_HOURS * 3600,
        path="/",
    )

    devices = e2ee_db.list_user_devices(user["user_id"], include_revoked=False)
    return {
        "success": True,
        "created_account": created,
        "session_id": sess["session_id"],
        "session_token": raw_token,
        "expires_at": sess["expires_at"],
        "user": user,
        "devices": devices,
    }


@router.post("/auth/logout")
def logout_e2ee_session(
    response: Response,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    e2ee_db.revoke_session_token(ctx["raw_token"])
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"success": True, "status": "logged_out"}


@router.get("/me")
def get_current_e2ee_account(ctx: Dict[str, Any] = Depends(require_authenticated_session)):
    user = ctx["user"]
    sess = ctx["session"]
    devices = e2ee_db.list_user_devices(user["user_id"], include_revoked=True)
    return {
        "session_id": sess.get("session_id"),
        "session_expires_at": sess.get("expires_at"),
        "user": user,
        "devices": devices,
    }


@router.get("/account/username/check")
def check_username_availability(
    username: str = Query(..., min_length=1, max_length=64),
    ctx: Optional[Dict[str, Any]] = Depends(get_optional_session),
):
    clean = username.strip()
    if clean.startswith("@"):
        clean = clean[1:]
    if not USERNAME_RE.match(clean):
        return {
            "username": clean,
            "available": False,
            "reason": "Must be 3-32 alphanumeric or underscore characters",
        }

    current_uid = ctx["user"]["user_id"] if ctx else None
    existing = e2ee_db.get_user_by_username(clean)
    if existing:
        if current_uid and existing["user_id"] == current_uid:
            return {
                "username": clean,
                "available": True,
                "is_current": True,
                "reason": "Your current username",
            }
        return {
            "username": clean,
            "available": False,
            "reason": "Username is already claimed by another account",
        }

    # Check reservation quarantine in username_history
    now = datetime.now(timezone.utc)
    if e2ee_db._is_pg():
        conn = chat_db._pg_pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT user_id, reserved_until FROM username_history WHERE LOWER(old_username) = LOWER(%s) ORDER BY changed_at DESC LIMIT 1;",
                    (clean,),
                )
                row = cur.fetchone()
        finally:
            chat_db._pg_pool.putconn(conn)
    else:
        with chat_db._sqlite_lock:
            cur = chat_db._sqlite_conn.cursor()
            cur.execute(
                "SELECT user_id, reserved_until FROM username_history WHERE LOWER(old_username) = LOWER(?) ORDER BY changed_at DESC LIMIT 1",
                (clean,),
            )
            row = cur.fetchone()

    if row and row[1]:
        res_dt = datetime.fromisoformat(str(row[1]).replace("Z", "+00:00"))
        if res_dt > now and (not current_uid or row[0] != current_uid):
            return {
                "username": clean,
                "available": False,
                "reason": "Username was recently used by another account and is reserved",
            }

    return {
        "username": clean,
        "available": True,
        "reason": None,
    }


@router.patch("/account/username")
def update_account_username(
    payload: UsernameUpdateRequest,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    user_id = ctx["user"]["user_id"]
    try:
        updated = platform_db.update_username_with_history_and_cooldown(
            user_id=user_id, new_username=payload.username
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ve))
    except Exception as exc:
        err_msg = str(exc).lower()
        if "unique" in err_msg or "integrity" in err_msg or "idx_chat_users_username" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username is already claimed by another account",
            )
        raise
    return {
        "success": True,
        "user": updated,
        "encryption_identity_unchanged": True,
    }


@router.post("/account/wallets/link")
def link_or_replace_wallet(
    payload: WalletLinkRequest,
    request: Request,
    response: Response,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    user_id = ctx["user"]["user_id"]
    old_primary = ctx["user"].get("primary_wallet")
    _verify_and_consume_challenge(
        challenge_id=payload.challenge_id,
        expected_wallet=payload.new_wallet_address,
        expected_purpose="link_wallet",
        signature=payload.signature,
        expected_user_id=user_id,
    )
    try:
        updated_user = e2ee_db.link_wallet_to_user(
            user_id=user_id,
            new_wallet_address=payload.new_wallet_address,
            make_primary=payload.make_primary,
            revoke_previous_wallets=payload.revoke_previous_wallets,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ve))

    platform_db.record_wallet_change_and_revoke_old_sessions(
        user_id=user_id,
        action="wallet_replaced" if payload.revoke_previous_wallets else "wallet_linked",
        old_wallet=old_primary,
        new_wallet=payload.new_wallet_address,
        performed_by=user_id,
        revoke_previous_sessions=payload.revoke_previous_wallets,
    )
    if payload.revoke_previous_wallets:
        platform_db.reset_user_balance_on_wallet_revoke(user_id)
    platform_db.bootstrap_admin_if_configured(user_id, payload.new_wallet_address)
    updated_user = e2ee_db.get_user_by_id(user_id) or updated_user

    new_session_token: Optional[str] = None
    new_session_id: Optional[str] = None
    if payload.revoke_previous_wallets:
        expires_at = (e2ee_db.now_utc() + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
        new_session_token, new_sess = e2ee_db.create_auth_session(
            user_id=user_id,
            wallet_address=payload.new_wallet_address,
            expires_at=expires_at,
        )
        new_session_id = new_sess["session_id"]
        is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=new_session_token,
            httponly=True,
            secure=is_https,
            samesite="none" if is_https else "lax",
            max_age=SESSION_TTL_HOURS * 3600,
            path="/",
        )

    evt = e2ee_db.record_identity_event(
        user_id=user_id,
        event_type="wallet_changed" if payload.revoke_previous_wallets else "wallet_linked",
        identity_version=updated_user["identity_version"],
        details={
            "primary_wallet": updated_user["primary_wallet"],
            "encryption_keys_unchanged": True,
        },
    )
    _schedule_ws_notify([user_id], {"type": "identity_event", "event": evt})

    resp_body: Dict[str, Any] = {
        "success": True,
        "user": updated_user,
        "encryption_identity_unchanged": True,
    }
    if new_session_token:
        resp_body["session_token"] = new_session_token
        if new_session_id:
            resp_body["session_id"] = new_session_id
    return resp_body


@router.get("/users/resolve/{identifier}")
def resolve_peer_account(
    identifier: str,
    _ctx: Dict[str, Any] = Depends(require_paid_member),
):
    peer = e2ee_db.resolve_peer_identifier(identifier)
    if not peer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No registered E2EE user found for that user_id, username, or wallet address",
        )
    devices = e2ee_db.list_user_devices(peer["user_id"], include_revoked=False)
    return {
        "user_id": peer["user_id"],
        "username": peer["username"],
        "primary_wallet": peer["primary_wallet"],
        "identity_version": peer["identity_version"],
        "devices": devices,
    }


# ============================================================================
# 2. DEVICE REGISTRATION, PREKEY REPLENISHMENT, REVOCATION, & LOST-KEY RESET
# ============================================================================

def _validate_and_verify_device_payload(
    user_id: str,
    device_id: str,
    ed25519_identity_key: str,
    curve25519_identity_key: str,
    fallback_key_id: Optional[str],
    fallback_public_key: Optional[str],
    bundle_signature: str,
    one_time_keys: Dict[str, str],
    mls_key_packages: List[MlsKeyPackageUploadItem],
) -> str:
    _validate_32byte_key(curve25519_identity_key, "curve25519_identity_key")
    if fallback_public_key:
        _validate_32byte_key(fallback_public_key, "fallback_public_key")
    if len(one_time_keys) > 100:
        raise ValueError("Too many one_time_keys in a single batch (max 100)")
    for kid, pub in one_time_keys.items():
        if not kid or len(kid) > 64:
            raise ValueError("Invalid one_time_key ID")
        _validate_32byte_key(pub, f"one_time_keys[{kid}]")
    if len(mls_key_packages) > 50:
        raise ValueError("Too many mls_key_packages in a single batch (max 50)")
    for kp in mls_key_packages:
        if kp.ciphersuite != MLS_CIPHERSUITE_ID:
            raise ValueError(f"Unsupported MLS ciphersuite: {kp.ciphersuite}")
        _decode_b64_any(kp.key_package_b64, "key_package_b64")

    canonical = build_canonical_device_bundle_payload(
        user_id=user_id,
        device_id=device_id,
        ed25519_identity_key=ed25519_identity_key,
        curve25519_identity_key=curve25519_identity_key,
        fallback_key_id=fallback_key_id,
        fallback_public_key=fallback_public_key,
    )
    verify_device_ed25519_bundle_signature(
        ed25519_key_b64=ed25519_identity_key,
        signature_b64=bundle_signature,
        canonical_payload=canonical,
    )
    return canonical


@router.post("/devices/register")
def register_e2ee_device(
    payload: DeviceRegisterRequest,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    user = ctx["user"]
    user_id = user["user_id"]

    try:
        canonical = _validate_and_verify_device_payload(
            user_id=user_id,
            device_id=payload.device_id,
            ed25519_identity_key=payload.ed25519_identity_key,
            curve25519_identity_key=payload.curve25519_identity_key,
            fallback_key_id=payload.fallback_key_id,
            fallback_public_key=payload.fallback_public_key,
            bundle_signature=payload.bundle_signature,
            one_time_keys=payload.one_time_keys,
            mls_key_packages=payload.mls_key_packages,
        )
        device_doc, event_type = e2ee_db.upsert_device_and_keys(
            user_id=user_id,
            device_id=payload.device_id,
            device_label=payload.device_label,
            ed25519_identity_key=payload.ed25519_identity_key,
            curve25519_identity_key=payload.curve25519_identity_key,
            fallback_key_id=payload.fallback_key_id,
            fallback_public_key=payload.fallback_public_key,
            bundle_signature=payload.bundle_signature,
            signed_payload=canonical,
            one_time_keys=payload.one_time_keys,
            mls_key_packages=[kp.model_dump() for kp in payload.mls_key_packages],
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        code = (
            status.HTTP_409_CONFLICT
            if "substitution" in str(ve).lower()
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=code, detail=str(ve))

    if event_type:
        evt = e2ee_db.record_identity_event(
            user_id=user_id,
            event_type=event_type,
            device_id=payload.device_id,
            identity_version=user["identity_version"],
            details={
                "device_label": payload.device_label,
                "ed25519_identity_key": payload.ed25519_identity_key,
                "curve25519_identity_key": payload.curve25519_identity_key,
            },
        )
        _schedule_ws_notify([user_id], {"type": "identity_event", "event": evt})

    counts = e2ee_db.count_available_prekeys(payload.device_id)
    return {
        "success": True,
        "device": device_doc,
        "available_counts": counts,
    }


@router.post("/devices/{device_id}/prekeys")
def replenish_device_prekeys(
    device_id: str,
    payload: PrekeyReplenishRequest,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    user_id = ctx["user"]["user_id"]
    existing = e2ee_db.get_device(device_id)
    if not existing or existing["user_id"] != user_id or existing["status"] != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active owned device required to replenish prekeys",
        )

    fb_id = payload.fallback_key_id or existing["fallback_key_id"]
    fb_pub = payload.fallback_public_key or existing["fallback_public_key"]

    try:
        canonical = _validate_and_verify_device_payload(
            user_id=user_id,
            device_id=device_id,
            ed25519_identity_key=existing["ed25519_identity_key"],
            curve25519_identity_key=existing["curve25519_identity_key"],
            fallback_key_id=fb_id,
            fallback_public_key=fb_pub,
            bundle_signature=payload.bundle_signature,
            one_time_keys=payload.one_time_keys,
            mls_key_packages=payload.mls_key_packages,
        )
        e2ee_db.upsert_device_and_keys(
            user_id=user_id,
            device_id=device_id,
            device_label=existing["device_label"],
            ed25519_identity_key=existing["ed25519_identity_key"],
            curve25519_identity_key=existing["curve25519_identity_key"],
            fallback_key_id=fb_id,
            fallback_public_key=fb_pub,
            bundle_signature=payload.bundle_signature,
            signed_payload=canonical,
            one_time_keys=payload.one_time_keys,
            mls_key_packages=[kp.model_dump() for kp in payload.mls_key_packages],
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    return {
        "success": True,
        "device_id": device_id,
        "available_counts": e2ee_db.count_available_prekeys(device_id),
    }


@router.get("/devices/{device_id}/prekey-count")
def get_device_prekey_counts(
    device_id: str,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    dev = e2ee_db.get_device(device_id)
    if not dev or dev["user_id"] != ctx["user"]["user_id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return e2ee_db.count_available_prekeys(device_id)


@router.get("/users/{target_user_id}/devices")
def list_peer_active_devices(
    target_user_id: str,
    _ctx: Dict[str, Any] = Depends(require_paid_member),
):
    peer = e2ee_db.get_user_by_id(target_user_id)
    if not peer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    devices = e2ee_db.list_user_devices(target_user_id, include_revoked=False)
    return {
        "user_id": target_user_id,
        "identity_version": peer["identity_version"],
        "devices": devices,
    }


@router.post("/devices/{device_id}/revoke")
def revoke_user_device(
    device_id: str,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    user = ctx["user"]
    user_id = user["user_id"]
    try:
        revoked_doc = e2ee_db.revoke_device(user_id=user_id, device_id=device_id)
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))

    evt = e2ee_db.record_identity_event(
        user_id=user_id,
        event_type="device_revoked",
        device_id=device_id,
        identity_version=user["identity_version"],
        details={"device_label": revoked_doc["device_label"]},
    )
    _schedule_ws_notify([user_id], {"type": "identity_event", "event": evt})

    return {"success": True, "device": revoked_doc, "event": evt}


@router.post("/prekeys/claim")
def claim_peer_olm_prekeys(
    payload: PrekeyClaimRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    requester_id = ctx["user"]["user_id"]
    if platform_db.is_blocked_between(requester_id, payload.target_user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot claim prekeys from a blocked user",
        )
    _check_rate_limit("prekey_claim", f"{requester_id}:{payload.target_user_id}", max_hits=30, window_sec=60.0)

    active_devices = e2ee_db.list_user_devices(payload.target_user_id, include_revoked=False)
    if payload.target_device_ids is not None:
        wanted = set(payload.target_device_ids)
        active_devices = [d for d in active_devices if d["device_id"] in wanted]

    bundles = []
    for d in active_devices:
        claimed = e2ee_db.claim_one_time_prekey_for_device(d["device_id"])
        if claimed:
            bundles.append(claimed)

    return {
        "target_user_id": payload.target_user_id,
        "bundles": bundles,
    }


@router.post("/identity/reset")
def reset_lost_encryption_identity(
    payload: LostIdentityResetRequest,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    """
    Explicit recovery procedure when a user loses all devices and private keys.
    Never promises decryption of prior messages; revokes old devices, increments
    `identity_version`, registers a fresh verified device, and alerts peers.
    """
    if not payload.confirm_irrecoverable_history:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Lost-key reset requires confirm_irrecoverable_history=true. "
                "Encrypted messages whose local decryption keys were lost cannot be recovered."
            ),
        )

    user_id = ctx["user"]["user_id"]
    user_doc = e2ee_db.get_user_by_id(user_id) or {}
    user_wallets = [w["wallet_address"].lower() for w in user_doc.get("wallets", [])]
    if payload.wallet_address.lower() not in user_wallets:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reset signing wallet is not an active linked wallet for this account",
        )
    _verify_and_consume_challenge(
        challenge_id=payload.challenge_id,
        expected_wallet=payload.wallet_address,
        expected_purpose="reset_lost_identity",
        signature=payload.signature,
        expected_user_id=user_id,
    )

    nd = payload.new_device
    if e2ee_db.get_device(nd.device_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identity reset requires a freshly generated device_id; existing or revoked device IDs cannot be reused.",
        )
    try:
        canonical = _validate_and_verify_device_payload(
            user_id=user_id,
            device_id=nd.device_id,
            ed25519_identity_key=nd.ed25519_identity_key,
            curve25519_identity_key=nd.curve25519_identity_key,
            fallback_key_id=nd.fallback_key_id,
            fallback_public_key=nd.fallback_public_key,
            bundle_signature=nd.bundle_signature,
            one_time_keys=nd.one_time_keys,
            mls_key_packages=nd.mls_key_packages,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    new_version = e2ee_db.reset_all_user_devices_lost_keys(user_id)
    try:
        dev_doc, _ = e2ee_db.upsert_device_and_keys(
            user_id=user_id,
            device_id=nd.device_id,
            device_label=nd.device_label,
            ed25519_identity_key=nd.ed25519_identity_key,
            curve25519_identity_key=nd.curve25519_identity_key,
            fallback_key_id=nd.fallback_key_id,
            fallback_public_key=nd.fallback_public_key,
            bundle_signature=nd.bundle_signature,
            signed_payload=canonical,
            one_time_keys=nd.one_time_keys,
            mls_key_packages=[kp.model_dump() for kp in nd.mls_key_packages],
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    evt = e2ee_db.record_identity_event(
        user_id=user_id,
        event_type="identity_reset_lost_keys",
        device_id=nd.device_id,
        identity_version=new_version,
        details={
            "new_ed25519_identity_key": nd.ed25519_identity_key,
            "new_curve25519_identity_key": nd.curve25519_identity_key,
        },
    )

    peer_convs = e2ee_db.list_dm_conversations_for_user(user_id)
    notify_targets = [user_id] + [c["peer_user_id"] for c in peer_convs]
    _schedule_ws_notify(notify_targets, {"type": "identity_event", "event": evt})

    return {
        "success": True,
        "user_id": user_id,
        "identity_version": new_version,
        "device": dev_doc,
        "event": evt,
        "irrecoverable_history_notice": (
            "All previous device keys have been revoked and replaced. Previously encrypted "
            "messages cannot be decrypted unless you still hold a local device vault with those keys."
        ),
    }


@router.get("/identity/events")
def get_identity_security_events(
    user_ids: str = Query(..., description="Comma-separated user_ids to monitor (yourself and your chat peers)"),
    after_seq: int = Query(0, ge=0),
    _ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    # Peers use this to notice when a contact resets their identity or revokes a device (possible takeover).
    parsed_ids = [u.strip() for u in user_ids.split(",") if u.strip()][:50]
    events = e2ee_db.list_identity_events_for_users(parsed_ids, after_seq=after_seq)
    return {"events": events}


# ============================================================================
# 3. PRIVATE 1-TO-1 / MULTI-DEVICE OLM v2 MESSAGING ENDPOINTS
# ============================================================================

@router.post("/dm/messages")
def send_olm_dm_message(
    payload: DmCiphertextSubmitRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    sender_user_id = ctx["user"]["user_id"]
    if ctx["user"].get("account_status") == "muted":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is currently muted by moderation",
        )
    if platform_db.is_blocked_between(sender_user_id, payload.recipient_user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot send private messages when a block is active between accounts",
        )
    if payload.protocol != OLM_PROTOCOL_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported DM protocol; required {OLM_PROTOCOL_ID}",
        )

    sender_dev = e2ee_db.get_device(payload.sender_device_id)
    if (
        not sender_dev
        or sender_dev["user_id"] != sender_user_id
        or sender_dev["status"] != "active"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sender device is not registered and active for the authenticated user",
        )

    recipient_user = e2ee_db.get_user_by_id(payload.recipient_user_id)
    if not recipient_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipient user not found")

    if not payload.device_ciphertexts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="device_ciphertexts cannot be empty",
        )

    # Validate every per-device ciphertext is valid base64
    serialized_cts: Dict[str, Dict[str, Any]] = {}
    for target_dev_id, entry in payload.device_ciphertexts.items():
        if not DEVICE_ID_RE.match(target_dev_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid target device_id: {target_dev_id}",
            )
        _decode_b64_any(entry.ciphertext_b64, f"device_ciphertexts[{target_dev_id}]")
        serialized_cts[target_dev_id] = {
            "message_type": entry.message_type,
            "ciphertext_b64": entry.ciphertext_b64,
        }

    try:
        stored = e2ee_db.insert_dm_ciphertext(
            message_id=payload.message_id,
            sender_user_id=sender_user_id,
            sender_device_id=payload.sender_device_id,
            sender_curve25519_key=sender_dev["curve25519_identity_key"],
            sender_ed25519_key=sender_dev["ed25519_identity_key"],
            recipient_user_id=payload.recipient_user_id,
            protocol=payload.protocol,
            device_ciphertexts=serialized_cts,
            attachment_ids=payload.attachment_ids,
            event_kind=payload.event_kind,
            expires_at=chat_features_db.expires_at_for(chat_features_db.dm_scope_key(sender_user_id, payload.recipient_user_id)),
        )
    except e2ee_db.DuplicateMessageError as de:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(de))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    _schedule_ws_notify(
        [sender_user_id, payload.recipient_user_id],
        {
            "type": "dm_ciphertext",
            "conversation_id": stored["conversation_id"],
            "message_id": stored["message_id"],
            "seq": stored["seq"],
            "sender_user_id": sender_user_id,
            "recipient_user_id": payload.recipient_user_id,
            "event_kind": stored["event_kind"],
        },
    )

    return {
        "success": True,
        "expires_at": stored["expires_at"],
        "seq": stored["seq"],
        "message_id": stored["message_id"],
        "conversation_id": stored["conversation_id"],
        "timestamp": stored["timestamp"],
    }


@router.get("/dm/messages")
def get_olm_dm_messages(
    peer_user_id: str = Query(..., min_length=8, max_length=64),
    conversation_id: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    after_seq: int = Query(0, ge=0),
    limit: int = Query(60, ge=1, le=100),
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    requester_id = ctx["user"]["user_id"]
    chat_features_db.purge_expired_if_due()
    expected_conv = e2ee_db.make_dm_conversation_id(requester_id, peer_user_id)
    if conversation_id and conversation_id != expected_conv:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: not a participant in the requested conversation_id",
        )
    if device_id:
        dev = e2ee_db.get_device(device_id)
        if not dev or dev["user_id"] != requester_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: device_id does not belong to authenticated user",
            )

    msgs = e2ee_db.list_dm_ciphertexts(
        requester_user_id=requester_id,
        peer_user_id=peer_user_id,
        requester_device_id=device_id,
        after_seq=after_seq,
        limit=limit,
    )
    return {
        "conversation_id": expected_conv,
        "messages": msgs,
    }


class ReadMarkerRequest(BaseModel):
    scope_type: str = Field(..., pattern="^(dm|group)$")
    peer_user_id: Optional[str] = Field(None, min_length=3, max_length=64)
    group_id: Optional[str] = Field(None, min_length=3, max_length=64)
    last_read_seq: int = Field(..., ge=0)


@router.get("/unread")
def get_my_unread_counts(ctx: Dict[str, Any] = Depends(require_paid_member)):
    """Unread messages from other people per private chat and group (for notification badges)."""
    return read_markers_db.unread_counts(ctx["user"]["user_id"])


@router.post("/read-markers")
def mark_conversation_read(payload: ReadMarkerRequest, ctx: Dict[str, Any] = Depends(require_paid_member)):
    """Remembers how far this member has read a private chat or group. Only they ever see it."""
    user_id = ctx["user"]["user_id"]
    if payload.scope_type == "dm":
        if not payload.peer_user_id or not e2ee_db.get_user_by_id(payload.peer_user_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
        scope_key = read_markers_db.dm_scope_key(
            e2ee_db.make_dm_conversation_id(user_id, payload.peer_user_id)
        )
    else:
        if not payload.group_id or not e2ee_db.is_active_group_member(payload.group_id, user_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not in this group")
        scope_key = read_markers_db.group_scope_key(payload.group_id)
    read_markers_db.mark_read(user_id, scope_key, payload.last_read_seq)
    return {"success": True}


@router.get("/dm/conversations")
def list_my_dm_conversations(ctx: Dict[str, Any] = Depends(require_paid_member)):
    return {
        "conversations": e2ee_db.list_dm_conversations_for_user(ctx["user"]["user_id"])
    }


# ============================================================================
# 4. MLS RFC 9420 ENCRYPTED GROUP MESSAGING & MEMBERSHIP ENDPOINTS
# ============================================================================

@router.post("/mls/key-packages/claim")
def claim_mls_key_packages_endpoint(
    payload: MlsKeyPackageClaimRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    requester_id = ctx["user"]["user_id"]
    if platform_db.is_blocked_between(requester_id, payload.target_user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot claim KeyPackages from a blocked user",
        )
    _check_rate_limit("mls_kp_claim", f"{requester_id}:{payload.target_user_id}", max_hits=30, window_sec=60.0)
    packages = e2ee_db.claim_mls_key_packages_for_user(payload.target_user_id)
    if not packages:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user has no available unconsumed MLS KeyPackages",
        )
    return {
        "target_user_id": payload.target_user_id,
        "key_packages": packages,
    }


@router.post("/groups")
def create_encrypted_group_endpoint(
    payload: GroupCreateRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    user_id = ctx["user"]["user_id"]
    if payload.ciphersuite != MLS_CIPHERSUITE_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported MLS ciphersuite; required {MLS_CIPHERSUITE_ID}",
        )
    dev = e2ee_db.get_device(payload.creator_device_id)
    if not dev or dev["user_id"] != user_id or dev["status"] != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Creator device is not active and owned by authenticated user",
        )
    _decode_b64_any(payload.mls_group_id_b64, "mls_group_id_b64")

    if payload.is_paid:
        if platform_db.get_admin_role(user_id) != "superadmin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the platform admin can create a paid group.",
            )
        if not payload.entry_fee_usd or payload.entry_fee_usd <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A paid group needs an entry fee greater than $0.",
            )

    grp = e2ee_db.create_mls_group(
        mls_group_id_b64=payload.mls_group_id_b64,
        name=payload.name.strip(),
        creator_user_id=user_id,
        creator_device_id=payload.creator_device_id,
        ciphersuite=payload.ciphersuite,
        creator_profile=ctx["user"],
    )
    saved_policy = platform_db.upsert_group_access_policy(
        group_id=grp["group_id"],
        description=payload.description,
        visibility=payload.visibility,
        min_eth_balance_wei=payload.min_eth_balance_wei,
        require_invitation=payload.require_invitation,
        actor_user_id=user_id,
        is_paid=bool(payload.is_paid),
        entry_fee_usd=payload.entry_fee_usd if payload.is_paid else None,
        entry_fee_yearly_usd=payload.entry_fee_yearly_usd if payload.is_paid else None,
    )
    grp["policy"] = saved_policy
    return {"success": True, "group": grp}


@router.get("/groups")
def list_my_encrypted_groups(ctx: Dict[str, Any] = Depends(require_paid_member)):
    return {"groups": e2ee_db.list_groups_for_user(ctx["user"]["user_id"])}


@router.get("/groups/welcomes")
def get_pending_mls_welcomes(
    device_id: str = Query(..., min_length=12, max_length=52),
    consume: bool = Query(True),
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    user_id = ctx["user"]["user_id"]
    dev = e2ee_db.get_device(device_id)
    if not dev or dev["user_id"] != user_id or dev.get("status") != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden or revoked device_id")
    welcomes = e2ee_db.list_pending_welcomes(user_id=user_id, device_id=device_id, consume=consume)
    return {"welcomes": welcomes}


@router.post("/groups/welcomes/{welcome_id}/ack")
def ack_pending_mls_welcome(
    welcome_id: str,
    device_id: str = Query(..., min_length=12, max_length=52),
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    user_id = ctx["user"]["user_id"]
    dev = e2ee_db.get_device(device_id)
    if not dev or dev["user_id"] != user_id or dev.get("status") != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden or revoked device_id")
    acked = e2ee_db.ack_welcome_consumed(welcome_id=welcome_id, user_id=user_id, device_id=device_id)
    return {"success": True, "acknowledged": acked, "consumed": acked}


@router.get("/groups/invitations")
def list_my_group_invitations(ctx: Dict[str, Any] = Depends(require_paid_member)):
    """Groups an admin added me to that are waiting for my Accept / Reject."""
    return {"invitations": e2ee_db.list_group_invitations_for_user(ctx["user"]["user_id"])}


def _notify_group_admins_and_members(group_id: str, event: Dict[str, Any]) -> None:
    grp = e2ee_db.get_mls_group(group_id)
    uids = list({m["user_id"] for m in (grp["members"] if grp else []) if m["status"] == "active"})
    if uids:
        _schedule_ws_notify(uids, event)


@router.post("/groups/{group_id}/invitation/accept")
def accept_group_invitation(group_id: str, ctx: Dict[str, Any] = Depends(require_paid_member)):
    user_id = ctx["user"]["user_id"]
    grp = e2ee_db.get_mls_group(group_id)
    if not grp or not e2ee_db.has_group_invitation(group_id, user_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This invitation is no longer available.",
        )
    meets, reason = platform_db.verify_user_meets_group_policy(group_id, user_id)
    if not meets:
        pol = grp.get("policy") or {}
        if pol.get("is_paid") and not platform_db.has_user_paid_group_entry(user_id, group_id):
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail={
                    "code": "group_payment_required",
                    "message": reason,
                    "group_id": group_id,
                    "group_name": grp["name"],
                },
            )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)

    if not e2ee_db.respond_to_group_invitation(group_id, user_id, accept=True):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This invitation is no longer available.",
        )
    # This member's devices can now pick up the group keys and open the group.
    _schedule_ws_notify([user_id], {"type": "group_welcome", "group_id": group_id})
    _notify_group_admins_and_members(
        group_id,
        {
            "type": "group_invitation_response",
            "group_id": group_id,
            "accepted": True,
            "username": ctx["user"].get("username"),
        },
    )
    return {"success": True, "status": "joined", "group": e2ee_db.get_mls_group(group_id)}


@router.post("/groups/{group_id}/invitation/decline")
def decline_group_invitation(group_id: str, ctx: Dict[str, Any] = Depends(require_paid_member)):
    user_id = ctx["user"]["user_id"]
    if not e2ee_db.respond_to_group_invitation(group_id, user_id, accept=False):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="This invitation is no longer available.",
        )
    _notify_group_admins_and_members(
        group_id,
        {
            "type": "group_invitation_response",
            "group_id": group_id,
            "accepted": False,
            "username": ctx["user"].get("username"),
        },
    )
    return {"success": True, "status": "declined"}


@router.get("/groups/{group_id}")
def get_encrypted_group_details(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    user_id = ctx["user"]["user_id"]
    grp = e2ee_db.get_mls_group(group_id)
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    if not e2ee_db.is_active_group_member(group_id, user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: only active group members can inspect group membership state",
        )
    return {"group": grp}


@router.post("/groups/{group_id}/commits")
def submit_group_mls_commit(
    group_id: str,
    payload: GroupCommitSubmitRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    user_id = ctx["user"]["user_id"]
    _decode_b64_any(payload.mls_commit_b64, "mls_commit_b64")
    if payload.ratchet_tree_b64:
        _decode_b64_any(payload.ratchet_tree_b64, "ratchet_tree_b64")
    for w in payload.welcomes:
        _decode_b64_any(w.mls_welcome_b64, "mls_welcome_b64")

    if payload.commit_type == "add" and not payload.added_members:
        raise HTTPException(status_code=400, detail="add commit requires added_members")
    if payload.commit_type == "remove" and not payload.removed_members:
        raise HTTPException(status_code=400, detail="remove commit requires removed_members")

    if payload.commit_type not in ("add", "remove"):
        if payload.added_members or payload.removed_members or payload.welcomes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Commit type '{payload.commit_type}' cannot include added_members, removed_members, or welcomes",
            )

    if payload.added_members or payload.removed_members or payload.welcomes or payload.commit_type in ("add", "remove"):
        if not platform_db.is_group_admin(group_id, user_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only group admins can add or remove group members or issue welcomes",
            )

    if payload.added_members:
        for am in payload.added_members:
            dev = e2ee_db.get_device(am.device_id)
            if not dev or dev.get("user_id") != am.user_id or dev.get("status") != "active":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Added member device {am.device_id} is invalid, inactive, or not owned by {am.user_id}",
                )
            meets, reason = platform_db.verify_user_meets_group_policy(group_id, am.user_id)
            if not meets:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Candidate {am.user_id} does not meet group access policy: {reason}",
                )
            if platform_db.is_blocked_between(user_id, am.user_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Cannot add blocked user {am.user_id}",
                )

    # Someone an admin adds has to Accept first (like Instagram group invites). They join straight
    # away only if they already agreed: they asked to join (join request / invite code), they are
    # already in the group (a new device of theirs), or it is the admin's own device.
    added_members_out: List[Dict[str, Any]] = []
    invited_uids: Set[str] = set()
    if payload.added_members:
        grp_before = e2ee_db.get_mls_group(group_id)
        already_active = {
            m["user_id"] for m in (grp_before["members"] if grp_before else []) if m["status"] == "active"
        }
        consent_cache: Dict[str, bool] = {}
        for m in payload.added_members:
            row = m.model_dump()
            uid = row["user_id"]
            if uid not in consent_cache:
                consent_cache[uid] = (
                    uid == user_id
                    or uid in already_active
                    or platform_db.has_pending_join_request(group_id, uid)
                )
            if consent_cache[uid]:
                row["status"] = "active"
            else:
                row["status"] = e2ee_db.GROUP_INVITED_STATUS
                invited_uids.add(uid)
            added_members_out.append(row)

    try:
        res = e2ee_db.submit_mls_commit_atomic(
            group_id=group_id,
            committer_user_id=user_id,
            committer_device_id=payload.committer_device_id,
            expected_epoch=payload.expected_epoch,
            commit_type=payload.commit_type,
            mls_commit_b64=payload.mls_commit_b64,
            ratchet_tree_b64=payload.ratchet_tree_b64,
            added_members=added_members_out,
            removed_members=[m.model_dump() for m in payload.removed_members],
            welcomes=[w.model_dump() for w in payload.welcomes],
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except e2ee_db.EpochConflictError as ec:
        missing = e2ee_db.list_group_commits(
            group_id=group_id,
            requester_user_id=user_id,
            after_epoch=payload.expected_epoch,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": str(ec),
                "current_epoch": ec.current_epoch,
                "expected_epoch": ec.expected_epoch,
                "missing_commits": missing,
            },
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))

    if payload.commit_type == "add" and payload.added_members:
        approved_uids = list({am.user_id for am in payload.added_members} - invited_uids)
        platform_db.mark_group_join_requests_approved(group_id, approved_uids)

    grp = e2ee_db.get_mls_group(group_id)
    active_uids = [m["user_id"] for m in (grp["members"] if grp else []) if m["status"] == "active"]
    removed_uids = [m.user_id for m in payload.removed_members]
    _schedule_ws_notify(
        active_uids + removed_uids,
        {
            "type": "group_commit",
            "group_id": group_id,
            "epoch": res["epoch"],
            "commit_type": payload.commit_type,
        },
    )
    if payload.welcomes:
        welcome_uids = list({w.target_user_id for w in payload.welcomes} - invited_uids)
        if welcome_uids:
            _schedule_ws_notify(
                welcome_uids,
                {"type": "group_welcome", "group_id": group_id, "epoch": res["epoch"]},
            )
    if invited_uids:
        _schedule_ws_notify(
            list(invited_uids),
            {
                "type": "group_invitation",
                "group_id": group_id,
                "group_name": grp["name"] if grp else "",
                "invited_by_username": ctx["user"].get("username"),
            },
        )

    return {"success": True, "commit": res, "group": grp}


@router.get("/groups/{group_id}/commits")
def get_group_mls_commits(
    group_id: str,
    after_epoch: int = Query(0, ge=0),
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    try:
        commits = e2ee_db.list_group_commits(
            group_id=group_id,
            requester_user_id=ctx["user"]["user_id"],
            after_epoch=after_epoch,
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    return {"group_id": group_id, "commits": commits}


@router.post("/groups/{group_id}/messages")
def send_group_mls_message(
    group_id: str,
    payload: GroupMessageSubmitRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    user_id = ctx["user"]["user_id"]
    if ctx["user"].get("account_status") == "muted":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is currently muted by moderation",
        )
    meets, reason = platform_db.verify_user_meets_group_policy(group_id, user_id)
    if not meets:
        # Paid group whose subscription ran out: 402 with the group's id and name, exactly like
        # reading and Accept, so the app opens the renew window instead of showing a bare error.
        # (This used to be a 403, so sending after a lapse never offered renewal.)
        if platform_db.get_group_access_policy(group_id).get("is_paid") and not platform_db.has_user_paid_group_entry(
            user_id, group_id
        ):
            grp_info = e2ee_db.get_mls_group(group_id) or {}
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail={
                    "code": "group_payment_required",
                    "message": reason,
                    "group_id": group_id,
                    "group_name": grp_info.get("name") or "Group",
                },
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Group access policy requirement not met: {reason}",
        )
    is_message = payload.event_kind == "message"
    if is_message and chat_features_db.is_admins_only(group_id) and not platform_db.is_group_admin(group_id, user_id):
        # Announcement group: members may still react and vote (encrypted 'control' events).
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "admins_only", "message": "Only admins can send messages in this group."},
        )
    mentioned: List[str] = []
    if is_message:
        for mid in dict.fromkeys(payload.mention_user_ids):
            if mid != user_id and e2ee_db.is_active_group_member(group_id, mid):
                mentioned.append(mid)
    _decode_b64_any(payload.mls_ciphertext_b64, "mls_ciphertext_b64")

    try:
        stored = e2ee_db.insert_group_ciphertext(
            message_id=payload.message_id,
            group_id=group_id,
            epoch=payload.epoch,
            sender_user_id=user_id,
            sender_device_id=payload.sender_device_id,
            mls_ciphertext_b64=payload.mls_ciphertext_b64,
            attachment_ids=payload.attachment_ids,
            event_kind=payload.event_kind,
            expires_at=chat_features_db.expires_at_for(chat_features_db.group_scope_key(group_id)),
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except e2ee_db.EpochConflictError as ec:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": str(ec),
                "current_epoch": ec.current_epoch,
                "expected_epoch": ec.expected_epoch,
            },
        )
    except e2ee_db.DuplicateMessageError as de:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(de))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))

    grp = e2ee_db.get_mls_group(group_id)
    active_uids = [m["user_id"] for m in (grp["members"] if grp else []) if m["status"] == "active"]
    _schedule_ws_notify(
        active_uids,
        {
            "type": "group_ciphertext",
            "group_id": group_id,
            "epoch": stored["epoch"],
            "seq": stored["seq"],
            "message_id": stored["message_id"],
            "sender_user_id": user_id,
            "event_kind": stored["event_kind"],
        },
    )
    if mentioned:
        _schedule_ws_notify(
            mentioned,
            {
                "type": "mention",
                "scope_type": "group",
                "group_id": group_id,
                "message_id": stored["message_id"],
                "sender_user_id": user_id,
                "seq": stored["seq"],
            },
        )

    return {"success": True, "message": stored}


@router.get("/groups/{group_id}/messages")
def get_group_mls_messages(
    group_id: str,
    after_seq: int = Query(0, ge=0),
    limit: int = Query(60, ge=1, le=100),
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    chat_features_db.purge_expired_if_due()
    # Paid group: reading needs an active subscription too (402 lets the app show "renew").
    _pol = platform_db.get_group_access_policy(group_id)
    if _pol.get("is_paid") and not platform_db.has_user_paid_group_entry(ctx["user"]["user_id"], group_id):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="This group's subscription has expired. Renew it to keep chatting.",
        )
    try:
        msgs = e2ee_db.list_group_ciphertexts(
            group_id=group_id,
            requester_user_id=ctx["user"]["user_id"],
            after_seq=after_seq,
            limit=limit,
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))

    return {"group_id": group_id, "messages": msgs}


# ============================================================================
# 4b. CHAT FEATURES: delete for everyone, typing, pins, disappearing messages,
#     announcement-only groups, mute / archive  (message text never reaches the server)
# ============================================================================

def _conversation_scope(user_id: str, scope_type: str, peer_user_id: Optional[str], group_id: Optional[str]) -> Dict[str, Any]:
    """Resolves and authorises a private chat (with a peer) or a group for this member."""
    if scope_type == "dm":
        if not peer_user_id or peer_user_id == user_id or not e2ee_db.get_user_by_id(peer_user_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
        return {
            "scope_type": "dm",
            "scope_key": chat_features_db.dm_scope_key(user_id, peer_user_id),
            "scope_id": e2ee_db.make_dm_conversation_id(user_id, peer_user_id),
            "notify": [user_id, peer_user_id],
            "can_manage": True,  # either person in a private chat may pin / set the timer
            "peer_user_id": peer_user_id,
        }
    if scope_type == "group":
        if not group_id or not e2ee_db.get_mls_group(group_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
        if not e2ee_db.is_active_group_member(group_id, user_id):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only group members can do this")
        grp = e2ee_db.get_mls_group(group_id) or {}
        return {
            "scope_type": "group",
            "scope_key": chat_features_db.group_scope_key(group_id),
            "scope_id": group_id,
            "notify": list({m["user_id"] for m in grp.get("members", []) if m["status"] == "active"}),
            "can_manage": platform_db.is_group_admin(group_id, user_id),
            "group_id": group_id,
        }
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="scope_type must be 'dm' or 'group'")


def _state_changed(scope: Dict[str, Any], what: str) -> None:
    event: Dict[str, Any] = {"type": "conversation_state_changed", "scope_type": scope["scope_type"], "what": what}
    if scope["scope_type"] == "group":
        event["group_id"] = scope["group_id"]
    else:
        event["conversation_id"] = scope["scope_id"]
    _schedule_ws_notify(scope["notify"], event)


class ConversationRef(StrictModel):
    scope_type: str = Field(..., pattern=r"^(dm|group)$")
    peer_user_id: Optional[str] = Field(None, min_length=8, max_length=64)
    group_id: Optional[str] = Field(None, min_length=6, max_length=64)


class PinRequest(ConversationRef):
    message_id: str = Field(..., min_length=10, max_length=64)
    pinned: bool = True


class DisappearingRequest(ConversationRef):
    ttl_seconds: int = Field(..., ge=0)


class GroupSettingsRequest(StrictModel):
    admins_only_posting: bool


class ConversationPrefRequest(StrictModel):
    scope_key: str = Field(..., min_length=4, max_length=80)
    mute: Optional[str] = Field(None, pattern=r"^(off|8h|1w|always)$")
    archived: Optional[bool] = None


@router.post("/dm/messages/{message_id}/delete")
def delete_dm_message_for_everyone(message_id: str, ctx: Dict[str, Any] = Depends(require_paid_member)):
    """Delete for everyone in a private chat: the sender, within 48 hours. The stored copy is removed."""
    uid = ctx["user"]["user_id"]
    try:
        res = e2ee_db.delete_dm_message(message_id, uid)
    except e2ee_db.MessageDeleteError as de:
        raise HTTPException(status_code=de.status, detail=str(de))
    chat_features_db.unpin_everywhere(message_id)
    _schedule_ws_notify(
        [res["sender_user_id"], res["recipient_user_id"]],
        {"type": "message_deleted", "scope_type": "dm", "conversation_id": res["conversation_id"], "message_id": message_id},
    )
    return {"success": True, "message_id": message_id}


@router.post("/groups/{group_id}/messages/{message_id}/delete")
def delete_group_message_for_everyone(group_id: str, message_id: str, ctx: Dict[str, Any] = Depends(require_paid_member)):
    """Delete for everyone in a group: the sender within 48 hours, or a group admin at any time."""
    uid = ctx["user"]["user_id"]
    if not e2ee_db.is_active_group_member(group_id, uid):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only group members can delete messages")
    try:
        e2ee_db.delete_group_message(group_id, message_id, uid, platform_db.is_group_admin(group_id, uid))
    except e2ee_db.MessageDeleteError as de:
        raise HTTPException(status_code=de.status, detail=str(de))
    chat_features_db.unpin_everywhere(message_id)
    _notify_group_admins_and_members(group_id, {"type": "message_deleted", "scope_type": "group", "group_id": group_id, "message_id": message_id})
    return {"success": True, "message_id": message_id}


@router.post("/typing")
def send_typing_signal(payload: ConversationRef, ctx: Dict[str, Any] = Depends(require_paid_member)):
    """'Typing…' for the other people in a chat. Never sent for members who hide their online status."""
    uid = ctx["user"]["user_id"]
    _check_rate_limit("typing", uid, max_hits=40, window_sec=60.0)
    scope = _conversation_scope(uid, payload.scope_type, payload.peer_user_id, payload.group_id)  # authorise first
    ext = platform_db.get_extended_user_fields(uid) or {}
    if ext.get("show_online_presence") is False or ext.get("account_status") in ("muted", "suspended"):
        return {"success": True, "sent": False}
    if scope["scope_type"] == "dm":
        if platform_db.is_blocked_between(uid, scope["peer_user_id"]):
            return {"success": True, "sent": False}
        _schedule_ws_notify([scope["peer_user_id"]], {"type": "typing", "scope_type": "dm", "peer_user_id": uid, "user_id": uid})
    else:
        others = [u for u in scope["notify"] if u != uid]
        _schedule_ws_notify(others, {"type": "typing", "scope_type": "group", "group_id": scope["group_id"], "user_id": uid})
    return {"success": True, "sent": True}


@router.get("/conversations/state")
def get_conversation_state(
    scope_type: str = Query(..., pattern=r"^(dm|group)$"),
    peer_user_id: Optional[str] = Query(None, max_length=64),
    group_id: Optional[str] = Query(None, max_length=64),
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    """Pinned messages, disappearing timer, announcement mode and my mute / archive choice for one chat."""
    uid = ctx["user"]["user_id"]
    scope = _conversation_scope(uid, scope_type, peer_user_id, group_id)
    pref_key = f"dm:{peer_user_id}" if scope_type == "dm" else f"group:{group_id}"
    return {
        "scope_type": scope_type,
        "pins": chat_features_db.list_pins(scope["scope_key"]),
        "disappearing_ttl": chat_features_db.get_disappearing_ttl(scope["scope_key"]),
        "admins_only": chat_features_db.is_admins_only(group_id) if scope_type == "group" else False,
        "can_manage": scope["can_manage"],
        "pref": chat_features_db.get_pref(uid, pref_key),
    }


@router.post("/pins")
def pin_or_unpin_message(payload: PinRequest, ctx: Dict[str, Any] = Depends(require_paid_member)):
    """Group: admins pin. Private chat: either person. Up to 3 pins; a 4th replaces the oldest."""
    uid = ctx["user"]["user_id"]
    scope = _conversation_scope(uid, payload.scope_type, payload.peer_user_id, payload.group_id)
    if not scope["can_manage"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only group admins can pin messages")
    if payload.pinned and not e2ee_db.message_exists_in_scope(scope["scope_type"], scope["scope_id"], payload.message_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found in this chat")
    res = chat_features_db.set_pin(scope["scope_key"], payload.message_id, uid, payload.pinned)
    _state_changed(scope, "pins")
    return {"success": True, **res}


@router.post("/disappearing")
def set_disappearing_messages(payload: DisappearingRequest, ctx: Dict[str, Any] = Depends(require_paid_member)):
    """Timer for NEW messages: 0 (off), 86400 (24 h), 604800 (7 days) or 7776000 (90 days).
    Group: admins only. Private chat: either person. The server removes its copies when time is up."""
    uid = ctx["user"]["user_id"]
    scope = _conversation_scope(uid, payload.scope_type, payload.peer_user_id, payload.group_id)
    if not scope["can_manage"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only group admins can change disappearing messages")
    try:
        ttl = chat_features_db.set_disappearing_ttl(scope["scope_key"], payload.ttl_seconds, uid)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    _state_changed(scope, "disappearing")
    return {"success": True, "disappearing_ttl": ttl}


@router.post("/groups/{group_id}/settings")
def update_group_chat_settings(group_id: str, payload: GroupSettingsRequest, ctx: Dict[str, Any] = Depends(require_paid_member)):
    """Announcement group: only admins post; members read, react and vote."""
    uid = ctx["user"]["user_id"]
    scope = _conversation_scope(uid, "group", None, group_id)
    if not scope["can_manage"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only group admins can change this")
    value = chat_features_db.set_admins_only(group_id, payload.admins_only_posting, uid)
    _state_changed(scope, "settings")
    return {"success": True, "admins_only": value}


@router.get("/conversation-prefs")
def list_my_conversation_prefs(ctx: Dict[str, Any] = Depends(require_paid_member)):
    """My muted and archived chats (keys: 'dm:<peer_user_id>', 'group:<group_id>', 'room')."""
    return {"prefs": chat_features_db.get_prefs(ctx["user"]["user_id"])}


@router.post("/conversation-prefs")
def set_my_conversation_pref(payload: ConversationPrefRequest, ctx: Dict[str, Any] = Depends(require_paid_member)):
    uid = ctx["user"]["user_id"]
    key = payload.scope_key
    if not chat_features_db.is_valid_pref_key(key):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown chat")
    if key.startswith("dm:") and not e2ee_db.get_user_by_id(key[3:]):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    if key.startswith("group:") and not e2ee_db.get_member_record(key[6:], uid):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only group members can do this")
    try:
        pref = chat_features_db.set_pref(uid, key, mute=payload.mute, archived=payload.archived)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    _schedule_ws_notify([uid], {"type": "conversation_prefs_changed", "scope_key": key})  # my other devices
    return {"success": True, "scope_key": key, "pref": pref}


# ============================================================================
# 5. ENCRYPTED FILE ATTACHMENTS (CIPHERTEXT-ONLY BLOB API)
# ============================================================================

def _authorize_attachment_scope(scope_type: str, scope_id: str, user_id: str) -> None:
    if scope_type == "group":
        if not e2ee_db.is_active_group_member(scope_id, user_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not an active member of attachment's encrypted group",
            )
    elif scope_type == "dm":
        if scope_id.startswith("usr_"):
            if platform_db.is_blocked_between(user_id, scope_id):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot exchange attachments with blocked user")
            return
        convs = e2ee_db.list_dm_conversations_for_user(user_id)
        if any(c["conversation_id"] == scope_id for c in convs):
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for this DM attachment conversation",
        )


@router.post("/attachments")
def upload_encrypted_attachment(
    payload: EncryptedAttachmentUploadRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    user_id = ctx["user"]["user_id"]
    dev = e2ee_db.get_device(payload.uploader_device_id)
    if not dev or dev["user_id"] != user_id or dev["status"] != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid uploader device")

    raw_ct = _decode_b64_any(payload.ciphertext_b64, "ciphertext_b64")
    if len(raw_ct) > MAX_ATTACHMENT_BYTES:
        raise HTTPException(status_code=413, detail="Encrypted attachment exceeds 5 MiB limit")
    if len(raw_ct) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty files cannot be sent")
    _check_rate_limit("e2ee_attachment_upload", user_id, max_hits=30, window_sec=60.0)
    since = e2ee_db.coarse_timestamp_iso(e2ee_db.now_utc() - timedelta(hours=24))
    used = e2ee_db.encrypted_attachment_usage_since(user_id, since)
    if used["files"] + 1 > E2EE_DAILY_MAX_FILES or used["bytes"] + len(raw_ct) > E2EE_DAILY_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Daily file limit reached: up to {E2EE_DAILY_MAX_FILES} files and "
                f"{E2EE_DAILY_MAX_BYTES // (1024 * 1024)} MB in 24 hours across private chats and groups."
            ),
        )

    computed_sha256 = hashlib.sha256(raw_ct).hexdigest()
    if not secrets.compare_digest(computed_sha256.lower(), payload.ciphertext_sha256.lower()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Attachment ciphertext SHA-256 integrity mismatch",
        )

    scope_id = payload.scope_id
    if payload.scope_type == "dm" and scope_id.startswith("usr_"):
        scope_id = e2ee_db.make_dm_conversation_id(user_id, scope_id)
    elif payload.scope_type == "group":
        _authorize_attachment_scope("group", scope_id, user_id)

    stored = e2ee_db.store_encrypted_attachment(
        scope_type=payload.scope_type,
        scope_id=scope_id,
        uploader_user_id=user_id,
        uploader_device_id=payload.uploader_device_id,
        algorithm=payload.algorithm,
        ciphertext_b64=payload.ciphertext_b64,
        ciphertext_sha256=computed_sha256,
        byte_length=len(raw_ct),
    )
    return {"success": True, "attachment": stored}


@router.get("/attachments/{attachment_id}")
def download_encrypted_attachment(
    attachment_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    user_id = ctx["user"]["user_id"]
    att = e2ee_db.get_encrypted_attachment(attachment_id)
    if not att:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attachment not found")
    if att["revoked"]:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Attachment has been revoked")

    if att["uploader_user_id"] != user_id:
        _authorize_attachment_scope(att["scope_type"], att["scope_id"], user_id)

    return {"attachment": att}


@router.post("/attachments/{attachment_id}/revoke")
def revoke_encrypted_attachment_endpoint(
    attachment_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    try:
        e2ee_db.revoke_encrypted_attachment(attachment_id, ctx["user"]["user_id"])
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    return {"success": True, "attachment_id": attachment_id, "revoked": True}


# ============================================================================
# 6. AUTHENTICATED REAL-TIME WEBSOCKET (`/ws/e2ee`)
# ============================================================================

@ws_router.websocket("/ws/e2ee")
async def e2ee_realtime_websocket(websocket: WebSocket):
    """
    Secure WebSocket transport for real-time ciphertext & epoch delivery notifications.
    Authenticates via HttpOnly cookie or first-frame JSON `{ "type": "auth", "token": "..." }`
    so bearer tokens are never leaked in URL query strings.
    """
    await websocket.accept()
    user_id: Optional[str] = None
    if realtime_hub.at_capacity("e2ee"):
        await websocket.close(code=4503)  # server full: the app retries later with a long delay
        return

    try:
        cookie_tok = websocket.cookies.get(SESSION_COOKIE_NAME)
        auth_header = websocket.headers.get("authorization", "")
        initial_tok = cookie_tok
        if not initial_tok and auth_header.lower().startswith("bearer "):
            initial_tok = auth_header[7:].strip()

        if initial_tok:
            # DB lookup runs in a worker thread so it can never freeze the live-update loop
            sess = await asyncio.to_thread(e2ee_db.get_session_by_token, initial_tok)
            if sess:
                user_id = sess["user_id"]

        if not user_id:
            raw_msg = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
            if not isinstance(raw_msg, dict) or raw_msg.get("type") != "auth":
                await websocket.close(code=4401)
                return
            sess = await asyncio.to_thread(e2ee_db.get_session_by_token, str(raw_msg.get("token") or ""))
            if not sess:
                await websocket.close(code=4401)
                return
            user_id = sess["user_id"]

        realtime_hub.register(user_id, websocket)
        await websocket.send_json({"type": "authenticated", "user_id": user_id})
        await realtime_hub.broadcast_public_presence()

        while True:
            msg = await websocket.receive_json()
            if isinstance(msg, dict) and msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except (WebSocketDisconnect, asyncio.TimeoutError, Exception):
        pass
    finally:
        if user_id:
            realtime_hub.unregister(user_id, websocket)
            await realtime_hub.broadcast_public_presence()