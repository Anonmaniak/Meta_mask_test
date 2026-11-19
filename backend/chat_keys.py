"""
Wallet-Bound Public Encryption Key Registration and Lookup Module.
FastAPI Router for E2EE chat public keys, challenge generation,
EIP-191 signature verification, and NIST P-256 public key validation.
"""

import os
import time
import base64
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Request, status
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

# NIST P-256 (secp256r1) Elliptic Curve Parameters
P_256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_256_A = P_256_P - 3
P_256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

CHALLENGE_TTL_SECONDS = int(os.getenv("CHAT_KEY_CHALLENGE_TTL_SECONDS", "300"))  # 5 minutes
APP_DOMAIN = os.getenv("APP_DOMAIN", "zyphra.in")
APP_URI = os.getenv("FRONTEND_URL", "https://zyphra.in").split(",")[0].strip().rstrip("/")

import logging
import chat_db

logger = logging.getLogger("chat_keys")

router = APIRouter(prefix="/api/chat/keys", tags=["chat-keys"])

# In-memory storage cache for challenges and public keys (persisted to Neon PostgreSQL via chat_db)
_in_memory_challenges: Dict[str, Dict[str, Any]] = {}
_in_memory_public_keys: Dict[str, Dict[str, Any]] = {}

# Simple rate limiter for challenge requests: { "ip_or_addr": [timestamp, ...] }
_rate_limit_records: Dict[str, List[float]] = {}
RATE_LIMIT_MAX_CHALLENGES = 10  # Max challenges
RATE_LIMIT_WINDOW_SECONDS = 60  # per 60 seconds


# ============================================================================
# Pydantic Request & Response Models
# ============================================================================

class ChatPublicKeyModel(BaseModel):
    version: int = Field(1, description="Public key representation version (must be 1)")
    curve: str = Field("P-256", description="Elliptic curve, must be P-256")
    format: str = Field("raw+jwk", description="Key format")
    rawBase64Url: str = Field(..., min_length=86, max_length=92, description="65-byte uncompressed EC point in base64url")
    jwk: Optional[Dict[str, Any]] = Field(None, description="RFC 7517 compliant JSON Web Key")
    fingerprint: str = Field(..., min_length=40, max_length=50, description="SHA-256 digest of raw key in base64url")


class ChatKeyChallengeRequest(BaseModel):
    address: str = Field(..., description="EVM wallet address to be challenged")
    public_key_fingerprint: str = Field(..., min_length=40, max_length=50, description="SHA-256 fingerprint of the public key to bind")
    chain_id: Optional[int] = Field(1, description="EVM chain ID")


class ChatKeyChallengeResponse(BaseModel):
    challenge_id: str
    address: str
    message: str
    expires_at: str
    public_key_fingerprint: str


class ChatKeyRegisterRequest(BaseModel):
    address: str = Field(..., description="EVM wallet address")
    challenge_id: str = Field(..., min_length=16, max_length=64, description="Server-issued challenge nonce")
    signature: str = Field(..., min_length=130, max_length=134, description="EIP-191 signature hex")
    public_key: ChatPublicKeyModel = Field(..., description="Canonical public encryption key")
    key_version: int = Field(1, ge=1, description="Key format/protocol version")
    rotate: bool = Field(False, description="Explicit rotation flag if replacing an existing key")


class ChatKeyRegisterResponse(BaseModel):
    success: bool
    address: str
    fingerprint: str
    key_version: int
    created_at: str
    updated_at: str
    rotated: bool


class ChatKeyLookupResponse(BaseModel):
    address: str
    registered: bool
    public_key: Optional[ChatPublicKeyModel] = None
    fingerprint: Optional[str] = None
    key_version: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class BatchChatKeyLookupRequest(BaseModel):
    addresses: List[str] = Field(..., min_length=1, max_length=100, description="List of EVM wallet addresses to lookup")


# ============================================================================
# Cryptographic Validation & Helpers
# ============================================================================

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_utc().isoformat()


def decode_base64url(s: str) -> bytes:
    """Decodes a base64url string with or without padding."""
    if not isinstance(s, str) or not s:
        raise ValueError("Invalid base64url input")
    rem = len(s) % 4
    padded = s + ("=" * (4 - rem) if rem > 0 else "")
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def encode_base64url(b: bytes) -> str:
    """Encodes bytes into a base64url string without padding."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def compute_key_fingerprint(raw_bytes: bytes) -> str:
    """Computes SHA-256 base64url fingerprint of the raw public key bytes."""
    digest = hashlib.sha256(raw_bytes).digest()
    return encode_base64url(digest)


def validate_p256_public_key(raw_bytes: bytes) -> bool:
    """
    Mathematically verifies whether the given bytes form a valid, non-infinity
    uncompressed public key point on the NIST P-256 (secp256r1) elliptic curve.
    Equation: y^2 == x^3 - 3x + b (mod p).
    """
    if len(raw_bytes) != 65 or raw_bytes[0] != 0x04:
        return False
    x = int.from_bytes(raw_bytes[1:33], "big")
    y = int.from_bytes(raw_bytes[33:65], "big")
    if not (0 < x < P_256_P and 0 < y < P_256_P):
        return False
    lhs = pow(y, 2, P_256_P)
    rhs = (pow(x, 3, P_256_P) + (P_256_A * x) + P_256_B) % P_256_P
    return lhs == rhs


def build_challenge_message(
    domain: str,
    address: str,
    nonce: str,
    fingerprint: str,
    uri: str,
    chain_id: int,
    issued_at: str,
    expires_at: str,
) -> str:
    """
    Constructs an unambiguous, domain-separated human-readable message for wallet signing.
    Strictly identifies purpose as chat key registration, binding domain, address, nonce,
    and public key fingerprint.
    """
    return (
        f"{domain} wants you to register your chat encryption key for:\n"
        f"{address}\n\n"
        f"Purpose: End-to-End Chat Key Registration\n"
        f"URI: {uri}\n"
        f"Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Key Fingerprint: {fingerprint}\n"
        f"Issued At: {issued_at}\n"
        f"Expires At: {expires_at}"
    )


def check_rate_limit(key: str) -> bool:
    """Sliding-window rate limiter. Returns True if allowed, False if rate limited."""
    now = time.time()
    if len(_rate_limit_records) > 5000:
        stale = [k for k, v in _rate_limit_records.items() if not v or (now - v[-1] >= 300)]
        for k in stale:
            _rate_limit_records.pop(k, None)
    records = _rate_limit_records.get(key, [])
    records = [t for t in records if now - t < RATE_LIMIT_WINDOW_SECONDS]
    if len(records) >= RATE_LIMIT_MAX_CHALLENGES:
        _rate_limit_records[key] = records
        return False
    records.append(now)
    _rate_limit_records[key] = records
    return True


# ============================================================================
# Database Index Initializer
# ============================================================================

def init_chat_key_indexes(db=None):
    """Initializes indexes on chat_public_keys in Neon PostgreSQL idempotently."""
    try:
        chat_db.init_chat_db()
    except Exception as e:
        print(f"ℹ️  Notice during chat key index initialization: {e}")


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/challenge", response_model=ChatKeyChallengeResponse)
def create_chat_key_challenge(payload: ChatKeyChallengeRequest, request: Request):
    """
    Generates a single-use, time-bounded challenge for wallet-ownership verification.
    Binds domain, wallet address, nonce, and the target public key fingerprint.
    """
    if not Web3.is_address(payload.address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid EVM wallet address format",
        )

    checksum_address = Web3.to_checksum_address(payload.address)

    # Rate limiting by client IP and address
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{checksum_address.lower()}"
    if not check_rate_limit(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many challenge requests. Please wait a moment before requesting another challenge.",
        )

    fp = payload.public_key_fingerprint.strip()
    if not fp or len(fp) < 40 or len(fp) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid public key fingerprint length",
        )

    nonce = secrets.token_hex(16)
    now = _now_utc()
    expires_dt = now + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    issued_at = now.isoformat()
    expires_at = expires_dt.isoformat()
    chain_id = int(payload.chain_id or 1)

    message = build_challenge_message(
        domain=APP_DOMAIN,
        address=checksum_address,
        nonce=nonce,
        fingerprint=fp,
        uri=APP_URI,
        chain_id=chain_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )

    challenge_record = {
        "_id": nonce,
        "challenge_id": nonce,
        "address": checksum_address,
        "public_key_fingerprint": fp,
        "nonce": nonce,
        "message": message,
        "chain_id": chain_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "consumed": False,
        "created_at": issued_at,
    }

    # Persist challenge in memory cache and Neon PostgreSQL
    _in_memory_challenges[nonce] = dict(challenge_record)
    try:
        chat_db.save_chat_challenge(challenge_record)
    except Exception:
        pass

    return ChatKeyChallengeResponse(
        challenge_id=nonce,
        address=checksum_address,
        message=message,
        expires_at=expires_at,
        public_key_fingerprint=fp,
    )


@router.post("/register", response_model=ChatKeyRegisterResponse)
def register_chat_public_key(payload: ChatKeyRegisterRequest):
    """
    Registers or rotates a public encryption key bound to a verified wallet.
    Verifies EIP-191 signature over the exact server-issued challenge, verifies
    NIST P-256 curve mathematics, ensures single-use challenge consumption,
    and applies explicit key rotation rules.
    """
    if not Web3.is_address(payload.address):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid EVM address")

    checksum_address = Web3.to_checksum_address(payload.address)

    # 1. Validate public key curve and metadata
    pk = payload.public_key
    if pk.version != 1 or pk.curve != "P-256":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported key parameters. Must be version 1 on NIST P-256 curve.",
        )

    # 2. Decode and mathematically validate NIST P-256 point
    try:
        raw_bytes = decode_base64url(pk.rawBase64Url)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64url encoding in public key raw bytes",
        )

    if not validate_p256_public_key(raw_bytes):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Public key point does not lie on the NIST P-256 elliptic curve",
        )

    # 3. Verify fingerprint
    computed_fp = compute_key_fingerprint(raw_bytes)
    if computed_fp != pk.fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Public key fingerprint mismatch",
        )

    # 4. Fetch challenge record (check memory cache first, then Neon PostgreSQL)
    challenge = _in_memory_challenges.get(payload.challenge_id) or chat_db.get_chat_challenge(payload.challenge_id)

    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge not found or invalid challenge identifier",
        )

    # 5. Verify challenge constraints
    if challenge.get("consumed", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge has already been consumed. Single-use nonces cannot be replayed.",
        )

    if challenge.get("address", "").lower() != checksum_address.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge was issued for a different wallet address",
        )

    if challenge.get("public_key_fingerprint") != computed_fp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge public key fingerprint does not match submitted key",
        )

    # Check expiration
    expires_at_str = challenge.get("expires_at", "")
    try:
        expires_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        if _now_utc() > expires_dt:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Challenge has expired. Please request a fresh challenge.",
            )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Corrupted challenge expiration")

    # 6. Verify EIP-191 signature
    challenge_message = challenge.get("message", "")
    try:
        msg_hash = encode_defunct(text=challenge_message)
        recovered_address = Account.recover_message(msg_hash, signature=payload.signature)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to decode or recover wallet signature",
        )

    if recovered_address.lower() != checksum_address.lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signature verification failed: recovered signer does not match wallet address",
        )

    # 7. Atomically consume challenge
    now_iso = _now_iso()
    if challenge.get("consumed"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge has already been consumed. Single-use nonces cannot be replayed.",
        )
    if payload.challenge_id in _in_memory_challenges:
        _in_memory_challenges[payload.challenge_id]["consumed"] = True
        _in_memory_challenges[payload.challenge_id]["consumed_at"] = now_iso
    try:
        chat_db.consume_chat_challenge(payload.challenge_id)
    except Exception:
        pass

    # 8. Check existing registration and enforce Key Rotation policy
    existing_key = _in_memory_public_keys.get(checksum_address) or chat_db.get_chat_key(checksum_address)

    is_rotation = False
    created_at = now_iso

    prev_history: List[Dict[str, Any]] = []
    if existing_key:
        # Neon rows use registered_at / public_key_fingerprint / rotation_history;
        # in-memory docs use created_at / fingerprint / previous_keys.
        created_at = existing_key.get("created_at") or existing_key.get("registered_at") or now_iso
        existing_fp = existing_key.get("fingerprint") or existing_key.get("public_key_fingerprint")
        prev_history = list(existing_key.get("previous_keys") or existing_key.get("rotation_history") or [])

        if existing_fp == computed_fp:
            # Re-registration of identical key: update timestamp without rotation
            is_rotation = False
        else:
            # Different key requested! Check explicit rotation flag
            if not payload.rotate:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "A chat encryption key is already registered for this wallet. "
                        "Explicit rotation flag (rotate=true) is required to replace an existing key."
                    ),
                )
            is_rotation = True

    # 9. Persist public key record (private keys are strictly never accepted or stored)
    key_doc = {
        "_id": checksum_address,
        "address": checksum_address,
        "public_key": {
            "version": pk.version,
            "curve": pk.curve,
            "format": pk.format,
            "rawBase64Url": pk.rawBase64Url,
            "jwk": pk.jwk,
            "fingerprint": computed_fp,
        },
        "fingerprint": computed_fp,
        "key_version": payload.key_version,
        "created_at": created_at,
        "updated_at": now_iso,
        "last_verified_at": now_iso,
        "rotations_count": (existing_key.get("rotations_count", len(prev_history)) + 1) if is_rotation else (existing_key.get("rotations_count", len(prev_history)) if existing_key else 0),
    }

    if is_rotation and existing_key:
        history_entry = {
            "fingerprint": existing_fp,
            "replaced_at": now_iso,
            "key_version": existing_key.get("key_version", 1),
        }
        key_doc["previous_keys"] = prev_history + [history_entry]

    _in_memory_public_keys[checksum_address] = key_doc

    try:
        chat_db.insert_or_update_chat_key({
            "address": checksum_address,
            "public_key": pk.model_dump(),
            "public_key_raw_b64": pk.rawBase64Url,
            "public_key_fingerprint": computed_fp,
            "algorithm": "ECDH-ES+A256GCM",
            "curve": pk.curve,
            "key_format_version": payload.key_version,
            "status": "active",
            "registered_at": created_at,
            "rotation_history": key_doc.get("previous_keys", [])
        })
    except Exception as exc:
        logger.error("Failed to persist chat public key to database for %s: %s", checksum_address, exc, exc_info=True)

    return ChatKeyRegisterResponse(
        success=True,
        address=checksum_address,
        fingerprint=computed_fp,
        key_version=payload.key_version,
        created_at=created_at,
        updated_at=now_iso,
        rotated=is_rotation,
    )


@router.get("/{address}", response_model=ChatKeyLookupResponse)
def lookup_chat_public_key(address: str):
    """
    Retrieves the registered public encryption key and metadata for a given wallet.
    Returns 404 with documented schema if no key has been registered for the wallet.
    Never returns private keys, challenge nonces, or raw signatures.
    """
    if not Web3.is_address(address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid EVM address format",
        )

    checksum_address = Web3.to_checksum_address(address)

    doc = _in_memory_public_keys.get(checksum_address)
    if not doc:
        try:
            doc = chat_db.get_chat_key(checksum_address)
        except Exception as exc:
            logger.error("Database error looking up chat public key for %s: %s", checksum_address, exc, exc_info=True)
            doc = None

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No public encryption key registered for this wallet address",
        )

    pk_dict = doc.get("public_key", {})
    return ChatKeyLookupResponse(
        address=checksum_address,
        registered=True,
        public_key=ChatPublicKeyModel(
            version=pk_dict.get("version", 1),
            curve=pk_dict.get("curve", "P-256"),
            format=pk_dict.get("format", "raw+jwk"),
            rawBase64Url=pk_dict.get("rawBase64Url", ""),
            jwk=pk_dict.get("jwk"),
            fingerprint=doc.get("fingerprint") or doc.get("public_key_fingerprint", ""),
        ),
        fingerprint=doc.get("fingerprint") or doc.get("public_key_fingerprint"),
        key_version=doc.get("key_version", 1),
        created_at=doc.get("created_at") or doc.get("registered_at"),
        updated_at=doc.get("updated_at") or doc.get("last_updated_at"),
    )


@router.post("/lookup")
def batch_lookup_chat_public_keys(payload: BatchChatKeyLookupRequest):
    """
    Batch lookup for multiple wallet addresses.
    Returns a dictionary mapping normalized addresses to their lookup responses.
    """
    results: Dict[str, Any] = {}
    normalized_map = {}

    for raw in payload.addresses:
        if Web3.is_address(raw):
            norm = Web3.to_checksum_address(raw)
            normalized_map[norm] = raw

    if not normalized_map:
        return {"keys": {}}

    found_docs = {}
    # First check in-memory cache
    for norm in normalized_map:
        if norm in _in_memory_public_keys:
            found_docs[norm] = _in_memory_public_keys[norm]

    # For any remaining addresses, query chat_db (Neon PostgreSQL)
    remaining = [addr for addr in normalized_map if addr not in found_docs]
    if remaining:
        try:
            db_docs = chat_db.get_chat_keys_batch(remaining)
            for addr, doc in db_docs.items():
                found_docs[addr] = doc
        except Exception as exc:
            logger.error("Database error during batch chat keys lookup: %s", exc, exc_info=True)

    for norm in normalized_map:
        doc = found_docs.get(norm)
        if doc:
            pk_dict = doc.get("public_key", {})
            fp = doc.get("fingerprint") or doc.get("public_key_fingerprint")
            results[norm] = {
                "address": norm,
                "registered": True,
                "public_key": pk_dict,
                "fingerprint": fp,
                "key_version": doc.get("key_version", 1),
                "created_at": doc.get("created_at") or doc.get("registered_at"),
                "updated_at": doc.get("updated_at") or doc.get("last_updated_at"),
            }
        else:
            results[norm] = {
                "address": norm,
                "registered": False,
                "public_key": None,
                "fingerprint": None,
                "key_version": None,
                "created_at": None,
                "updated_at": None,
            }

    return {"keys": results}