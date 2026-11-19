"""
FastAPI Router for Cryptographic Global Envelope Channel.
Enforces:
1. Strict ciphertext-only transmission and storage. Zero plaintext accepted or stored.
2. EIP-191 cryptographic sender authentication (prevents sender spoofing).
3. Neon PostgreSQL persistence via chat_db.py.
4. Authoritative room recipient directory lookup for multi-recipient encryption.
5. Public anonymous feed reading of encrypted envelopes with locked placeholders.
"""

import re
import json
import base64
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator
from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

import chat_db

logger = logging.getLogger("chat_routes")

router = APIRouter(prefix="/api/chat", tags=["chat-e2ee"])

SUPPORTED_PROTOCOL_VERSIONS = {1}
SUPPORTED_KEY_VERSIONS = {1}
PROTOCOL_ALGORITHM = "ECDH-P256-HKDF-AES-GCM-256"
AES_GCM_IV_BYTE_LENGTH = 12
MIN_CIPHERTEXT_BYTES = 16  # 128-bit authentication tag minimum
MAX_CIPHERTEXT_BYTES = 65536  # 64 KB safe payload ceiling
MIN_WRAPPED_KEY_BYTES = 32
MAX_WRAPPED_KEY_BYTES = 256
MAX_ROOM_RECIPIENTS = 50
MAX_ENCRYPTED_REQUEST_BYTES = 131072  # 128 KB safe ceiling for encrypted envelopes
SIGNATURE_WINDOW_SECONDS = 300  # 5 minutes

BASE64URL_PATTERN = re.compile(r'^[A-Za-z0-9_-]+={0,2}$')


def validate_base64url_string(
    value: str,
    field_name: str,
    exact_bytes: Optional[int] = None,
    min_bytes: Optional[int] = None,
    max_bytes: Optional[int] = None,
) -> bytes:
    """
    Validates that a string is strictly URL-safe base64 encoded and decodes within expected byte limits.
    Rejects illegal characters, invalid padding/lengths, and out-of-bound byte sizes.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty base64url string")

    val = value.strip()
    if not BASE64URL_PATTERN.match(val):
        raise ValueError(f"{field_name} contains invalid base64url characters")

    unpadded = val.rstrip("=")
    remainder = len(unpadded) % 4
    if remainder == 1:
        raise ValueError(f"{field_name} has invalid base64url length")

    padded = unpadded + ("=" * (4 - remainder) if remainder else "")
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise ValueError(f"{field_name} is not valid base64url encoded data: {exc}")

    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise ValueError(f"{field_name} must decode to exactly {exact_bytes} bytes (got {len(decoded)})")

    if min_bytes is not None and len(decoded) < min_bytes:
        raise ValueError(f"{field_name} must decode to at least {min_bytes} bytes (got {len(decoded)})")

    if max_bytes is not None and len(decoded) > max_bytes:
        raise ValueError(f"{field_name} exceeds maximum allowed size of {max_bytes} bytes (got {len(decoded)})")

    return decoded


# ============================================================================
# Canonical Envelope Representation & Integrity Hashing
# ============================================================================

def build_canonical_envelope_dict(
    message_id: str,
    sender: str,
    channel: str,
    timestamp: str,
    version: int,
    algorithm: str,
    key_version: int,
    content_iv: str,
    content_ciphertext: str,
    recipients: List[Dict[str, str]],
) -> Dict[str, Any]:
    """
    Constructs a deterministic canonical dictionary of the security-relevant envelope fields.
    Enforces:
    - Normalization of addresses to lowercase
    - Rejection of duplicate recipient addresses
    - Deterministic lexicographical sorting of recipients by recipient address
    - Complete cryptographic binding of ciphertext, IVs, key wrappers, and metadata
    """
    seen = set()
    for r in recipients:
        addr = str(r.get("recipient", "")).strip().lower()
        if not addr:
            raise ValueError("Recipient address cannot be empty in envelope wrapper")
        if addr in seen:
            raise ValueError(f"Duplicate recipient address in envelope: {r.get('recipient')}")
        seen.add(addr)

    sorted_recipients = sorted(
        [
            {
                "iv": str(r.get("iv", "")),
                "keyFingerprint": str(r.get("keyFingerprint", "")),
                "recipient": str(r.get("recipient", "")).strip().lower(),
                "wrappedKey": str(r.get("wrappedKey", "")),
            }
            for r in recipients
        ],
        key=lambda x: x["recipient"],
    )

    room_val = str(channel).strip()
    return {
        "algorithm": str(algorithm).strip(),
        "channel": room_val,
        "content_ciphertext": str(content_ciphertext).strip(),
        "content_iv": str(content_iv).strip(),
        "key_version": int(key_version),
        "message_id": str(message_id).strip(),
        "recipients": sorted_recipients,
        "room": room_val,
        "sender": str(sender).strip().lower(),
        "timestamp": str(timestamp).strip(),
        "version": int(version),
    }


def compute_canonical_envelope_hash(canonical_dict: Dict[str, Any]) -> str:
    """
    Generates a deterministic SHA-256 hex digest of the canonical envelope dictionary
    using strict sorted-key, whitespace-free JSON serialization.
    """
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def build_envelope_signing_text(
    sender: str,
    message_id: str,
    room: str,
    timestamp: str,
    envelope_hash: str,
) -> str:
    """
    Generates the exact EIP-191 human-readable message text verified by the sender's wallet.
    Cryptographically binds both the room/timestamp metadata and the full envelope SHA-256 hash.
    """
    checksummed_sender = Web3.to_checksum_address(sender) if Web3.is_address(sender) else sender
    return (
        f"zyphra.in Chat Message\n"
        f"Sender: {checksummed_sender}\n"
        f"Message ID: {message_id}\n"
        f"Room: {room}\n"
        f"Timestamp: {timestamp}\n"
        f"Envelope Hash: {envelope_hash}"
    )


# ============================================================================
# Pydantic Schemas
# ============================================================================

class RecipientKeyWrapperModel(BaseModel):
    recipient: str = Field(..., description="EVM address of recipient")
    keyFingerprint: str = Field(..., min_length=1, max_length=128, description="P-256 public key fingerprint")
    iv: str = Field(..., description="12-byte IV for wrappedKey (base64url)")
    wrappedKey: str = Field(..., description="Encrypted 256-bit content key (base64url)")

    @field_validator("recipient")
    @classmethod
    def validate_recipient_address(cls, v: str) -> str:
        if not isinstance(v, str) or not Web3.is_address(v.strip()):
            raise ValueError(f"Invalid recipient address: {v}")
        return Web3.to_checksum_address(v.strip())

    @field_validator("keyFingerprint")
    @classmethod
    def validate_key_fingerprint(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Recipient keyFingerprint cannot be empty")
        return v.strip()

    @field_validator("iv")
    @classmethod
    def validate_iv(cls, v: str) -> str:
        validate_base64url_string(v, "Recipient key wrapper iv", exact_bytes=AES_GCM_IV_BYTE_LENGTH)
        return v.strip()

    @field_validator("wrappedKey")
    @classmethod
    def validate_wrapped_key(cls, v: str) -> str:
        validate_base64url_string(
            v,
            "Recipient key wrapper wrappedKey",
            min_bytes=MIN_WRAPPED_KEY_BYTES,
            max_bytes=MAX_WRAPPED_KEY_BYTES,
        )
        return v.strip()


class EncryptedMessageSubmit(BaseModel):
    version: int = Field(1, description="Protocol version, must be 1")
    message_id: str = Field(..., min_length=8, max_length=64, description="Unique client message ID")
    channel: str = Field("global", description="Room / channel identifier (default: global)")
    room: Optional[str] = Field(None, description="Optional alias for channel")
    sender: str = Field(..., description="Connected sender EVM address")
    algorithm: str = Field(PROTOCOL_ALGORITHM, description="Must be ECDH-P256-HKDF-AES-GCM-256")
    key_version: int = Field(1, description="Key format version")
    content_iv: str = Field(..., description="12-byte IV for content (base64url)")
    content_ciphertext: str = Field(..., description="Ciphertext with GCM auth tag (base64url)")
    recipients: List[RecipientKeyWrapperModel] = Field(..., min_length=1, max_length=MAX_ROOM_RECIPIENTS)
    sender_public_key: Dict[str, Any] = Field(..., description="Sender public key metadata")
    signature: str = Field(..., min_length=130, max_length=134, description="EIP-191 signature over message metadata")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")

    # Extra forbid ensures NO plaintext fields can be smuggled
    model_config = {
        "extra": "forbid"
    }

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_format(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Timestamp must be a non-empty ISO 8601 string")
        val = v.strip()
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                raise ValueError("Timestamp must include explicit timezone offset (e.g., Z or +00:00)")
        except Exception:
            raise ValueError("Invalid ISO 8601 timestamp format")
        return val

    @field_validator("version")
    @classmethod
    def validate_protocol_version(cls, v: int) -> int:
        if v not in SUPPORTED_PROTOCOL_VERSIONS:
            raise ValueError(
                f"Client update required: protocol version {v} is not supported. "
                f"Supported versions: {sorted(SUPPORTED_PROTOCOL_VERSIONS)}"
            )
        return v

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        if v != PROTOCOL_ALGORITHM:
            raise ValueError(
                f"Unsupported algorithm '{v}': must be exact supported algorithm '{PROTOCOL_ALGORITHM}'"
            )
        return v

    @field_validator("key_version")
    @classmethod
    def validate_key_version(cls, v: int) -> int:
        if v not in SUPPORTED_KEY_VERSIONS:
            raise ValueError(
                f"Unsupported key version '{v}': must be {sorted(SUPPORTED_KEY_VERSIONS)}"
            )
        return v

    @field_validator("sender")
    @classmethod
    def validate_sender_address(cls, v: str) -> str:
        if not isinstance(v, str) or not Web3.is_address(v.strip()):
            raise ValueError("Invalid sender EVM address")
        return Web3.to_checksum_address(v.strip())

    @field_validator("content_iv")
    @classmethod
    def validate_content_iv(cls, v: str) -> str:
        validate_base64url_string(v, "content_iv", exact_bytes=AES_GCM_IV_BYTE_LENGTH)
        return v.strip()

    @field_validator("content_ciphertext")
    @classmethod
    def validate_content_ciphertext(cls, v: str) -> str:
        validate_base64url_string(
            v,
            "content_ciphertext",
            min_bytes=MIN_CIPHERTEXT_BYTES,
            max_bytes=MAX_CIPHERTEXT_BYTES,
        )
        return v.strip()

    @field_validator("recipients")
    @classmethod
    def validate_unique_recipients(cls, recipients: List[RecipientKeyWrapperModel]) -> List[RecipientKeyWrapperModel]:
        seen = set()
        for r in recipients:
            norm_addr = r.recipient.lower()
            if norm_addr in seen:
                raise ValueError(f"Duplicate recipient address in envelope: {r.recipient}")
            seen.add(norm_addr)
        return recipients

    @model_validator(mode="after")
    def sync_channel_and_room(self) -> "EncryptedMessageSubmit":
        effective_room = self.room or self.channel or "global"
        self.channel = effective_room
        self.room = effective_room
        return self


# ============================================================================
# API Endpoints
# ============================================================================

@router.get("/rooms/{room_id}/recipients")
def get_room_recipients(room_id: str = "global"):
    """
    Returns the authoritative list of registered public keys authorized to receive
    encrypted messages in the room. Senders use this list to wrap the content key.
    """
    try:
        keys = chat_db.get_active_room_public_keys(room_id=room_id, limit=MAX_ROOM_RECIPIENTS)
        return {
            "room_id": room_id,
            "count": len(keys),
            "recipients": keys,
        }
    except Exception as exc:
        logger.error("Failed to fetch room recipients for %s: %s", room_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to fetch room recipients",
        )


PUBLIC_ROOM_SECURITY_MODEL = {
    "room_id": "global",
    "confidential": False,
    "transport_security": "HTTPS + WSS (TLS in transit)",
    "storage_encryption_at_rest": True,
    "e2ee_scope_warning": (
        "The Global Public Room is intentionally public and NOT confidential. "
        "Even when envelopes use multi-recipient public-room key wrapping or TLS/database "
        "encryption at rest, any visitor or moderator who registers in the public directory "
        "may receive public room keys, and server-side moderation applies. Use Private Chats "
        "(Olm v2 Double Ratchet) or Encrypted Groups (MLS RFC 9420) for confidential E2EE."
    ),
}


@router.get("/public-security-model")
def get_public_room_security_model():
    """Explicitly discloses the security and confidentiality model of the public room."""
    return PUBLIC_ROOM_SECURITY_MODEL


@router.get("/messages")
def get_chat_messages(
    response: Response,
    channel: str = Query("global"),
    recipient: Optional[str] = Query(None, description="Optional EVM recipient filter"),
    limit: int = Query(50, le=100)
):
    """
    Public message stream: Anyone may view the Global Chat feed without connecting MetaMask.
    Strictly restricted to the public 'global' room; private and group chats must use
    authenticated /api/e2ee/* endpoints.
    Supports optional recipient address filtering for multi-recipient envelopes.
    """
    if channel != "global":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Direct and group conversations are strictly restricted to authenticated "
                "E2EE endpoints (/api/e2ee/dm/messages and /api/e2ee/groups/{group_id}/messages)."
            ),
        )

    norm_recipient: Optional[str] = None
    if recipient:
        recip_val = recipient.strip()
        if not Web3.is_address(recip_val):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid recipient address parameter: must be a valid EVM address",
            )
        norm_recipient = Web3.to_checksum_address(recip_val)

    response.headers["X-Chat-Room-Model"] = "public-non-confidential"
    try:
        messages = chat_db.get_chat_messages(room_id="global", recipient=norm_recipient, limit=limit)
        return messages
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to fetch public room chat messages: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch chat messages",
        )


def _is_envelope_identical(existing: Optional[Dict[str, Any]], payload: EncryptedMessageSubmit) -> bool:
    """Verifies whether an existing stored message envelope is byte-for-byte identical to the submitted payload."""
    if not existing:
        return False
    if existing.get("id") != payload.message_id:
        return False
    if str(existing.get("sender", "")).lower() != payload.sender.lower():
        return False
    if existing.get("room_id") != payload.channel:
        return False
    if existing.get("content_ciphertext") != payload.content_ciphertext:
        return False
    if existing.get("content_iv") != payload.content_iv:
        return False
    if existing.get("algorithm") != payload.algorithm:
        return False
    if existing.get("signature") != payload.signature:
        return False

    existing_ts = existing.get("client_timestamp") or existing.get("timestamp")
    if existing_ts and existing_ts != payload.timestamp:
        return False

    existing_recips = existing.get("recipients") or []
    payload_recips = [r.model_dump() for r in payload.recipients]
    if len(existing_recips) != len(payload_recips):
        return False

    existing_by_addr = {
        str(r.get("recipient", "")).lower(): r
        for r in existing_recips
    }
    for pr in payload_recips:
        er = existing_by_addr.get(pr["recipient"].lower())
        if not er:
            return False
        if er.get("wrappedKey") != pr.get("wrappedKey") or er.get("iv") != pr.get("iv"):
            return False
    return True


@router.get("/messages/{message_id}")
def get_single_chat_message(message_id: str):
    """
    Retrieves a single encrypted message envelope by its unique message ID.
    Returns ciphertext only; server never decrypts content.
    """
    try:
        msg = chat_db.get_chat_message_by_id(message_id)
    except Exception as exc:
        logger.error("Database error retrieving message %s: %s", message_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve chat message",
        )
    if not msg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Message with ID '{message_id}' not found",
        )
    return msg


@router.post("/messages")
def post_chat_message(
    request: Request,
    payload: EncryptedMessageSubmit,
    idempotent: bool = Query(False, description="Safely return original message if verified identical"),
):
    """
    Posts an end-to-end encrypted message to Global Chat.
    Enforces:
    1. Zero plaintext allowed (strict Pydantic schema validation).
    2. EIP-191 cryptographic wallet signature verification of the sender over canonical envelope hash.
    3. Replay protection (freshness window).
    4. Authoritative recipient set binding and duplicate recipient rejection.
    5. Database row creation detection and duplicate message ID handling (409 Conflict).
    6. Safe error responses: database exceptions never leak internal details to clients.
    """
    # 0. Request size limit to prevent oversized encrypted payload abuse
    cl_header = request.headers.get("content-length")
    if cl_header:
        try:
            cl_int = int(cl_header)
            if cl_int > MAX_ENCRYPTED_REQUEST_BYTES:
                logger.warning(
                    "Rejected oversized encrypted message: %d bytes (limit %d bytes)",
                    cl_int,
                    MAX_ENCRYPTED_REQUEST_BYTES,
                )
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Encrypted message payload exceeds maximum size limit ({MAX_ENCRYPTED_REQUEST_BYTES // 1024} KB)",
                )
        except ValueError:
            pass

    # 1. Verify timestamp freshness & clock-skew validation for replay protection
    try:
        raw_ts = str(payload.timestamp).strip()
        msg_time = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        if msg_time.tzinfo is None:
            raise ValueError("Timestamp must include explicit timezone offset (e.g. Z or +00:00)")
        now = datetime.now(timezone.utc)
        diff_seconds = abs((now - msg_time).total_seconds())
        if diff_seconds > SIGNATURE_WINDOW_SECONDS:
            logger.warning(
                "Rejected message %s from %s: timestamp outside clock-skew window (diff=%.1fs, window=%ds). Client ts=%s, server now=%s",
                payload.message_id,
                payload.sender,
                diff_seconds,
                SIGNATURE_WINDOW_SECONDS,
                raw_ts,
                now.isoformat(),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Message timestamp is outside the valid window ({diff_seconds:.0f}s difference). Check device clock.",
            )
    except HTTPException:
        raise
    except ValueError as ve:
        logger.warning(
            "Timestamp validation error for message %s from %s: %s",
            payload.message_id,
            payload.sender,
            ve,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid ISO 8601 timestamp format",
        )
    except Exception as exc:
        logger.error(
            "Unexpected error processing timestamp for message %s from %s: %s",
            payload.message_id,
            payload.sender,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid ISO 8601 timestamp format",
        )

    # 2. Build canonical representation and verify complete envelope integrity
    try:
        recipients_dicts = [
            {
                "iv": r.iv,
                "keyFingerprint": r.keyFingerprint,
                "recipient": r.recipient,
                "wrappedKey": r.wrappedKey,
            }
            for r in payload.recipients
        ]
        canonical_dict = build_canonical_envelope_dict(
            message_id=payload.message_id,
            sender=payload.sender,
            channel=payload.channel,
            timestamp=payload.timestamp,
            version=payload.version,
            algorithm=payload.algorithm,
            key_version=payload.key_version,
            content_iv=payload.content_iv,
            content_ciphertext=payload.content_ciphertext,
            recipients=recipients_dicts,
        )
        envelope_hash = compute_canonical_envelope_hash(canonical_dict)
    except ValueError as ve:
        logger.warning(
            "Envelope canonical validation failed for message %s from %s: %s",
            payload.message_id,
            payload.sender,
            ve,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as exc:
        logger.error(
            "Unexpected error constructing canonical envelope for message %s: %s",
            payload.message_id,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed envelope structure",
        )

    # 3. Verify EIP-191 Sender Signature over canonical envelope hash
    expected_message_text = build_envelope_signing_text(
        sender=payload.sender,
        message_id=payload.message_id,
        room=payload.channel,
        timestamp=payload.timestamp,
        envelope_hash=envelope_hash,
    )

    try:
        msghash = encode_defunct(text=expected_message_text)
        recovered_address = Account.recover_message(msghash, signature=payload.signature)
    except Exception as sig_err:
        logger.warning(
            "Failed to decode wallet signature for message %s: %s",
            payload.message_id,
            sig_err,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to decode or verify wallet signature over message envelope",
        )

    if recovered_address.lower() != payload.sender.lower():
        # Check if the client signed using legacy unhashed format
        legacy_message_text = (
            f"zyphra.in Chat Message\n"
            f"Sender: {payload.sender}\n"
            f"Message ID: {payload.message_id}\n"
            f"Room: {payload.channel}\n"
            f"Timestamp: {payload.timestamp}"
        )
        try:
            legacy_msghash = encode_defunct(text=legacy_message_text)
            legacy_recovered = Account.recover_message(legacy_msghash, signature=payload.signature)
        except Exception:
            legacy_recovered = None

        if legacy_recovered and legacy_recovered.lower() == payload.sender.lower():
            logger.warning(
                "Rejected legacy unhashed envelope for message %s from sender %s (upgrade required)",
                payload.message_id,
                payload.sender,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Legacy envelope signature rejected. The envelope signature must cryptographically "
                    "bind the canonical envelope hash. Please upgrade your client."
                ),
            )

        logger.warning(
            "Envelope signature verification failed for message %s: expected %s, recovered %s (envelope_hash=%s)",
            payload.message_id,
            payload.sender,
            recovered_address,
            envelope_hash,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sender authentication failed: invalid signature or envelope hash mismatch",
        )

    if payload.channel != "global":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Private and group messages must use authenticated /api/e2ee/* endpoints",
        )

    import e2ee_db
    try:
        sender_user = e2ee_db.get_user_by_wallet(payload.sender)
    except Exception as exc:
        logger.error(
            "Database error checking sender account status for %s: %s",
            payload.sender,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to verify sender account status",
        )
    if sender_user:
        if sender_user.get("account_status") == "suspended":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is suspended")
        if sender_user.get("account_status") == "muted":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is muted")

    # 3. Ensure sender is included in recipient wrappers so sender can decrypt their own message
    sender_in_recipients = any(
        r.recipient.lower() == payload.sender.lower()
        for r in payload.recipients
    )
    if not sender_in_recipients:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sender must be included in the recipients list to enable self-decryption",
        )

    # 4. Strict server-side verification of recipient encryption keys and fingerprints
    if payload.channel == "global":
        recipient_addresses = [r.recipient for r in payload.recipients]
        try:
            registered_keys = chat_db.get_chat_keys_batch(recipient_addresses)
        except Exception as exc:
            logger.error(
                "Database error fetching recipient keys for message %s: %s",
                payload.message_id,
                exc,
                exc_info=True,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to verify recipient encryption keys",
            )
        reg_by_lower = {k.lower(): v for k, v in registered_keys.items()}

        for r in payload.recipients:
            key_doc = reg_by_lower.get(r.recipient.lower())
            if not key_doc:
                logger.warning(
                    "Rejected message %s: recipient %s has no registered encryption key",
                    payload.message_id,
                    r.recipient,
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Recipient {r.recipient} has no registered encryption key",
                )

            key_status = str(key_doc.get("status", "")).strip().lower()
            if key_status != "active":
                logger.warning(
                    "Rejected message %s: recipient %s encryption key is not active (status: %s)",
                    payload.message_id,
                    r.recipient,
                    key_status,
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Recipient {r.recipient} encryption key is inactive or revoked",
                )

            registered_fp = key_doc.get("public_key_fingerprint")
            if not registered_fp or registered_fp != r.keyFingerprint:
                logger.warning(
                    "Rejected message %s: recipient %s fingerprint mismatch: registered=%s, submitted=%s",
                    payload.message_id,
                    r.recipient,
                    registered_fp,
                    r.keyFingerprint,
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Recipient {r.recipient} key fingerprint mismatch: submitted key does not match registered active key",
                )

    # 5. Authoritative server creation timestamp
    server_now = datetime.now(timezone.utc).isoformat()

    # Persist encrypted envelope to Neon PostgreSQL / SQLite via chat_db
    doc = {
        "id": payload.message_id,
        "room_id": payload.channel,
        "sender": payload.sender,
        "algorithm": payload.algorithm,
        "content_iv": payload.content_iv,
        "content_ciphertext": payload.content_ciphertext,
        "recipients": [r.model_dump() for r in payload.recipients],
        "sender_public_key": payload.sender_public_key,
        "signature": payload.signature,
        "client_timestamp": payload.timestamp,
        "server_timestamp": server_now,
        "created_at": server_now,
        "timestamp": payload.timestamp,
    }

    try:
        insert_res = chat_db.insert_chat_message(doc)
    except ValueError as ve:
        logger.warning(
            "Validation error inserting encrypted message %s from %s: %s",
            payload.message_id,
            payload.sender,
            ve,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as exc:
        logger.error(
            "Database failure while saving message %s from %s: %s",
            payload.message_id,
            payload.sender,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to save encrypted message",
        )

    # 6. Handle duplicate message ID or uncreated row
    if not insert_res.created:
        if insert_res.duplicate:
            existing = insert_res.existing
            is_identical = _is_envelope_identical(existing, payload)
            if is_identical and idempotent:
                logger.info(
                    "Idempotent resubmission of message %s; safely returning original record",
                    payload.message_id,
                )
                return {
                    "success": True,
                    "message_id": existing["id"],
                    "channel": existing["room_id"],
                    "status": "already_exists",
                    "client_timestamp": existing.get("client_timestamp") or existing.get("timestamp"),
                    "server_timestamp": existing.get("server_timestamp") or existing.get("created_at"),
                    "created_at": existing.get("created_at") or existing.get("server_timestamp"),
                    "timestamp": existing["timestamp"],
                    "duplicate": True,
                    "original_message": existing,
                }

            logger.warning(
                "Duplicate message ID conflict: message %s already exists in channel %s (identical=%s)",
                payload.message_id,
                payload.channel,
                is_identical,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Duplicate message ID conflict: message '{payload.message_id}' already exists",
            )

        logger.error(
            "Database insert failed to create row for message %s from %s",
            payload.message_id,
            payload.sender,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to save encrypted message",
        )

    return {
        "success": True,
        "message_id": payload.message_id,
        "channel": payload.channel,
        "status": "encrypted_delivered",
        "client_timestamp": payload.timestamp,
        "server_timestamp": server_now,
        "created_at": server_now,
        "timestamp": payload.timestamp,
    }
