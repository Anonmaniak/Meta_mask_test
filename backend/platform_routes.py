"""
Unified Chat Platform API Router (`/api/platform/*` & `/ws/public-chat`).

Covers:
1. Open Public Chat (readable feed, configurable guest policy, edit/delete, URL safety, WS broadcast)
2. Username Search Directory, Extended Profiles, Identity/Wallet/Level History, User Blocks,
   Optional DM Read Receipts & Abuse Reporting
3. Configurable Wallet-Based Levels (starting at Level 7) & Server-Side Ethereum RPC Balance Verification
4. Group Access Policies (`min_level`, `min_eth_balance_wei`, `visibility`), Invite Links,
   Public Group Discovery, Policy-Gated Join Requests & Leave Group
5. Role-Based Admin Console (`superadmin`, `moderator`) & Immutable Audit Logs
"""

import os
import re
import asyncio
import hashlib
import secrets
import logging
from decimal import Decimal, InvalidOperation
from typing import Optional, List, Dict, Any

logger = logging.getLogger("platform_routes")

from pydantic import BaseModel, Field
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from web3 import Web3

import admin_auth
import e2ee_db
import platform_db
import support_db
import eth_rpc
from e2ee_routes import (
    SESSION_COOKIE_NAME,
    StrictModel,
    _check_rate_limit,
    _schedule_ws_notify,
    schedule_public_ws_broadcast,
    realtime_hub,
    get_optional_session,
    require_authenticated_session,
    require_paid_member,
)

router = APIRouter(prefix="/api/platform", tags=["platform"])
public_ws_router = APIRouter(tags=["public-chat-ws"])

DANGEROUS_CONTENT_RE = re.compile(
    r"(javascript\s*:|vbscript\s*:|data\s*:\s*text/html|<\s*script\b)",
    re.IGNORECASE,
)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_public_text(raw: str, max_len: int) -> str:
    cleaned = CONTROL_CHARS_RE.sub("", raw or "").strip()
    if not cleaned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message content cannot be empty",
        )
    if len(cleaned) > max_len:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Message exceeds maximum length of {max_len} characters",
        )
    if DANGEROUS_CONTENT_RE.search(cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message rejected: potentially malicious script or URI scheme detected",
        )
    return cleaned


def _validate_safe_optional_url(url: Optional[str], field_name: str = "url") -> Optional[str]:
    if url is None:
        return None
    cleaned = url.strip()
    if not cleaned:
        return None
    low = cleaned.lower()
    if not (low.startswith("https://") or low.startswith("http://") or low.startswith("data:image/")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {field_name}: only http(s) or data:image URLs are permitted",
        )
    return cleaned[:500]


# ============================================================================
# RBAC ADMIN DEPENDENCIES (`moderator` | `superadmin` | break-glass `X-Admin-Token`)
# ============================================================================

def _resolve_admin_actor(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
    min_role: str = "moderator",
) -> Dict[str, Any]:
    # 1) Admin Console login session (`/Admin456`) issued by POST /admin/login.
    if x_admin_token and admin_auth.verify_session(x_admin_token):
        return {
            "actor_user_id": "admin_console",
            "role": "superadmin",
            "user": None,
        }

    # 2) Ops break-glass token. Only honoured when it is a high-entropy secret (>= 24 chars).
    configured_token = (os.getenv("ADMIN_TOKEN") or "").strip()
    if (
        len(configured_token) >= 24
        and x_admin_token
        and secrets.compare_digest(
            hashlib.sha256(x_admin_token.strip().encode("utf-8")).digest(),
            hashlib.sha256(configured_token.encode("utf-8")).digest(),
        )
    ):
        return {
            "actor_user_id": "admin_token_breakglass",
            "role": "superadmin",
            "user": None,
        }

    ctx = get_optional_session(request, authorization)
    if not ctx:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required: sign in with an authorized admin wallet",
        )

    user = ctx["user"]
    role = platform_db.get_admin_role(user["user_id"])
    if not role and user.get("primary_wallet"):
        role = platform_db.bootstrap_admin_if_configured(user["user_id"], user["primary_wallet"])

    if role not in ("moderator", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: moderator or superadmin role required",
        )
    if min_role == "superadmin" and role != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: superadmin role required for this action",
        )

    return {
        "actor_user_id": user["user_id"],
        "role": role,
        "user": user,
    }


def require_moderator(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
) -> Dict[str, Any]:
    return _resolve_admin_actor(request, authorization, x_admin_token, min_role="moderator")


def require_superadmin(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
) -> Dict[str, Any]:
    return _resolve_admin_actor(request, authorization, x_admin_token, min_role="superadmin")


# ============================================================================
# ADMIN CONSOLE LOGIN (`/Admin456`) — credentials from backend env only
# ============================================================================

class AdminLoginRequest(BaseModel):
    model_config = {"extra": "forbid"}
    login_id: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        # Right-most entry is the one appended by our trusted proxy (Render); never trust the left-most.
        return fwd.split(",")[-1].strip()[:64]
    return request.client.host if request.client else "unknown"


@router.post("/admin/login")
def admin_login(body: AdminLoginRequest, request: Request) -> Dict[str, Any]:
    try:
        token = admin_auth.attempt_login(body.login_id, body.password, _client_ip(request))
    except admin_auth.LoginError as exc:
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        raise HTTPException(status_code=exc.status, detail=exc.detail, headers=headers)
    return {
        "token": token,
        "expires_in_seconds": admin_auth.SESSION_ABSOLUTE_TTL_SEC,
        "idle_timeout_seconds": admin_auth.SESSION_IDLE_TTL_SEC,
    }


@router.get("/admin/session")
def admin_session_check(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
) -> Dict[str, Any]:
    if not admin_auth.verify_session(x_admin_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin session invalid or expired")
    return {"ok": True}


@router.post("/admin/logout")
def admin_logout(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
) -> Dict[str, Any]:
    admin_auth.revoke_session(x_admin_token)
    return {"ok": True}


# ============================================================================
# PYDANTIC REQUEST SCHEMAS
# ============================================================================

class PublicChatPostRequest(StrictModel):
    content: str = Field(..., min_length=1, max_length=4000)
    guest_token: Optional[str] = Field(None, max_length=64)


class PublicChatEditRequest(StrictModel):
    content: str = Field(..., min_length=1, max_length=4000)


class ProfileUpdateRequest(StrictModel):
    display_name: Optional[str] = Field(None, max_length=48)
    bio: Optional[str] = Field(None, max_length=280)
    avatar_url: Optional[str] = Field(None, max_length=500)
    show_online_presence: Optional[bool] = None
    send_read_receipts: Optional[bool] = None


class UserBlockRequest(StrictModel):
    target_user_id: str = Field(..., min_length=6, max_length=64)
    reason: str = Field("", max_length=200)


class DmReadReceiptRequest(StrictModel):
    peer_user_id: str = Field(..., min_length=6, max_length=64)
    last_read_seq: int = Field(..., ge=0)


class AbuseReportCreateRequest(StrictModel):
    scope_type: str = Field(..., pattern=r"^(public_chat|dm|group|user)$")
    scope_id: str = Field(..., min_length=2, max_length=64)
    reason: str = Field(..., min_length=3, max_length=120)
    details: str = Field("", max_length=1000)
    target_user_id: Optional[str] = Field(None, max_length=64)
    message_id: Optional[str] = Field(None, max_length=64)


class VerifyBalanceRequest(StrictModel):
    chain_id: Optional[int] = Field(None, ge=1)


class PaymentVerifyRequest(StrictModel):
    transaction_reference: str = Field(..., min_length=10, max_length=128)
    chain_id: Optional[int] = Field(None, ge=1)
    purpose: Optional[str] = Field("platform_entry", max_length=32)
    group_id: Optional[str] = Field(None, max_length=128)


class GroupPolicyUpdateRequest(StrictModel):
    description: str = Field("", max_length=500)
    avatar_url: Optional[str] = Field(None, max_length=500)
    visibility: str = Field("invite_only", pattern=r"^(public|invite_only)$")
    min_level: int = Field(7, ge=7, le=100)
    min_eth_balance_wei: Optional[str] = Field(None, pattern=r"^[0-9]{1,36}$")
    min_eth_balance_eth: Optional[str] = Field(None, max_length=32)
    require_invitation: bool = True
    is_paid: Optional[bool] = False
    entry_fee_eth: Optional[str] = Field("0", max_length=32)  # legacy fixed-ETH fee
    entry_fee_usd: Optional[float] = Field(None, ge=0, le=100000)  # preferred: priced in USD


class AdminPricingUpdateRequest(StrictModel):
    platform_entry_fee_usd: Optional[float] = Field(None, ge=0, le=100000)
    use_live_eth_price: Optional[bool] = None
    platform_entry_fee_eth: Optional[str] = Field(None, max_length=32)  # legacy, ignored for pricing
    eth_usd_price: Optional[float] = Field(None, gt=0)
    authorized_payment_destination: Optional[str] = Field(None, max_length=64)


class GroupInviteCreateRequest(StrictModel):
    expires_hours: int = Field(72, ge=1, le=720)
    max_uses: int = Field(25, ge=1, le=1000)


class GroupMemberRoleUpdateRequest(StrictModel):
    role: str = Field(..., pattern=r"^(admin|member)$")


class AdminUserModerateRequest(StrictModel):
    action_type: str = Field(..., pattern=r"^(suspend|mute|restore)$")
    reason: str = Field(..., min_length=2, max_length=300)
    duration_hours: Optional[int] = Field(None, ge=1, le=8760)


class AdminRoleGrantRequest(StrictModel):
    role: Optional[str] = Field(None, pattern=r"^(superadmin|moderator)$")


class AdminReportResolveRequest(StrictModel):
    status: str = Field(..., pattern=r"^(resolved|dismissed)$")
    resolution_note: str = Field("", max_length=500)


class AdminSettingsUpdateRequest(BaseModel):
    public_chat_max_length: Optional[int] = Field(None, ge=50, le=4000)
    public_chat_edit_window_seconds: Optional[int] = Field(None, ge=0, le=86400)
    public_chat_retention_days: Optional[int] = Field(None, ge=1, le=3650)
    username_cooldown_hours: Optional[int] = Field(None, ge=0, le=720)
    username_reservation_days: Optional[int] = Field(None, ge=0, le=365)
    balance_reeval_minutes: Optional[int] = Field(None, ge=1, le=1440)
    default_balance_chain_id: Optional[int] = Field(None, ge=1)
    authorized_payment_destination: Optional[str] = Field(None, max_length=42)
    # Membership pricing (previously silently dropped by this model, so the admin
    # dashboard could never actually change the fee)
    platform_entry_fee_usd: Optional[float] = Field(None, ge=0, le=100000)
    use_live_eth_price: Optional[bool] = None
    eth_usd_price: Optional[float] = Field(None, gt=0)


class PaymentDestinationUpdateRequest(StrictModel):
    destination_address: str = Field(..., min_length=42, max_length=42)


def _eth_or_wei_to_wei_str(
    wei_str: Optional[str], eth_str: Optional[str], field_label: str = "ETH requirement"
) -> str:
    if wei_str is not None and str(wei_str).strip() != "":
        s = str(wei_str).strip()
        try:
            val = int(s)
            if val < 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{field_label} cannot be negative",
                )
            return str(val)
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid {field_label} value: {wei_str}",
            ) from exc
    if eth_str is not None and str(eth_str).strip() != "":
        s = str(eth_str).strip()
        try:
            dec = Decimal(s)
            if dec < 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{field_label} cannot be negative",
                )
            return str(int(Web3.to_wei(dec, "ether")))
        except (InvalidOperation, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid {field_label} value: {eth_str}",
            ) from exc
    return "0"


# ============================================================================
# 1. OPEN PUBLIC CHAT ENDPOINTS & REAL-TIME WEBSOCKET
# ============================================================================

def _normalize_wallet_addr(raw: Any) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if cleaned and Web3.is_address(cleaned):
        return cleaned.lower()
    return None


def _extract_ws_session_user_id(websocket: WebSocket) -> Optional[str]:
    tok = websocket.cookies.get(SESSION_COOKIE_NAME)
    if not tok:
        auth_hdr = websocket.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            tok = auth_hdr[7:].strip()
    if not tok:
        return None
    sess = e2ee_db.get_session_by_token(tok)
    return sess["user_id"] if sess else None


def _require_paid_member_ctx(request: Request, authorization: Optional[str]) -> Dict[str, Any]:
    """Session + paid-membership check for handlers that resolve the session themselves."""
    ctx = get_optional_session(request, authorization)
    if not ctx:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Connect your wallet to use Open Public Chat.",
        )
    if not platform_db.has_user_paid_platform_entry(ctx["user"]["user_id"]):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Membership payment required to use Open Public Chat.",
        )
    return ctx


@router.get("/public-chat/messages")
def get_open_public_chat_feed(
    request: Request,
    before_seq: Optional[int] = Query(None, ge=1),
    limit: int = Query(50, ge=1, le=100),
    authorization: Optional[str] = Header(None),
    x_wallet_address: Optional[str] = Header(None, alias="X-Wallet-Address"),
):
    settings = platform_db.get_platform_settings()
    # Premium-only: Open Public Chat is readable by signed-in, paid members only.
    opt_ctx = _require_paid_member_ctx(request, authorization)

    viewer_uid = opt_ctx["user"]["user_id"]
    is_connected_member = True
    feed = platform_db.list_public_chat_messages(
        before_seq=before_seq,
        limit=limit,
        viewer_user_id=viewer_uid,
    )
    return {
        "room": "open_public",
        "security_notice": (
            "Open Public Chat is readable by all members and moderated. "
            "Use Private Messages or Encrypted Groups for end-to-end encrypted communication."
        ),
        "messages": feed["messages"],
        "next_before_seq": feed["next_before_seq"],
        "online": realtime_hub.get_online_stats(include_active_live=is_connected_member),
        "policy": {
            "guest_read_enabled": False,
            "guest_posting_enabled": False,
            "max_length": int(settings.get("public_chat_max_length") or 1000),
            "edit_window_seconds": int(settings.get("public_chat_edit_window_seconds") or 900),
        },
    }


@router.post("/public-chat/messages")
def post_open_public_chat_message(
    payload: PublicChatPostRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    settings = platform_db.get_platform_settings()
    max_len = int(settings.get("public_chat_max_length") or 1000)
    cleaned = _sanitize_public_text(payload.content, max_len=max_len)

    opt_ctx = _require_paid_member_ctx(request, authorization)
    user = opt_ctx["user"]
    if user.get("account_status") == "muted":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account is currently muted by moderation",
        )
    _check_rate_limit("public_chat_post", user["user_id"], max_hits=20, window_sec=60.0)
    uname = user.get("username")
    disp = f"@{uname}" if uname else (user.get("display_name") or f"User-{user['user_id'][4:10]}")
    try:
        msg = platform_db.insert_public_chat_message(
            content=cleaned,
            author_user_id=user["user_id"],
            guest_id=None,
            display_name=disp,
            author_level=int(user.get("current_level") or 7),
            is_guest=False,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(ve))
    except Exception as exc:
        logger.error("Database error saving member public chat message: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to save chat message",
        )

    if not msg:
        logger.error("Public chat message storage returned empty result")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to save chat message",
        )

    schedule_public_ws_broadcast({"type": "public_message_created", "message": msg})
    return {"success": True, "message": msg}


@router.patch("/public-chat/messages/{message_id}")
def edit_open_public_chat_message_endpoint(
    message_id: str,
    payload: PublicChatEditRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    if ctx["user"].get("account_status") == "muted":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Muted users cannot edit messages")
    settings = platform_db.get_platform_settings()
    max_len = int(settings.get("public_chat_max_length") or 1000)
    cleaned = _sanitize_public_text(payload.content, max_len=max_len)

    try:
        updated = platform_db.edit_public_chat_message(
            message_id=message_id,
            actor_user_id=ctx["user"]["user_id"],
            new_content=cleaned,
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))

    schedule_public_ws_broadcast({"type": "public_message_edited", "update": updated})
    return {"success": True, **updated}


@router.delete("/public-chat/messages/{message_id}")
def delete_open_public_chat_message_endpoint(
    message_id: str,
    request: Request,
    reason: str = Query("", max_length=200),
    authorization: Optional[str] = Header(None),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    actor = _resolve_admin_actor(request, authorization, x_admin_token, min_role="moderator")
    actor_id = actor["actor_user_id"]
    is_mod = actor["role"] in ("moderator", "superadmin")

    try:
        deleted = platform_db.delete_public_chat_message(
            message_id=message_id,
            actor_user_id=actor_id,
            is_moderator=is_mod,
            reason=reason,
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))

    schedule_public_ws_broadcast({"type": "public_message_deleted", "message_id": message_id})
    return {"success": True, **deleted}


@public_ws_router.websocket("/ws/public-chat")
async def open_public_chat_websocket(websocket: WebSocket):
    """Real-time WebSocket stream for Open Public Chat messages, edits, deletes & presence."""
    await websocket.accept()
    # Premium-only stream: the first frame must authenticate a PAID member
    # ({"type": "auth", "token": "<session token>"}), unless a session cookie/header is present.
    sess_uid = _extract_ws_session_user_id(websocket)
    if not sess_uid:
        try:
            first = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
        except Exception:
            await websocket.close(code=4401)
            return
        tok = str(first.get("token") or "") if isinstance(first, dict) and first.get("type") == "auth" else ""
        sess = e2ee_db.get_session_by_token(tok) if tok else None
        sess_uid = sess["user_id"] if sess else None
    if not sess_uid:
        await websocket.close(code=4401)
        return
    if not platform_db.has_user_paid_platform_entry(sess_uid):
        await websocket.close(code=4402)
        return
    initial_member: Optional[str] = f"user:{sess_uid}"

    realtime_hub.register_public(websocket, member_ident=initial_member)
    try:
        is_member = realtime_hub.is_public_member_socket(websocket)
        await websocket.send_json({
            "type": "public_connected",
            "online": realtime_hub.get_online_stats(include_active_live=is_member),
        })
        await realtime_hub.broadcast_public_presence(exclude_ws=websocket)
        while True:
            msg = await websocket.receive_json()
            if not isinstance(msg, dict):
                continue
            mtype = msg.get("type")
            if mtype == "ping":
                cur_member = realtime_hub.is_public_member_socket(websocket)
                await websocket.send_json({
                    "type": "pong",
                    "online": realtime_hub.get_online_stats(include_active_live=cur_member),
                })
            elif mtype == "presence_status":
                w_norm = _normalize_wallet_addr(msg.get("wallet_address"))
                realtime_hub.set_public_member_wallet(websocket, w_norm)
                await realtime_hub.broadcast_public_presence()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        realtime_hub.unregister_public(websocket)
        await realtime_hub.broadcast_public_presence()


@public_ws_router.websocket("/ws/member-presence")
async def member_system_presence_websocket(websocket: WebSocket):
    """
    System-wide presence channel for MetaMask-connected members across all tabs/sections
    (Chats, Groups, Individual Chats, Payments, Settings) powering `Active Live`.
    """
    await websocket.accept()
    registered = False
    try:
        sess_uid = _extract_ws_session_user_id(websocket)
        raw_first = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
        if not isinstance(raw_first, dict) or raw_first.get("type") != "member_online":
            await websocket.close(code=4401)
            return
        w_norm = _normalize_wallet_addr(raw_first.get("wallet_address"))
        ident = w_norm or (f"user:{sess_uid}" if sess_uid else None)
        if not ident:
            await websocket.close(code=4401)
            return

        realtime_hub.register_member_presence(websocket, ident)
        registered = True
        await websocket.send_json({
            "type": "member_presence_ack",
            "online": realtime_hub.get_online_stats(include_active_live=True),
        })
        await realtime_hub.broadcast_public_presence()

        while True:
            msg = await websocket.receive_json()
            if not isinstance(msg, dict):
                continue
            mtype = msg.get("type")
            if mtype == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "online": realtime_hub.get_online_stats(include_active_live=True),
                })
            elif mtype == "member_online":
                next_w = _normalize_wallet_addr(msg.get("wallet_address"))
                if next_w:
                    realtime_hub.register_member_presence(websocket, next_w)
                    await realtime_hub.broadcast_public_presence()
    except (WebSocketDisconnect, asyncio.TimeoutError, Exception):
        pass
    finally:
        if registered:
            realtime_hub.unregister_member_presence(websocket)
            await realtime_hub.broadcast_public_presence()


# ============================================================================
# 2. USERNAME SEARCH, PROFILE, HISTORY, BLOCKING, RECEIPTS & REPORTS
# ============================================================================

@router.get("/users/search")
def search_users_by_username(
    request: Request,
    q: str = Query("", max_length=64),
    limit: int = Query(20, ge=1, le=50),
    authorization: Optional[str] = Header(None),
):
    opt_ctx = _require_paid_member_ctx(request, authorization)
    rate_id = opt_ctx["user"]["user_id"]
    _check_rate_limit("user_search", rate_id, max_hits=30, window_sec=60.0)

    exclude_uid = opt_ctx["user"]["user_id"]
    results = platform_db.search_users_directory(query=q, limit=limit, exclude_user_id=exclude_uid)
    for item in results:
        show_pres = item.pop("show_online_presence", True)
        item["online"] = bool(show_pres and realtime_hub.is_user_online(item["user_id"]))
    return {"users": results}


@router.patch("/profile")
def update_my_profile(
    payload: ProfileUpdateRequest,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    safe_avatar = _validate_safe_optional_url(payload.avatar_url, "avatar_url")
    updated = platform_db.update_user_profile(
        user_id=ctx["user"]["user_id"],
        display_name=payload.display_name,
        bio=payload.bio,
        avatar_url=safe_avatar if payload.avatar_url is not None else None,
        show_online_presence=payload.show_online_presence,
        send_read_receipts=payload.send_read_receipts,
    )
    return {"success": True, "user": updated}


@router.get("/profile/history")
def get_my_identity_and_balance_history(
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    uid = ctx["user"]["user_id"]
    wallet_hist = platform_db.list_wallet_history(uid)
    bal_hist = platform_db.list_user_balance_history(uid)
    return {
        "user_id": uid,
        "username_history": platform_db.list_username_history(uid),
        "wallets": wallet_hist["wallets"],
        "wallet_history": wallet_hist["history"],
        "balance_snapshots": bal_hist["snapshots"],
    }


@router.get("/blocks")
def list_my_blocked_users(ctx: Dict[str, Any] = Depends(require_paid_member)):
    return {"blocked_users": platform_db.list_blocked_users_detailed(ctx["user"]["user_id"])}


@router.post("/blocks")
def block_target_user(
    payload: UserBlockRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    try:
        platform_db.block_user(
            blocker_user_id=ctx["user"]["user_id"],
            blocked_user_id=payload.target_user_id,
            reason=payload.reason,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    return {"success": True, "blocked_user_id": payload.target_user_id}


@router.delete("/blocks/{target_user_id}")
def unblock_target_user(
    target_user_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    platform_db.unblock_user(ctx["user"]["user_id"], target_user_id)
    return {"success": True, "unblocked_user_id": target_user_id}


@router.post("/dm/read-receipt")
def submit_dm_read_receipt(
    payload: DmReadReceiptRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    uid = ctx["user"]["user_id"]
    if platform_db.is_blocked_between(uid, payload.peer_user_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot send read receipt to blocked user")
    rec = platform_db.upsert_dm_read_receipt(uid, payload.peer_user_id, payload.last_read_seq)
    if rec:
        _schedule_ws_notify(
            [payload.peer_user_id],
            {
                "type": "dm_read_receipt",
                "conversation_id": rec["conversation_id"],
                "reader_user_id": uid,
                "last_read_seq": rec["last_read_seq"],
            },
        )
    return {"success": True, "receipt": rec}


@router.get("/dm/read-receipts/{peer_user_id}")
def fetch_dm_read_receipts(
    peer_user_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    return {
        "receipts": platform_db.get_dm_read_receipts(ctx["user"]["user_id"], peer_user_id)
    }


@router.post("/reports")
def submit_abuse_report(
    payload: AbuseReportCreateRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    uid = ctx["user"]["user_id"]
    _check_rate_limit("abuse_report", uid, max_hits=10, window_sec=60.0)
    rep = platform_db.create_abuse_report(
        reporter_user_id=uid,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        reason=payload.reason.strip(),
        details=payload.details.strip(),
        target_user_id=payload.target_user_id,
        message_id=payload.message_id,
    )
    return {"success": True, "report": rep}


# ============================================================================
# 3. RPC WALLET BALANCE VERIFICATION
# ============================================================================


@router.post("/wallet/verify-balance")
def verify_my_wallet_balance_via_rpc(
    payload: Optional[VerifyBalanceRequest] = None,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    """
    Queries the backend Ethereum RPC node directly (`eth_getBalance` + `block_number`)
    for the authenticated user's active primary wallet, persists a verified snapshot,
    and updates `current_level` / `highest_level`. Never trusts browser-reported balances.
    """
    user = ctx["user"]
    uid = user["user_id"]
    _check_rate_limit("verify_balance", uid, max_hits=10, window_sec=60.0)

    primary_wallet = user.get("primary_wallet")
    if not primary_wallet:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active primary Ethereum wallet is linked to this account",
        )

    settings = platform_db.get_platform_settings()
    chain_id = int(
        (payload.chain_id if payload and payload.chain_id else None)
        or settings.get("default_balance_chain_id")
        or 1
    )

    try:
        rpc_res = eth_rpc.verify_onchain_eth_balance(primary_wallet, chain_id=chain_id)
    except eth_rpc.EthereumRpcUnavailableError as rpc_err:
        platform_db.record_audit_log(
            actor_user_id=uid,
            action="verification_failure",
            entity_type="wallet_balance",
            entity_id=uid,
            details={
                "event_type": "verification_failure",
                "target_type": "wallet_balance",
                "wallet_address": primary_wallet,
                "chain_id": chain_id,
                "result": "temporary_error",
                "safe_error_code": "RPC_UNAVAILABLE",
                "reason": "Ethereum RPC service is temporarily unavailable",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(rpc_err),
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    snap = platform_db.record_verified_balance_snapshot(
        user_id=uid,
        wallet_address=rpc_res["wallet_address"],
        chain_id=rpc_res["chain_id"],
        balance_wei_int=rpc_res["balance_wei_int"],
        block_number=rpc_res["block_number"],
        rpc_source=rpc_res["rpc_source"],
    )
    snap["balance_eth"] = rpc_res["balance_eth"]
    updated_user = e2ee_db.get_user_by_id(uid)
    return {
        "success": True,
        "snapshot": snap,
        "user": updated_user,
    }


# ============================================================================
# AUTHORITATIVE SERVER-SIDE VERIFIED PAYMENT RECORDS
# ============================================================================

@router.post("/payments/verify")
def submit_and_verify_payment(
    payload: PaymentVerifyRequest,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    """
    Submits a transaction reference for authoritative server-side verification.
    The frontend CANNOT mark a payment as verified directly.
    - Idempotent: safe retries return existing record without double-crediting.
    - Recipient must match the server-controlled authorized payment destination.
    - Sender must match the authenticated user's primary wallet.
    - Transaction must be on an allowed chain/network and succeeded on-chain.
    - Unverified/pending/failed payments do NOT count toward level qualification.
    - If verification fails temporarily, stores a safe retryable state.
    - If DB fails, an error is logged and payment is not reported as verified.
    """
    user = ctx["user"]
    uid = user["user_id"]
    _check_rate_limit("payment_verify", uid, max_hits=10, window_sec=60.0)

    user_wallet = user.get("primary_wallet")
    if not user_wallet:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authenticated user does not have a primary wallet address linked.",
        )

    clean_ref = payload.transaction_reference.strip().lower()
    settings = platform_db.get_platform_settings()
    cid = int(payload.chain_id or settings.get("default_balance_chain_id") or 1)

    # 1. Enforce allowed chain / network
    allowed_chains = platform_db.get_allowed_payment_chain_ids()
    if cid not in allowed_chains:
        logger.warning("Payment verification rejected: chain_id %s is not in allowed chains %s", cid, allowed_chains)
        try:
            payment, _ = platform_db.create_or_submit_payment_record(
                user_id=uid,
                transaction_reference=clean_ref,
                chain_id=cid,
                wallet_address=user_wallet,
            )
            platform_db.record_failed_payment(
                payment["payment_id"],
                error_message=f"Transaction is on unsupported chain {cid}. Allowed chains: {allowed_chains}",
            )
        except Exception:
            pass
        platform_db.record_audit_log(
            actor_user_id=uid,
            action="verification_failure",
            entity_type="payment",
            entity_id=clean_ref,
            details={
                "event_type": "verification_failure",
                "result": "rejected",
                "safe_error_code": "UNSUPPORTED_CHAIN",
                "reason": f"Transaction chain {cid} is not allowed",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported chain_id {cid}. Allowed chains are: {allowed_chains}.",
        )

    # 2. Enforce authorized payment destination (Fail closed if missing or invalid)
    authorized_dest = platform_db.get_authorized_payment_destination()
    if not authorized_dest or not Web3.is_address(authorized_dest):
        logger.error(
            "Payment verification fail-closed: server authorized payment destination is missing or invalid (%s)",
            authorized_dest,
        )
        try:
            payment, _ = platform_db.create_or_submit_payment_record(
                user_id=uid,
                transaction_reference=clean_ref,
                chain_id=cid,
                wallet_address=user_wallet,
            )
            platform_db.record_pending_payment_retry(
                payment["payment_id"],
                error_message="Payment verification service configuration error (missing/invalid destination)",
            )
        except Exception as db_err:
            logger.error("Database error saving pending payment: %s", db_err)

        platform_db.record_audit_log(
            actor_user_id=uid,
            action="verification_failure",
            entity_type="payment",
            entity_id=clean_ref,
            details={
                "event_type": "verification_failure",
                "target_type": "payment",
                "transaction_reference": clean_ref,
                "result": "retryable_failure",
                "safe_error_code": "CONFIGURATION_ERROR",
                "reason": "Payment verification service is not properly configured with an authorized destination",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment verification service is temporarily unavailable due to server configuration. Safe to retry.",
        )

    # 3. Create or fetch payment submission record (enforces unique transaction reference)
    req_purpose = payload.purpose or "platform_entry"
    if req_purpose not in ("platform_entry", "group_entry"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="purpose must be 'platform_entry' or 'group_entry'",
        )
    req_group_id = payload.group_id
    req_wei = 0
    grp_pol: Optional[Dict[str, Any]] = None
    if req_purpose == "platform_entry":
        # Minimum acceptable payment = current USD price in ETH, minus a small tolerance
        # for ETH price movement between the quote and the transaction being mined.
        tol_pct = float(os.getenv("PAYMENT_PRICE_TOLERANCE_PCT", "5"))
        quoted_wei = int(platform_db.get_platform_pricing().get("platform_entry_fee_wei") or 0)
        req_wei = int(quoted_wei * (100.0 - tol_pct) / 100.0)
    if req_purpose == "group_entry":
        if not req_group_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="group_id is required when purpose is group_entry",
            )
        grp_pol = platform_db.get_group_pricing(req_group_id)
        if not grp_pol.get("is_paid"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This group is free; no entry payment is needed.",
            )
        tol_pct_g = float(os.getenv("PAYMENT_PRICE_TOLERANCE_PCT", "5"))
        req_wei = int(int(grp_pol.get("entry_fee_wei") or 0) * (100.0 - tol_pct_g) / 100.0)

    try:
        payment, created = platform_db.create_or_submit_payment_record(
            user_id=uid,
            transaction_reference=clean_ref,
            chain_id=cid,
            wallet_address=user_wallet,
            purpose=req_purpose,
            target_id=req_group_id,
        )
    except Exception as exc:
        logger.error("Database failure creating payment submission for user %s: %s", uid, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed; payment was not recorded or verified.",
        )

    # A transaction hash belongs to whoever submitted it first. Another account must not be
    # able to read, replay, or fail someone else's payment record.
    if payment.get("user_id") != uid:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This transaction was already submitted by another account.",
        )

    # Idempotent shortcut: if already verified, return immediately without re-querying or duplicate credit
    if payment["status"] == "verified":
        return {
            "success": True,
            "status": "verified",
            "payment": payment,
            "already_verified": True,
            "user": e2ee_db.get_user_by_id(uid),
        }

    # 4. Authoritative server-side RPC verification
    try:
        v_res = eth_rpc.verify_onchain_payment_transaction(
            tx_hash=clean_ref,
            chain_id=cid,
            expected_sender=user_wallet,
            expected_recipient=authorized_dest,
            allowed_chain_ids=allowed_chains,
        )
    except eth_rpc.EthereumRpcUnavailableError as rpc_err:
        logger.warning("Payment RPC service unavailable for tx %s: %s", clean_ref, rpc_err)
        try:
            payment = platform_db.record_pending_payment_retry(
                payment["payment_id"],
                error_message="Verification service temporarily unavailable",
            )
        except Exception as db_err:
            logger.error("Database error saving pending payment retry for %s: %s", clean_ref, db_err)
        platform_db.record_audit_log(
            actor_user_id=uid,
            action="verification_failure",
            entity_type="payment",
            entity_id=payment["payment_id"],
            details={
                "event_type": "verification_failure",
                "target_type": "payment",
                "transaction_reference": clean_ref,
                "result": "retryable_failure",
                "safe_error_code": "RPC_UNAVAILABLE",
                "reason": "Payment verification service is temporarily unavailable",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment verification service is temporarily unavailable. Safe to retry.",
        )
    except ValueError as val_err:
        logger.info("Invalid payment transaction reference format or parameter: %s", val_err)
        try:
            payment = platform_db.record_failed_payment(
                payment["payment_id"],
                error_message=str(val_err),
            )
        except Exception:
            pass
        platform_db.record_audit_log(
            actor_user_id=uid,
            action="verification_failure",
            entity_type="payment",
            entity_id=payment["payment_id"],
            details={
                "event_type": "verification_failure",
                "target_type": "payment",
                "transaction_reference": clean_ref,
                "result": "rejected",
                "safe_error_code": "INVALID_TRANSACTION",
                "reason": str(val_err),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )

    # 5. Handle authoritative verification status
    try:
        if v_res.get("status") == "verified":
            recip = v_res.get("recipient_address")
            if recip and recip.lower() != authorized_dest.lower():
                failed_record = platform_db.record_failed_payment(
                    payment_id=payment["payment_id"],
                    error_message=f"Recipient mismatch (expected {authorized_dest}, found {recip})",
                    verification_source=v_res.get("verification_source", "ethereum_rpc"),
                    recipient_address=recip,
                )
                return {
                    "success": False,
                    "status": "failed",
                    "payment": failed_record,
                    "reason": f"Recipient mismatch (expected {authorized_dest}, found {recip})",
                }

            if req_wei > 0:
                paid_atomic = int(v_res.get("amount_atomic") or 0)
                if paid_atomic < req_wei:
                    need_eth = (
                        grp_pol.get("entry_fee_eth", "0")
                        if req_purpose == "group_entry" and grp_pol
                        else str(Web3.from_wei(req_wei, "ether"))
                    )
                    failed_record = platform_db.record_failed_payment(
                        payment_id=payment["payment_id"],
                        error_message=f"Insufficient payment: expected at least {need_eth} ETH",
                        verification_source=v_res.get("verification_source", "ethereum_rpc"),
                        recipient_address=recip,
                    )
                    return {
                        "success": False,
                        "status": "failed",
                        "payment": failed_record,
                        "reason": f"Insufficient payment: expected at least {need_eth} ETH",
                    }

            verified_record = platform_db.record_verified_payment(
                payment_id=payment["payment_id"],
                wallet_address=v_res.get("wallet_address") or user_wallet,
                amount_atomic=v_res.get("amount_atomic", "0"),
                amount_formatted=v_res.get("amount_formatted", "0"),
                currency=v_res.get("currency", "ETH"),
                network=v_res.get("network", "ethereum"),
                chain_id=v_res.get("chain_id", cid),
                block_number=v_res.get("block_number"),
                verification_source=v_res.get("verification_source", "ethereum_rpc"),
                recipient_address=recip or authorized_dest,
                purpose=req_purpose,
                target_id=req_group_id,
            )
            return {
                "success": True,
                "status": "verified",
                "payment": verified_record,
                "user": e2ee_db.get_user_by_id(uid),
                "is_platform_paid": platform_db.has_user_paid_platform_entry(uid),
            }
        elif v_res.get("status") == "failed":
            failed_record = platform_db.record_failed_payment(
                payment_id=payment["payment_id"],
                error_message=v_res.get("reason", "Transaction reverted on-chain"),
                verification_source=v_res.get("verification_source", "ethereum_rpc"),
                recipient_address=v_res.get("recipient_address"),
            )
            return {
                "success": False,
                "status": "failed",
                "payment": failed_record,
                "reason": v_res.get("reason"),
            }
        else:
            pending_record = platform_db.record_pending_payment_retry(
                payment_id=payment["payment_id"],
                error_message=v_res.get("reason", "Awaiting on-chain confirmation"),
            )
            return {
                "success": False,
                "status": "pending",
                "payment": pending_record,
                "reason": v_res.get("reason"),
            }
    except Exception as db_exc:
        logger.error("Database error while committing payment result for %s: %s", clean_ref, db_exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed; payment was not recorded or verified.",
        )


@router.get("/payments/history")
def get_my_payment_history(
    limit: int = Query(50, ge=1, le=200),
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    uid = ctx["user"]["user_id"]
    payments = platform_db.list_user_payment_records(uid, limit=limit)
    total_verified_wei = platform_db.get_user_verified_payment_total_wei(uid)
    return {
        "user_id": uid,
        "total_verified_wei": str(total_verified_wei),
        "total_verified_eth": str(Web3.from_wei(total_verified_wei, "ether")),
        "payments": payments,
    }


@router.get("/admin/payments")
def admin_list_payments_endpoint(
    limit: int = Query(100, ge=1, le=300),
    status: Optional[str] = Query(None),
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    records = platform_db.admin_list_payment_records(limit=limit, status_filter=status)
    return {"payments": records, "count": len(records)}


@router.post("/admin/payments/{payment_id}/retry")
def admin_retry_payment_verification_endpoint(
    payment_id: str,
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    record = platform_db.get_payment_record(payment_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment record not found")

    if record["status"] == "verified":
        return {"success": True, "already_verified": True, "payment": record}

    if int(record.get("retry_count") or 0) >= 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payment has reached the maximum allowed verification retries (10). Cannot retry further.",
        )

    cid = record.get("chain_id") or 1
    tx_ref = record["transaction_reference"]

    authorized_dest = platform_db.get_authorized_payment_destination()
    if not authorized_dest or not Web3.is_address(authorized_dest):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorized payment destination is not configured by administrator. Cannot verify payment.",
        )

    allowed_chains = platform_db.get_allowed_payment_chain_ids()
    if cid not in allowed_chains:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Transaction is on unsupported chain {cid}. Allowed chains: {allowed_chains}",
        )

    try:
        v_res = eth_rpc.verify_onchain_payment_transaction(
            tx_hash=tx_ref,
            chain_id=cid,
            expected_sender=record.get("wallet_address"),
            expected_recipient=authorized_dest,
            allowed_chain_ids=allowed_chains,
        )
    except eth_rpc.EthereumRpcUnavailableError as rpc_err:
        platform_db.record_pending_payment_retry(payment_id, error_message=str(rpc_err))
        platform_db.record_audit_log(
            actor_user_id=record.get("user_id") or "system",
            action="verification_failure",
            entity_type="payment",
            entity_id=payment_id,
            details={
                "event_type": "verification_failure",
                "target_type": "payment",
                "transaction_reference": tx_ref,
                "result": "temporary_error",
                "safe_error_code": "RPC_UNAVAILABLE",
                "reason": "Payment verification service is temporarily unavailable",
            },
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(rpc_err))

    if v_res.get("status") == "verified":
        recip = v_res.get("recipient_address")
        if recip and recip.lower() != authorized_dest.lower():
            updated = platform_db.record_failed_payment(
                payment_id=payment_id,
                error_message=f"Recipient mismatch (expected {authorized_dest}, found {recip})",
                verification_source="admin_rpc_retry",
                recipient_address=recip,
            )
            return {"success": False, "status": "failed", "payment": updated}

        updated = platform_db.record_verified_payment(
            payment_id=payment_id,
            wallet_address=v_res.get("wallet_address") or record.get("wallet_address"),
            amount_atomic=v_res.get("amount_atomic", "0"),
            amount_formatted=v_res.get("amount_formatted", "0"),
            currency=v_res.get("currency", "ETH"),
            network=v_res.get("network", "ethereum"),
            chain_id=v_res.get("chain_id", cid),
            block_number=v_res.get("block_number"),
            verification_source="admin_rpc_retry",
            recipient_address=recip or authorized_dest,
        )
        return {"success": True, "status": "verified", "payment": updated}
    elif v_res.get("status") == "failed":
        updated = platform_db.record_failed_payment(
            payment_id=payment_id,
            error_message=v_res.get("reason", "Transaction reverted"),
            verification_source="admin_rpc_retry",
            recipient_address=v_res.get("recipient_address"),
        )
        return {"success": False, "status": "failed", "payment": updated}
    else:
        updated = platform_db.record_pending_payment_retry(
            payment_id=payment_id,
            error_message=v_res.get("reason", "Pending confirmation"),
        )
        return {"success": False, "status": "pending", "payment": updated}


# ============================================================================
# 4. GROUP ACCESS POLICIES, DISCOVERY, INVITE LINKS & LEAVE GROUP
# ============================================================================

def _require_group_admin_or_platform_admin(
    group_id: str,
    user_id: str,
) -> None:
    if platform_db.is_group_admin(group_id, user_id):
        return
    if platform_db.get_admin_role(user_id) in ("moderator", "superadmin"):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden: group admin privilege required",
    )


def _public_group_price_fields(group_id: str) -> Dict[str, Any]:
    """Current entry price of a group (USD + live ETH conversion) for the UI."""
    gp = platform_db.get_group_pricing(group_id)
    return {
        "entry_fee_usd": gp["entry_fee_usd"],
        "entry_fee_eth": gp["entry_fee_eth"],
        "entry_fee_wei": gp["entry_fee_wei"],
        "eth_usd_price": gp["eth_usd_price"],
        "rate_source": gp["rate_source"],
    }


@router.get("/groups/discover")
def discover_public_groups(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    opt_ctx = _require_paid_member_ctx(request, authorization)
    viewer_uid = opt_ctx["user"]["user_id"]
    groups = platform_db.list_discoverable_groups(viewer_user_id=viewer_uid)
    for g in groups:
        g["min_eth_balance_eth"] = str(Web3.from_wei(int(g["min_eth_balance_wei"] or "0"), "ether"))
        if g.get("is_paid"):
            g.update(_public_group_price_fields(g["group_id"]))
    return {"groups": groups}


@router.get("/groups/{group_id}/policy")
def get_group_policy_endpoint(
    group_id: str,
    _ctx: Dict[str, Any] = Depends(require_paid_member),
):
    grp = e2ee_db.get_mls_group(group_id)
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    pol = platform_db.get_group_access_policy(group_id)
    pol["min_eth_balance_eth"] = str(Web3.from_wei(int(pol["min_eth_balance_wei"] or "0"), "ether"))
    return {"group_id": group_id, "name": grp["name"], "policy": pol}


@router.put("/groups/{group_id}/policy")
def update_group_policy_endpoint(
    group_id: str,
    payload: GroupPolicyUpdateRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    grp = e2ee_db.get_mls_group(group_id)
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")

    actor_uid: Optional[str] = None
    if x_admin_token:
        try:
            actor = _resolve_admin_actor(request, authorization, x_admin_token, min_role="superadmin")
            actor_uid = actor["actor_user_id"]
        except HTTPException:
            pass

    if not actor_uid:
        ctx = require_authenticated_session(request, authorization)
        actor_uid = ctx["user"]["user_id"]
        _require_group_admin_or_platform_admin(group_id, actor_uid)

    safe_avatar = _validate_safe_optional_url(payload.avatar_url, "avatar_url")
    min_wei = _eth_or_wei_to_wei_str(payload.min_eth_balance_wei, payload.min_eth_balance_eth)

    # Only the platform's superadmin decides whether a group is paid and what it costs.
    # Group owners can still edit everything else; their payment fields are ignored.
    is_superadmin = bool(x_admin_token and actor_uid) or platform_db.get_admin_role(actor_uid) == "superadmin"
    current = platform_db.get_group_access_policy(group_id)
    if is_superadmin:
        eff_paid = bool(payload.is_paid)
        eff_fee_eth = str(payload.entry_fee_eth or "0")
        eff_fee_usd = payload.entry_fee_usd
        if eff_paid and eff_fee_usd is None and float(eff_fee_eth or 0) <= 0:
            try:
                eff_fee_usd = float(current.get("entry_fee_usd") or 0) or None  # keep the existing price
            except Exception:
                eff_fee_usd = None
    else:
        wants_paid = bool(payload.is_paid)
        changes_fee = payload.entry_fee_usd is not None and float(payload.entry_fee_usd) != float(
            current.get("entry_fee_usd") or 0
        )
        if wants_paid and (not current.get("is_paid") or changes_fee):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the platform admin can make a group paid or change its price.",
            )
        eff_paid = bool(current.get("is_paid"))
        eff_fee_eth = str(current.get("entry_fee_eth") or "0")
        try:
            usd_now = float(current.get("entry_fee_usd") or 0)
        except Exception:
            usd_now = 0.0
        eff_fee_usd = usd_now if usd_now > 0 else None

    try:
        pol = platform_db.upsert_group_access_policy(
            group_id=group_id,
            description=payload.description,
            avatar_url=safe_avatar,
            visibility=payload.visibility,
            min_level=payload.min_level,
            min_eth_balance_wei=min_wei,
            require_invitation=payload.require_invitation,
            actor_user_id=actor_uid,
            is_paid=eff_paid,
            entry_fee_eth=eff_fee_eth,
            entry_fee_usd=eff_fee_usd,
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    pol["min_eth_balance_eth"] = str(Web3.from_wei(int(pol["min_eth_balance_wei"] or "0"), "ether"))
    pol.update(_public_group_price_fields(group_id))
    return {"success": True, "policy": pol}


@router.post("/groups/{group_id}/invites")
def create_group_invite_endpoint(
    group_id: str,
    payload: GroupInviteCreateRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    uid = ctx["user"]["user_id"]
    _require_group_admin_or_platform_admin(group_id, uid)
    inv = platform_db.create_group_invite_link(
        group_id=group_id,
        creator_user_id=uid,
        expires_hours=payload.expires_hours,
        max_uses=payload.max_uses,
    )
    return {"success": True, "invite": inv}


@router.get("/groups/{group_id}/invites")
def list_group_invites_endpoint(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    _require_group_admin_or_platform_admin(group_id, ctx["user"]["user_id"])
    return {"invites": platform_db.list_group_invite_links(group_id)}


@router.delete("/groups/{group_id}/invites/{invite_code}")
def revoke_group_invite_endpoint(
    group_id: str,
    invite_code: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    _require_group_admin_or_platform_admin(group_id, ctx["user"]["user_id"])
    platform_db.revoke_group_invite_link(group_id, invite_code)
    return {"success": True, "revoked": True}


@router.post("/groups/{group_id}/join-request")
def request_to_join_public_group(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    uid = ctx["user"]["user_id"]
    try:
        res = platform_db.create_group_join_request(user_id=uid, group_id=group_id)
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    grp = e2ee_db.get_mls_group(group_id)
    if grp:
        admin_uids = [m["user_id"] for m in grp["members"] if m["status"] == "active" and m.get("role") == "admin"]
        _schedule_ws_notify(admin_uids, {"type": "group_join_request", "group_id": group_id, "requester_user_id": uid})
    return {"success": True, **res}


@router.post("/groups/join-by-invite/{invite_code}")
def join_group_with_invite_code(
    invite_code: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    uid = ctx["user"]["user_id"]
    try:
        res = platform_db.create_group_join_request(user_id=uid, invite_code=invite_code)
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    grp = e2ee_db.get_mls_group(res["group_id"])
    if grp:
        admin_uids = [m["user_id"] for m in grp["members"] if m["status"] == "active" and m.get("role") == "admin"]
        _schedule_ws_notify(admin_uids, {"type": "group_join_request", "group_id": res["group_id"], "requester_user_id": uid})
    return {"success": True, **res}


@router.get("/groups/{group_id}/join-requests")
def get_pending_group_join_requests_endpoint(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    _require_group_admin_or_platform_admin(group_id, ctx["user"]["user_id"])
    return {"requests": platform_db.list_pending_group_join_requests(group_id)}


@router.post("/groups/{group_id}/leave")
def leave_encrypted_group_endpoint(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    uid = ctx["user"]["user_id"]
    try:
        res = platform_db.leave_group_self(group_id, uid)
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))

    grp = e2ee_db.get_mls_group(group_id)
    if grp:
        active_uids = [m["user_id"] for m in grp["members"] if m["status"] == "active"]
        _schedule_ws_notify(active_uids, {"type": "group_member_left", "group_id": group_id, "left_user_id": uid})
    return {"success": True, **res}


@router.post("/groups/{group_id}/members/{target_user_id}/role")
def set_group_member_role_endpoint(
    group_id: str,
    target_user_id: str,
    payload: GroupMemberRoleUpdateRequest,
    ctx: Dict[str, Any] = Depends(require_paid_member),
):
    uid = ctx["user"]["user_id"]
    _require_group_admin_or_platform_admin(group_id, uid)
    platform_db.update_group_member_role(group_id, target_user_id, payload.role, actor_user_id=uid)
    return {"success": True, "group_id": group_id, "target_user_id": target_user_id, "role": payload.role}


# ============================================================================
# 5. ADMINISTRATIVE DASHBOARD, RBAC & AUDIT LOGS (`/api/platform/admin/*`)
# ============================================================================

@router.get("/admin/overview")
def admin_overview_endpoint(admin_ctx: Dict[str, Any] = Depends(require_moderator)):
    return {
        "role": admin_ctx["role"],
        "actor_user_id": admin_ctx["actor_user_id"],
        "stats": platform_db.admin_get_overview_stats(),
        "online": realtime_hub.get_online_stats(),
        "networks": eth_rpc.get_rpc_health_status(),
    }


@router.get("/admin/users")
def admin_list_users_endpoint(
    q: str = Query("", max_length=64),
    limit: int = Query(50, ge=1, le=200),
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    return {"users": platform_db.admin_list_users(query=q, limit=limit)}


@router.get("/admin/users/{target_user_id}/inspect")
def admin_inspect_user_endpoint(
    target_user_id: str,
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    user = e2ee_db.get_user_by_id(target_user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    wallet_hist = platform_db.list_wallet_history(target_user_id)
    bal_hist = platform_db.list_user_balance_history(target_user_id)

    ext = platform_db.get_extended_user_fields(target_user_id) or {}
    bal_wei = int(ext.get("qualifying_balance_wei") or 0) if ext.get("primary_wallet") else 0
    pay_wei = platform_db.get_user_verified_payment_total_wei(target_user_id)
    user_payments = platform_db.list_user_payment_records(target_user_id, limit=50)
    pending_count = sum(1 for p in user_payments if p.get("status") == "pending")

    return {
        "user": user,
        "username_history": platform_db.list_username_history(target_user_id),
        "wallets": wallet_hist["wallets"],
        "wallet_history": wallet_hist["history"],
        "balance_snapshots": bal_hist["snapshots"],
        "devices": e2ee_db.list_user_devices(target_user_id, include_revoked=True),
        "qualification_status": {
            "wallet_balance_eth": str(Web3.from_wei(bal_wei, "ether")),
            "verified_payments_eth": str(Web3.from_wei(pay_wei, "ether")),
            "pending_payments_count": pending_count,
        },
    }


@router.post("/admin/users/{target_user_id}/moderate")
def admin_moderate_user_endpoint(
    target_user_id: str,
    payload: AdminUserModerateRequest,
    admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    target = e2ee_db.get_user_by_id(target_user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")
    if target.get("admin_role") == "superadmin" and admin_ctx["role"] != "superadmin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot moderate a superadmin")

    updated = platform_db.admin_moderate_user_account(
        target_user_id=target_user_id,
        action_type=payload.action_type,
        reason=payload.reason.strip(),
        moderator_user_id=admin_ctx["actor_user_id"],
        duration_hours=payload.duration_hours,
    )
    return {"success": True, "user": updated}


@router.post("/admin/users/{target_user_id}/verify-balance")
def admin_trigger_user_balance_verification(
    target_user_id: str,
    payload: Optional[VerifyBalanceRequest] = None,
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    user = e2ee_db.get_user_by_id(target_user_id)
    if not user or not user.get("primary_wallet"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User or primary wallet not found")

    settings = platform_db.get_platform_settings()
    chain_id = int(
        (payload.chain_id if payload and payload.chain_id else None)
        or settings.get("default_balance_chain_id")
        or 1
    )
    try:
        rpc_res = eth_rpc.verify_onchain_eth_balance(user["primary_wallet"], chain_id=chain_id)
    except eth_rpc.EthereumRpcUnavailableError as rpc_err:
        platform_db.record_audit_log(
            actor_user_id=target_user_id,
            action="verification_failure",
            entity_type="wallet_balance",
            entity_id=target_user_id,
            details={
                "event_type": "verification_failure",
                "target_type": "wallet_balance",
                "wallet_address": user.get("primary_wallet"),
                "chain_id": chain_id,
                "result": "temporary_error",
                "safe_error_code": "RPC_UNAVAILABLE",
                "reason": "Ethereum RPC service is temporarily unavailable",
            },
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(rpc_err))

    snap = platform_db.record_verified_balance_snapshot(
        user_id=target_user_id,
        wallet_address=rpc_res["wallet_address"],
        chain_id=rpc_res["chain_id"],
        balance_wei_int=rpc_res["balance_wei_int"],
        block_number=rpc_res["block_number"],
        rpc_source=rpc_res["rpc_source"],
    )
    snap["balance_eth"] = rpc_res["balance_eth"]
    return {"success": True, "snapshot": snap, "user": e2ee_db.get_user_by_id(target_user_id)}


@router.post("/admin/users/{target_user_id}/role")
def admin_set_user_role_endpoint(
    target_user_id: str,
    payload: AdminRoleGrantRequest,
    admin_ctx: Dict[str, Any] = Depends(require_superadmin),
):
    if not e2ee_db.get_user_by_id(target_user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")
    platform_db.set_admin_role(
        user_id=target_user_id,
        role=payload.role,
        actor_user_id=admin_ctx["actor_user_id"],
    )
    return {"success": True, "user": e2ee_db.get_user_by_id(target_user_id)}


@router.get("/admin/groups")
def admin_list_groups_endpoint(
    limit: int = Query(100, ge=1, le=300),
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    groups = platform_db.admin_list_all_groups(limit=limit)
    for g in groups:
        g["policy"]["min_eth_balance_eth"] = str(
            Web3.from_wei(int(g["policy"]["min_eth_balance_wei"] or "0"), "ether")
        )
    return {"groups": groups}


@router.get("/admin/reports")
def admin_list_reports_endpoint(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=300),
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    return {"reports": platform_db.list_abuse_reports(status_filter=status_filter, limit=limit)}


@router.post("/admin/reports/{report_id}/resolve")
def admin_resolve_report_endpoint(
    report_id: str,
    payload: AdminReportResolveRequest,
    admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    res = platform_db.resolve_abuse_report(
        report_id=report_id,
        reviewer_user_id=admin_ctx["actor_user_id"],
        new_status=payload.status,
        resolution_note=payload.resolution_note.strip(),
    )
    return {"success": True, "report": res}


@router.get("/admin/settings")
def admin_get_settings_endpoint(_admin_ctx: Dict[str, Any] = Depends(require_moderator)):
    return {"settings": platform_db.get_platform_settings()}


@router.put("/admin/settings")
def admin_update_settings_endpoint(
    payload: AdminSettingsUpdateRequest,
    admin_ctx: Dict[str, Any] = Depends(require_superadmin),
):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    try:
        updated = platform_db.update_platform_settings(updates, actor_user_id=admin_ctx["actor_user_id"])
        return {"success": True, "settings": updated}
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.get("/admin/payment-destination")
def admin_get_payment_destination_endpoint(_admin_ctx: Dict[str, Any] = Depends(require_moderator)):
    """Authoritative Admin endpoint to inspect the configured payment destination."""
    dest = platform_db.get_authorized_payment_destination()
    return {
        "authorized_payment_destination": dest,
        "is_configured": bool(dest),
        "allowed_chains": platform_db.get_allowed_payment_chain_ids(),
    }


@router.put("/admin/payment-destination")
def admin_update_payment_destination_endpoint(
    payload: PaymentDestinationUpdateRequest,
    admin_ctx: Dict[str, Any] = Depends(require_superadmin),
):
    """
    Authoritative Admin endpoint to update the authorized payment destination.
    Editable only by superadmin, records audit log with actor, timestamp, previous_value, and new_value.
    """
    try:
        res = platform_db.update_authorized_payment_destination(
            new_destination=payload.destination_address,
            actor_user_id=admin_ctx["actor_user_id"],
        )
        return res
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.get("/payments/destination")
def get_user_payment_destination(ctx: Dict[str, Any] = Depends(require_authenticated_session)):
    """
    Safe endpoint for authenticated users to query the currently authorized payment destination.
    Never exposes internal secrets or unauthorized configuration.
    """
    dest = platform_db.get_authorized_payment_destination()
    if not dest:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment destination is not currently configured by administrator.",
        )
    return {
        "destination_address": dest,
        "allowed_chains": platform_db.get_allowed_payment_chain_ids(),
    }


@router.get("/admin/audit-logs")
def admin_get_audit_logs_endpoint(
    limit: int = Query(100, ge=1, le=500),
    action: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    entity_id: Optional[str] = Query(None),
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    return {
        "audit_logs": platform_db.list_audit_logs(
            limit=limit,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
        )
    }


# ============================================================================
# 8. PLATFORM & GROUP ADMISSION PRICING & MEMBERSHIP PAYWALL
# ============================================================================

@router.get("/pricing")
def get_public_pricing():
    """Returns platform pricing, authorized destination, and allowed payment chains."""
    return platform_db.get_platform_pricing()


@router.get("/membership/status")
def get_membership_status(ctx: Dict[str, Any] = Depends(require_authenticated_session)):
    """Returns the caller's platform membership status and current platform pricing."""
    user = ctx["user"]
    uid = user["user_id"]
    is_paid = platform_db.has_user_paid_platform_entry(uid)
    ext = platform_db.get_extended_user_fields(uid)
    pricing = platform_db.get_platform_pricing()
    return {
        "user_id": uid,
        "wallet_address": user.get("primary_wallet"),
        "is_platform_paid": is_paid,
        "platform_paid_at": ext.get("platform_paid_at"),
        "pricing": pricing,
    }


@router.get("/groups/{group_id}/pricing")
def get_group_pricing_endpoint(
    group_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Returns group admission fee in ETH and USD, and whether caller has paid."""
    grp = e2ee_db.get_mls_group(group_id)
    if not grp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    gp = platform_db.get_group_pricing(group_id)
    pricing = platform_db.get_platform_pricing()
    fee_eth_str = gp["entry_fee_eth"]
    fee_usd = gp["entry_fee_usd"]
    eth_usd = gp["eth_usd_price"]

    has_paid = False
    try:
        if authorization and authorization.startswith("Bearer "):
            token = authorization.split(" ", 1)[1].strip()
            sess = e2ee_db.get_session_by_token(token)
            if sess:
                has_paid = platform_db.has_user_paid_group_entry(sess["user_id"], group_id)
    except Exception:
        pass

    return {
        "group_id": group_id,
        "name": grp.get("name"),
        "is_paid": bool(gp["is_paid"]),
        "entry_fee_eth": fee_eth_str,
        "entry_fee_wei": gp["entry_fee_wei"],
        "entry_fee_usd": fee_usd,
        "eth_usd_price": eth_usd,
        "rate_source": gp["rate_source"],
        "has_paid": has_paid,
        "authorized_payment_destination": pricing.get("authorized_payment_destination"),
        "allowed_payment_chain_ids": pricing.get("allowed_payment_chain_ids", [1, 11155111]),
    }


@router.put("/admin/pricing")
def admin_update_pricing_endpoint(
    payload: AdminPricingUpdateRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    """Superadmin endpoint to configure platform entry fee in ETH, ETH USD valuation, and destination."""
    actor = _resolve_admin_actor(request, authorization, x_admin_token, min_role="superadmin")
    updates: Dict[str, Any] = {}
    if payload.platform_entry_fee_usd is not None:
        updates["platform_entry_fee_usd"] = payload.platform_entry_fee_usd
    if payload.use_live_eth_price is not None:
        updates["use_live_eth_price"] = payload.use_live_eth_price
    if payload.platform_entry_fee_eth is not None:
        updates["platform_entry_fee_eth"] = payload.platform_entry_fee_eth
    if payload.eth_usd_price is not None:
        updates["eth_usd_price"] = payload.eth_usd_price
    if payload.authorized_payment_destination is not None:
        updates["authorized_payment_destination"] = payload.authorized_payment_destination

    if not updates:
        return {"success": True, "pricing": platform_db.get_platform_pricing()}

    try:
        platform_db.update_platform_settings(updates, actor_user_id=actor["actor_user_id"])
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    return {"success": True, "pricing": platform_db.get_platform_pricing()}


# ============================================================================
# 9. TALK TO ADMIN (support conversations)
# ============================================================================

class SupportThreadCreateRequest(StrictModel):
    subject: str = Field(..., min_length=3, max_length=120)
    message: str = Field(..., min_length=1, max_length=2000)


class SupportMessageRequest(StrictModel):
    content: str = Field(..., min_length=1, max_length=2000)


class SupportStatusRequest(StrictModel):
    status: str = Field(..., pattern=r"^(open|closed)$")


def _support_thread_public(t: Dict[str, Any], viewer: str) -> Dict[str, Any]:
    """Thread as shown to its owner ('user') or to the admin team ('admin')."""
    out = {
        "thread_id": t["thread_id"],
        "subject": t["subject"],
        "status": t["status"],
        "created_at": t["created_at"],
        "last_message_at": t["last_message_at"],
        "last_sender_role": t["last_sender_role"],
        "unread": int(t["user_unread"] if viewer == "user" else t["admin_unread"]),
    }
    return out


def _own_support_thread(thread_id: str, uid: str) -> Dict[str, Any]:
    t = support_db.get_thread(thread_id)
    # Same answer for "missing" and "someone else's" so thread ids cannot be probed.
    if not t or t["user_id"] != uid:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    return t


@router.post("/support/threads")
def create_support_thread(
    payload: SupportThreadCreateRequest,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    """Any signed-in user (paid or not, so payment problems can be reported) can write to the admin."""
    uid = ctx["user"]["user_id"]
    _check_rate_limit("support_msg", uid, max_hits=10, window_sec=60.0)
    subject = _sanitize_public_text(payload.subject, max_len=120)
    message = _sanitize_public_text(payload.message, max_len=2000)
    try:
        t = support_db.create_thread(uid, subject, message)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(ve))
    return {"success": True, "thread": _support_thread_public(t, "user")}


@router.get("/support/threads")
def list_my_support_threads(ctx: Dict[str, Any] = Depends(require_authenticated_session)):
    uid = ctx["user"]["user_id"]
    threads = [_support_thread_public(t, "user") for t in support_db.list_user_threads(uid)]
    return {"threads": threads, "unread_total": sum(t["unread"] for t in threads)}


@router.get("/support/unread")
def my_support_unread(ctx: Dict[str, Any] = Depends(require_authenticated_session)):
    return {"unread_total": support_db.user_unread_total(ctx["user"]["user_id"])}


@router.get("/support/threads/{thread_id}")
def get_my_support_thread(
    thread_id: str,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    uid = ctx["user"]["user_id"]
    t = _own_support_thread(thread_id, uid)
    msgs = support_db.list_messages(thread_id)
    support_db.mark_read(thread_id, "user")
    t["user_unread"] = 0
    return {"thread": _support_thread_public(t, "user"), "messages": msgs}


@router.post("/support/threads/{thread_id}/messages")
def reply_in_my_support_thread(
    thread_id: str,
    payload: SupportMessageRequest,
    ctx: Dict[str, Any] = Depends(require_authenticated_session),
):
    uid = ctx["user"]["user_id"]
    _own_support_thread(thread_id, uid)
    _check_rate_limit("support_msg", uid, max_hits=10, window_sec=60.0)
    content = _sanitize_public_text(payload.content, max_len=2000)
    msg = support_db.add_message(thread_id, "user", uid, content)
    return {"success": True, "message": msg}


@router.get("/admin/support/threads")
def admin_list_support_threads(
    status_filter: Optional[str] = Query(None, alias="status", pattern=r"^(open|closed)$"),
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    items = []
    for t in support_db.admin_list_threads(status_filter):
        u = e2ee_db.get_user_by_id(t["user_id"]) or {}
        row = _support_thread_public(t, "admin")
        row.update({
            "user_id": t["user_id"],
            "username": u.get("username"),
            "wallet_address": u.get("primary_wallet"),
        })
        items.append(row)
    return {"threads": items, "unread_total": support_db.admin_unread_total()}


@router.get("/admin/support/threads/{thread_id}")
def admin_get_support_thread(
    thread_id: str,
    _admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    t = support_db.get_thread(thread_id)
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    msgs = support_db.list_messages(thread_id)
    support_db.mark_read(thread_id, "admin")
    t["admin_unread"] = 0
    u = e2ee_db.get_user_by_id(t["user_id"]) or {}
    row = _support_thread_public(t, "admin")
    row.update({"user_id": t["user_id"], "username": u.get("username"), "wallet_address": u.get("primary_wallet")})
    return {"thread": row, "messages": msgs}


@router.post("/admin/support/threads/{thread_id}/reply")
def admin_reply_support_thread(
    thread_id: str,
    payload: SupportMessageRequest,
    admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    t = support_db.get_thread(thread_id)
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    content = _sanitize_public_text(payload.content, max_len=2000)
    actor = admin_ctx["actor_user_id"]
    msg = support_db.add_message(thread_id, "admin", actor, content)
    platform_db.record_audit_log(actor, "support_reply", "support_thread", thread_id, {"user_id": t["user_id"]})
    try:  # live nudge for users who have the app open
        _schedule_ws_notify([t["user_id"]], {"type": "support_reply", "thread_id": thread_id})
    except Exception:
        pass
    return {"success": True, "message": msg}


@router.post("/admin/support/threads/{thread_id}/status")
def admin_set_support_thread_status(
    thread_id: str,
    payload: SupportStatusRequest,
    admin_ctx: Dict[str, Any] = Depends(require_moderator),
):
    if not support_db.get_thread(thread_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    support_db.set_status(thread_id, payload.status)
    platform_db.record_audit_log(
        admin_ctx["actor_user_id"], "support_status", "support_thread", thread_id, {"status": payload.status}
    )
    return {"success": True, "status": payload.status}