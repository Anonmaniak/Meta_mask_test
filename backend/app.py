"""
Zyphra Ethereum Wallet-Linked Real-Time Chat Platform — FastAPI Backend.

Architecture:
- Unified Relational Storage: Neon PostgreSQL (with thread-safe SQLite fallback for local/unit tests)
- Wallet Authentication: Standardized EIP-4361 Sign-In with Ethereum (SIWE) via MetaMask
- High-Security End-to-End Encryption:
  - 1-to-1 & Multi-Device Private Chat: Olm v2 Double Ratchet (Vodozemac)
  - Encrypted Group Chat: IETF RFC 9420 Messaging Layer Security (MLS TreeKEM)
- Open Public Chat: Readable real-time public room with configurable guest policy & moderation
- Server-side Ethereum RPC wallet balance & on-chain payment verification
"""

import os
import re
import sys
import time
import threading
import subprocess
import urllib.request
from datetime import datetime, timezone
from typing import Any
from contextlib import asynccontextmanager

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _ensure_backend_dependencies() -> None:
    """Checks and automatically installs requirements.txt if any required packages are missing."""
    if os.getenv("TESTING") == "1" or "unittest" in sys.modules or "pytest" in sys.modules:
        return

    req_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if not os.path.exists(req_file):
        return

    required_modules = [
        "fastapi",
        "uvicorn",
        "dotenv",
        "web3",
        "eth_account",
        "cryptography",
        "pydantic",
        "starlette",
    ]
    missing = []
    for mod in required_modules:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)

    if missing:
        import subprocess

        print("=" * 65)
        print("  ZYPHRA CHAT PLATFORM — AUTOMATED DEPENDENCY SETUP")
        print("=" * 65)
        print(f"[AUTO-SETUP] Missing packages detected: {', '.join(missing)}")
        print(f"[AUTO-SETUP] Installing dependencies from requirements.txt via pip...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_file])
            print("[AUTO-SETUP] All dependencies successfully installed.")
            print("=" * 65)
        except Exception as err:
            print(f"[WARN] Dependency auto-install encountered an error: {err}")
            print(f"Please run manually: {sys.executable} -m pip install -r {req_file}")


_ensure_backend_dependencies()

try:
    from dotenv import load_dotenv
    if os.getenv("TESTING") != "1" and "unittest" not in sys.modules and "pytest" not in sys.modules:
        _backend_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        load_dotenv(_backend_env, override=True)
except Exception:
    pass

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

import chat_db
import platform_db
import eth_rpc
from eth_rpc import get_w3  # re-exported for convenience

# =============================================================
# ENVIRONMENT VARIABLES & CORS CONFIGURATION
# =============================================================
_raw_origins = os.getenv("FRONTEND_URL", "https://zyphra.in")
FRONTEND_URL = _raw_origins.split(",")[0].strip().rstrip("/")
_ALLOWED_ORIGINS = (
    [u.strip().rstrip("/") for u in _raw_origins.split(",") if u.strip()]
    + [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5500",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5500",
        "http://localhost:8080",
        "http://localhost:10000",
    ]
)
# Allow local dev/preview servers regardless of which ephemeral port Vite selects (e.g. 5174, 5175).
_LOCAL_DEV_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$"

SELF_URL = os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
KEEP_ALIVE_INTERVAL = 600


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _keep_alive_loop() -> None:
    if not SELF_URL:
        return
    ping_url = SELF_URL + "/api/health"
    while True:
        time.sleep(KEEP_ALIVE_INTERVAL)
        try:
            urllib.request.urlopen(ping_url, timeout=10)
        except Exception:
            pass


# =============================================================
# FASTAPI APPLICATION & LIFESPAN
# =============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    is_testing = "unittest" in sys.modules or os.getenv("TESTING") == "1"
    # Let sync route handlers (threadpool) hand real-time events to this loop.
    from e2ee_routes import capture_main_loop
    capture_main_loop()
    if not is_testing:
        try:
            from run_migrations import run_all_migrations
            run_all_migrations()
        except Exception as exc:
            print(f"[WARN] Database migration/startup note: {exc}")
            try:
                chat_db.init_chat_db()
                platform_db.ensure_platform_tables()
            except Exception:
                pass

        try:
            from startup_checks import log_security_report
            log_security_report()
        except Exception as exc:  # never block startup on the self-check
            print(f"[WARN] Security self-check could not run: {exc}")

        if SELF_URL:
            ka_thread = threading.Thread(target=_keep_alive_loop, daemon=True)
            ka_thread.start()

        rpc_status = eth_rpc.get_rpc_health_status()
        print(
            f"[OK] Zyphra Chat Platform ready | "
            f"Mainnet RPC={rpc_status['mainnet']['connected']} | "
            f"Sepolia RPC={rpc_status['sepolia']['connected']}"
        )
    else:
        try:
            chat_db.init_chat_db()
            platform_db.ensure_platform_tables()
        except Exception:
            pass

    yield
    if not is_testing:
        print("[STOP] Zyphra Chat Platform shutting down")


app = FastAPI(
    title="Zyphra Ethereum Wallet-Linked Chat Platform API",
    version="3.0.0",
    description=(
        "Real-time Ethereum wallet-linked chat platform with SIWE authentication, "
        "Olm v2 + MLS RFC 9420 E2EE, Open Public Chat, Verified On-Chain Payments, and RBAC Admin."
    ),
    lifespan=lifespan,
)

# Public Room Envelope & Key Routers
from chat_keys import router as chat_keys_router
from chat_routes import router as chat_e2ee_router
app.include_router(chat_keys_router)
app.include_router(chat_e2ee_router)

# High-Security E2EE Router & Authenticated WebSocket (Olm v2 + MLS RFC 9420)
from e2ee_routes import router as high_sec_e2ee_router, ws_router as high_sec_ws_router
app.include_router(high_sec_e2ee_router)
app.include_router(high_sec_ws_router)

# Unified Chat Platform Router & Open Public Chat WebSocket
from platform_routes import router as platform_router, public_ws_router
app.include_router(platform_router)
app.include_router(public_ws_router)


# =============================================================
# SECURITY HEADERS & METADATA-MINIMIZED DIAGNOSTICS MIDDLEWARE
# =============================================================

_SENSITIVE_LOG_PATTERNS = re.compile(
    r"(private_key|seed_phrase|mnemonic|pickle_key|zys_[A-Za-z0-9_\-]+|0x[a-fA-F0-9]{64,})",
    re.IGNORECASE,
)


def _scrub_sensitive_text(text: Any) -> str:
    raw = str(text or "")
    return _SENSITIVE_LOG_PATTERNS.sub("[REDACTED]", raw)


def _apply_security_headers(request: Request, response: Any) -> None:
    response.headers.setdefault(
        "Content-Security-Policy",
        (
            "default-src 'self'; "
            "script-src 'self' 'wasm-unsafe-eval'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob: https:; "
            "connect-src 'self' https: wss: http://localhost:* ws://localhost:* http://127.0.0.1:* ws://127.0.0.1:*; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
        ),
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    )
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )


def _is_pool_busy_error(exc: BaseException) -> bool:
    try:
        import psycopg2.pool
        return isinstance(exc, psycopg2.pool.PoolError)
    except Exception:
        return False


def _is_db_connection_error(exc: BaseException) -> bool:
    """True for dropped / unreachable database connections (e.g. Neon idle disconnect)."""
    try:
        import psycopg2
        if isinstance(exc, (psycopg2.OperationalError, psycopg2.InterfaceError)):
            return True
        if isinstance(exc, psycopg2.pool.PoolError):
            return True
    except Exception:
        pass
    return False


@app.middleware("http")
async def detailed_request_logger(request: Request, call_next):
    start_time = time.perf_counter()
    method = request.method
    path = request.url.path

    # Enforce request size limits to prevent oversized payload abuse
    cl = request.headers.get("content-length")
    if cl and path.startswith("/api/chat/"):
        try:
            if int(cl) > 131072:  # 128 KB limit for encrypted chat payloads
                resp = JSONResponse(
                    status_code=413,
                    content={
                        "error": "Payload Too Large",
                        "status_code": 413,
                        "detail": "Encrypted message payload exceeds maximum size limit (128 KB)",
                        "path": path,
                        "timestamp": _now_iso(),
                    },
                )
                _apply_security_headers(request, resp)
                return resp
        except ValueError:
            pass

    try:
        response = await call_next(request)
        _apply_security_headers(request, response)
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = response.status_code
        ts = datetime.now(timezone.utc).strftime("%H:%M")
        # Metadata minimization: omit client IP/port and raw query strings from logs
        print(f"[{ts}Z] {method:<6} {path:<40} -> HTTP {status_code} ({duration_ms:5.1f}ms)")
        return response
    except Exception as exc:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        ts = datetime.now(timezone.utc).strftime("%H:%M")
        import logging
        if _is_db_connection_error(exc):
            # Database connection dropped (Neon idle timeout / compute wake-up).
            # Flush the pool so the next call opens fresh connections, and answer
            # 503 + Retry-After so the frontend retries automatically instead of
            # showing "Failed to fetch". A busy pool (PoolError) is not a dropped
            # connection: leave the healthy connections alone.
            purged = 0 if _is_pool_busy_error(exc) else chat_db.purge_idle_connections()
            logging.getLogger("app").warning(
                "Database connection dropped on %s %s (%s); purged %d idle connection(s)",
                method, path, type(exc).__name__, purged,
            )
            err_resp = JSONResponse(
                status_code=503,
                headers={"Retry-After": "1"},
                content={
                    "error": "Service Temporarily Unavailable",
                    "detail": "Database connection was refreshed. Please retry.",
                    "retryable": True,
                    "path": path,
                    "timestamp": _now_iso(),
                },
            )
        else:
            logging.getLogger("app").error("Unhandled exception processing %s %s: %s", method, path, exc, exc_info=True)
            err_resp = JSONResponse(
                status_code=500,
                content={
                    "error": "Internal Server Error",
                    "detail": "An unexpected internal server error occurred.",
                    "path": path,
                    "timestamp": _now_iso(),
                },
            )
        _apply_security_headers(request, err_resp)
        return err_resp


# Register CORSMiddleware last so it is outermost and applies CORS headers to 413/500 responses too.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_origin_regex=_LOCAL_DEV_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-Token", "X-Wallet-Address"],
)


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    safe_detail = exc.detail if isinstance(exc.detail, dict) else _scrub_sensitive_text(exc.detail)
    resp = JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "Not Found" if exc.status_code == 404 else f"HTTP {exc.status_code}",
            "status_code": exc.status_code,
            "detail": safe_detail,
            "path": request.url.path,
            "timestamp": _now_iso(),
        },
    )
    _apply_security_headers(request, resp)
    return resp


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    err_msgs = []
    sanitized_errors = []
    for err in exc.errors():
        loc = " -> ".join(str(l) for l in err.get("loc", []))
        msg = _scrub_sensitive_text(f"{loc}: {err.get('msg')} ({err.get('type')})")
        err_msgs.append(msg)
        # Never echo raw `input` payloads back into logs or error bodies
        sanitized_errors.append({
            "loc": err.get("loc", []),
            "msg": _scrub_sensitive_text(err.get("msg")),
            "type": err.get("type"),
        })
    resp = JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "status_code": 422,
            "detail": sanitized_errors,
            "summary": err_msgs,
            "path": request.url.path,
            "timestamp": _now_iso(),
        },
    )
    _apply_security_headers(request, resp)
    return resp


# =============================================================
# HEALTH & PLATFORM METADATA ROUTES
# =============================================================

_RPC_HEALTH_TTL_SECS = 30.0
_rpc_health_cache: dict = {"at": 0.0, "value": None}
_rpc_health_lock = threading.Lock()


def _cached_rpc_health() -> dict:
    """RPC probes make live network calls (1-3 s). Cache them so /api/health stays instant."""
    now = time.monotonic()
    cached = _rpc_health_cache["value"]
    if cached is not None and now - _rpc_health_cache["at"] < _RPC_HEALTH_TTL_SECS:
        return cached
    with _rpc_health_lock:
        now = time.monotonic()
        cached = _rpc_health_cache["value"]
        if cached is not None and now - _rpc_health_cache["at"] < _RPC_HEALTH_TTL_SECS:
            return cached
        value = eth_rpc.get_rpc_health_status()
        _rpc_health_cache["value"] = value
        _rpc_health_cache["at"] = time.monotonic()
        return value


@app.get("/api/health")
@app.get("/health")
def health_check(deep: bool = False):
    """Liveness probe. `?deep=1` also touches the database, which wakes a suspended
    Neon compute and refreshes pooled connections (the frontend does this once on load)."""
    is_pg = bool(chat_db._pg_pool is not None and not chat_db._use_sqlite_fallback)
    payload = {
        "status": "healthy",
        "timestamp": _now_iso(),
        "service": "zyphra-chat-platform",
        "storage": "postgresql" if is_pg else "sqlite_fallback",
        "networks": _cached_rpc_health(),
    }
    if deep:
        payload["database"] = "ok" if chat_db.ping_pg_health() else "unavailable"
    return payload


# =============================================================
# UNIFIED ENTRYPOINT (`python app.py` / `python App.py`)
# =============================================================

def main():
    """Unified single-command backend entrypoint.

    Automatically:
    1. Checks and installs any missing dependencies from requirements.txt
    2. Runs all database migrations on Neon PostgreSQL (or SQLite fallback) & seeds default settings
    3. Starts the FastAPI + WebSockets server via Uvicorn on port 10000
    """
    _ensure_backend_dependencies()

    backend_dir = os.path.dirname(os.path.abspath(__file__))
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    print("=" * 65)
    print("  ZYPHRA CHAT PLATFORM — UNIFIED BACKEND SERVER")
    print("=" * 65)
    print("[1/2] Checking & applying database migrations (Neon PostgreSQL)...")
    try:
        from run_migrations import run_all_migrations
        run_all_migrations()
    except Exception as exc:
        print(f"[WARN] Migration execution note: {exc}")

    port = int(os.getenv("PORT", "10000"))
    print(f"[2/2] Starting FastAPI & WebSockets server on http://127.0.0.1:{port} (0.0.0.0)...")
    print(f"      Health Check: http://localhost:{port}/api/health")
    print("      Press Ctrl+C to stop the server.")
    print("=" * 65)

    import uvicorn
    reload_flag = os.getenv("ENV", "development").lower() == "development"
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=reload_flag)


if __name__ == "__main__":
    main()