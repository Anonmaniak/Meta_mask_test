"""
Startup security self-check.

Runs once when the server boots and prints clear `[SECURITY]` warnings to the server log for things that are
easy to get wrong and dangerous to leave: weak admin credentials, secrets this application never uses (they
only add risk if the environment ever leaks), and an ignored short break-glass token.

It only reports NAMES and reasons - it never prints a secret value.
"""

import os
import re
from typing import List

import admin_auth

# Secrets that older versions of this project used. The current application never reads them, so having them in
# the environment can only hurt (anyone who sees the environment gets a wallet key / database login for nothing).
_UNUSED_SECRET_NAMES = ("MONGO_URL", "MONGODB_URI", "MONGO_URI")
_PRIVATE_KEY_NAME = re.compile(r"(^|_)PRIVATE_KEY$", re.IGNORECASE)

# Settings that now live ONLY in the Admin console (/Admin456) and the database. Environment values are ignored.
_ADMIN_CONSOLE_ONLY_VARS = ("EXPECTED_CHAIN_ID", "AUTHORIZED_PAYMENT_DESTINATION", "PLATFORM_ENTRY_FEE_USD")


def collect_warnings() -> List[str]:
    warnings: List[str] = []

    raw_id = (os.getenv("ADMIN_LOGIN_ID") or "").strip()
    raw_pw = os.getenv("ADMIN_LOGIN_PASSWORD") or ""
    if raw_id or raw_pw:
        problems = admin_auth.credential_problems()
        if problems:
            warnings.append(
                "Admin login is DISABLED because the configured credentials are too weak: "
                + "; ".join(problems)
                + ". Run `python generate_admin_credentials.py` and set the new values."
            )

    for name in sorted(os.environ):
        if _PRIVATE_KEY_NAME.search(name) and (os.environ.get(name) or "").strip():
            warnings.append(
                f"{name} is set but this application never uses a wallet private key. "
                "Remove it from the environment and treat that key as exposed."
            )
    for name in _UNUSED_SECRET_NAMES:
        if (os.environ.get(name) or "").strip():
            warnings.append(
                f"{name} is set but this application does not use MongoDB. "
                "Remove it and revoke that database login."
            )

    for name in _ADMIN_CONSOLE_ONLY_VARS:
        if (os.environ.get(name) or "").strip():
            warnings.append(
                f"{name} is set but is IGNORED: this setting is now managed only in the Admin console (/Admin456). "
                "Remove it from the environment so nobody thinks it has an effect."
            )

    token = (os.getenv("ADMIN_TOKEN") or "").strip()
    if token and len(token) < 24:
        warnings.append("ADMIN_TOKEN is shorter than 24 characters, so it is ignored. Use a long random value or unset it.")

    if os.getenv("ENABLE_API_DOCS", "").strip().lower() in ("1", "true", "yes") and os.getenv("RENDER"):
        warnings.append("ENABLE_API_DOCS is on: /docs and /openapi.json publicly list every endpoint. Remove it on Render.")
    return warnings


def payment_config_notes() -> List[str]:
    """Reads the live Admin-console settings and reports anything that stops payments from working."""
    notes: List[str] = []
    try:
        import platform_db

        platform_db.ensure_platform_tables()
        if not platform_db.get_authorized_payment_destination():
            notes.append(
                "No payment destination wallet is set, so paid membership/groups cannot be paid. "
                "Open /Admin456 -> Platform Settings and set the Treasury Destination Address."
            )
        if platform_db.get_active_chain_id() == 11155111:
            notes.append("Active network is Sepolia (testnet). Switch to Ethereum Mainnet in /Admin456 when you go live.")
    except Exception as exc:  # never block startup
        notes.append(f"Could not read payment settings: {exc}")
    return notes


def log_security_report() -> List[str]:
    warnings = collect_warnings()
    for n in payment_config_notes():
        print(f"[CONFIG] {n}")
    if not warnings:
        print("[SECURITY] Startup self-check passed.")
    for w in warnings:
        print(f"[SECURITY][WARN] {w}")
    return warnings