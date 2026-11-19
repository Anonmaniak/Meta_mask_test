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

    token = (os.getenv("ADMIN_TOKEN") or "").strip()
    if token and len(token) < 24:
        warnings.append("ADMIN_TOKEN is shorter than 24 characters, so it is ignored. Use a long random value or unset it.")

    return warnings


def log_security_report() -> List[str]:
    warnings = collect_warnings()
    if not warnings:
        print("[SECURITY] Startup self-check passed.")
    for w in warnings:
        print(f"[SECURITY][WARN] {w}")
    return warnings