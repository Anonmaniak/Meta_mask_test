"""
Read-Only Ethereum RPC Balance Verification Service (Mainnet & Sepolia).

Security Guarantees:
- Zero server-side private keys (no signing or escrow wallet on backend).
- Never trusts browser-reported wallet balances for level qualification or group gates.
- Queries authoritative on-chain `eth_getBalance` + `eth_blockNumber` via Web3 HTTPProvider
  with automatic Mainnet fallback and clean timeout/error handling.
"""

import os
import re
import sys
import threading
import time
from typing import Optional, Dict, Any, List, Tuple
from web3 import Web3


def is_test_environment() -> bool:
    """Single source of truth for "are we running under a test runner?".

    Covers pytest, unittest and the explicit TESTING=1 switch so every module
    (app.py, lifespan, RPC helpers) agrees on when to skip live network calls.
    """
    return (
        os.getenv("TESTING") == "1"
        or "pytest" in sys.modules
        or "unittest" in sys.modules
    )


class EthereumRpcUnavailableError(RuntimeError):
    """Raised when no configured Ethereum RPC endpoint can serve a balance query."""


def _init_provider(url: Optional[str]) -> Optional[Web3]:
    if is_test_environment():
        return None
    cleaned = (url or "").strip()
    if not cleaned:
        return None
    return Web3(Web3.HTTPProvider(cleaned, request_kwargs={"timeout": 10}))


def _providers() -> Dict[str, Optional[Web3]]:
    return {
        "mainnet_primary": _init_provider(os.getenv("RPC_URL_MAINNET")),
        "mainnet_fallback": _init_provider(os.getenv("RPC_URL_MAINNET_FALLBACK")),
        "sepolia": _init_provider(os.getenv("RPC_URL_SEPOLIA")),
        "legacy": _init_provider(os.getenv("RPC_URL")),
    }


def get_w3_with_source(target_chain_id: int = 1) -> Tuple[Web3, str]:
    """
    Returns `(w3, rpc_source_label)` for the requested EVM `target_chain_id`.
    Supports Ethereum Mainnet (1) with automatic fallback and Sepolia Testnet (11155111).
    """
    cid = int(target_chain_id or 1)
    provs = _providers()

    if cid == 1:
        candidates = [
            ("mainnet_primary", provs["mainnet_primary"]),
            ("mainnet_fallback", provs["mainnet_fallback"]),
            ("legacy_rpc", provs["legacy"]),
        ]
    elif cid == 11155111:
        candidates = [
            ("sepolia_rpc", provs["sepolia"]),
            ("legacy_rpc", provs["legacy"]),
        ]
    else:
        candidates = [
            ("legacy_rpc", provs["legacy"]),
            ("mainnet_primary", provs["mainnet_primary"]),
            ("sepolia_rpc", provs["sepolia"]),
        ]

    last_err: Optional[Exception] = None
    for source_name, w3 in candidates:
        if w3 is None:
            continue
        try:
            if w3.is_connected():
                return w3, source_name
        except Exception as exc:
            last_err = exc

    detail = f" ({last_err})" if last_err else ""
    raise EthereumRpcUnavailableError(
        f"No active Ethereum RPC provider available for chain_id={cid}{detail}"
    )


def get_w3(target_chain_id: int = 1) -> Web3:
    w3, _ = get_w3_with_source(target_chain_id)
    return w3


def verify_onchain_eth_balance(wallet_address: str, chain_id: int = 1) -> Dict[str, Any]:
    """
    Queries the authoritative Ethereum RPC node for `wallet_address` on `chain_id`.
    Returns checksummed address, `balance_wei`, `balance_eth`, `block_number`, and `rpc_source`.
    """
    if not Web3.is_address(wallet_address):
        raise ValueError("Invalid Ethereum wallet address")

    checksum_addr = Web3.to_checksum_address(wallet_address)
    cid = int(chain_id or 1)
    w3, rpc_source = get_w3_with_source(cid)

    try:
        block_number = int(w3.eth.block_number)
        balance_wei = int(w3.eth.get_balance(checksum_addr, block_identifier=block_number))
    except Exception as exc:
        # Fallback to 'latest' tag if archival/specific block_identifier is restricted on free tier
        try:
            block_number = int(w3.eth.block_number)
            balance_wei = int(w3.eth.get_balance(checksum_addr))
        except Exception as inner_exc:
            raise EthereumRpcUnavailableError(
                f"Failed to query on-chain balance on chain {cid}: {inner_exc}"
            ) from exc

    balance_eth = str(Web3.from_wei(balance_wei, "ether"))
    return {
        "wallet_address": checksum_addr,
        "chain_id": cid,
        "balance_wei": str(balance_wei),
        "balance_wei_int": balance_wei,
        "balance_eth": balance_eth,
        "block_number": block_number,
        "rpc_source": rpc_source,
    }


def get_rpc_health_status() -> Dict[str, Any]:
    """Live probe of every configured RPC (slow: up to 10 s per provider). Prefer the
    cached variant below from request handlers."""
    if is_test_environment():
        return {
            "mainnet": {"configured": True, "connected": True},
            "sepolia": {"configured": True, "connected": True},
        }

    provs = _providers()
    mainnet_configured = bool(
        provs["mainnet_primary"] or provs["mainnet_fallback"] or provs["legacy"]
    )
    sepolia_configured = bool(provs["sepolia"] or provs["legacy"])

    mainnet_connected = False
    sepolia_connected = False
    if mainnet_configured:
        try:
            mainnet_connected = get_w3(1).is_connected()
        except Exception:
            mainnet_connected = False
    if sepolia_configured:
        try:
            sepolia_connected = get_w3(11155111).is_connected()
        except Exception:
            sepolia_connected = False

    return {
        "mainnet": {
            "configured": mainnet_configured,
            "connected": mainnet_connected,
        },
        "sepolia": {
            "configured": sepolia_configured,
            "connected": sepolia_connected,
        },
    }


# ---------------------------------------------------------------------------
# Cached health (stale-while-revalidate) so polled endpoints never block on RPC.
# ---------------------------------------------------------------------------
RPC_HEALTH_TTL_SECS = 30.0
_rpc_health_cache: Dict[str, Any] = {"at": 0.0, "value": None}
_rpc_health_lock = threading.Lock()
_rpc_health_refreshing = threading.Event()


def _refresh_rpc_health() -> Dict[str, Any]:
    try:
        value = get_rpc_health_status()
        with _rpc_health_lock:
            _rpc_health_cache["value"] = value
            _rpc_health_cache["at"] = time.monotonic()
        return value
    finally:
        _rpc_health_refreshing.clear()


def _configured_only_status() -> Dict[str, Any]:
    """Cheap placeholder used before the first probe finishes (no network I/O)."""
    if is_test_environment():
        return get_rpc_health_status()
    mainnet_configured = bool(
        (os.getenv("RPC_URL_MAINNET") or "").strip()
        or (os.getenv("RPC_URL_MAINNET_FALLBACK") or "").strip()
        or (os.getenv("RPC_URL") or "").strip()
    )
    sepolia_configured = bool(
        (os.getenv("RPC_URL_SEPOLIA") or "").strip() or (os.getenv("RPC_URL") or "").strip()
    )
    return {
        "mainnet": {"configured": mainnet_configured, "connected": False, "checking": True},
        "sepolia": {"configured": sepolia_configured, "connected": False, "checking": True},
    }


def get_cached_rpc_health_status(block_if_empty: bool = False) -> Dict[str, Any]:
    """Returns the last RPC health result, refreshing it in the background once it is older
    than RPC_HEALTH_TTL_SECS. Never blocks on the network unless `block_if_empty` is True and
    there is no result yet."""
    if is_test_environment():
        return get_rpc_health_status()

    # Read the cache and claim the single "refresher" slot atomically, so two requests arriving at
    # the same instant can never both start a probe.
    with _rpc_health_lock:
        cached = _rpc_health_cache["value"]
        age = time.monotonic() - _rpc_health_cache["at"]
        if cached is not None and age < RPC_HEALTH_TTL_SECS:
            return cached
        claimed = not _rpc_health_refreshing.is_set()
        if claimed:
            _rpc_health_refreshing.set()

    if claimed and cached is None and block_if_empty:
        return _refresh_rpc_health()
    if claimed:
        # Stale or empty: one background refresh, answer immediately.
        threading.Thread(target=_refresh_rpc_health, name="rpc-health-refresh", daemon=True).start()
    return cached if cached is not None else _configured_only_status()


def peek_rpc_health_status() -> Dict[str, Any]:
    """Last known RPC health WITHOUT any network call or refresh. For endpoints that every visitor
    polls (/api/health): reporting status must not cost an RPC request. The admin dashboard
    (get_cached_rpc_health_status) and startup are what actually probe."""
    if is_test_environment():
        return get_rpc_health_status()
    with _rpc_health_lock:
        cached = _rpc_health_cache["value"]
    return cached if cached is not None else _configured_only_status()


def verify_onchain_payment_transaction(
    tx_hash: str,
    chain_id: int = 1,
    expected_sender: Optional[str] = None,
    expected_recipient: Optional[str] = None,
    allowed_chain_ids: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """
    Authoritatively queries the configured Ethereum RPC node to verify a transaction.
    Returns authoritative payment verification details without trusting client input.

    Enforces all of:
    - on-chain transaction success (status == 1),
    - sender matches expected authenticated user wallet,
    - recipient matches server-controlled authorized payment destination,
    - network chain_id is among allowed chains.
    Fails closed if the expected authorized recipient is missing or invalid.
    """
    raw_hash = (tx_hash or "").strip()
    if not re.match(r"^0x[a-fA-F0-9]{64}$", raw_hash):
        raise ValueError("Invalid Ethereum transaction hash format (expected 0x followed by 64 hex characters)")

    # Fail closed if authorized recipient destination is missing or invalid
    if not expected_recipient or not Web3.is_address(expected_recipient):
        raise ValueError("Authorized payment destination is missing or invalid; verification rejected.")
    norm_expected_recipient = Web3.to_checksum_address(expected_recipient)

    norm_expected_sender: Optional[str] = None
    if expected_sender:
        if not Web3.is_address(expected_sender):
            raise ValueError(f"Invalid expected sender wallet address: {expected_sender}")
        norm_expected_sender = Web3.to_checksum_address(expected_sender)

    cid = int(chain_id or 1)
    allowed = list(allowed_chain_ids) if allowed_chain_ids is not None else [1, 11155111]
    if cid not in allowed:
        return {
            "verified": False,
            "status": "failed",
            "reason": f"Transaction chain {cid} is not an allowed payment network (allowed: {allowed})",
            "transaction_reference": raw_hash,
            "chain_id": cid,
            "verification_source": "ethereum_rpc",
        }

    w3, rpc_source = get_w3_with_source(cid)

    try:
        # Check receipt first for confirmation and status
        receipt = None
        try:
            receipt = w3.eth.get_transaction_receipt(raw_hash)
        except Exception:
            receipt = None

        if receipt is None:
            tx = None
            try:
                tx = w3.eth.get_transaction(raw_hash)
            except Exception:
                tx = None

            if tx is None:
                return {
                    "verified": False,
                    "status": "pending",
                    "reason": "Transaction not found or not yet propagated",
                    "transaction_reference": raw_hash,
                    "chain_id": cid,
                    "verification_source": rpc_source,
                }

            sender = Web3.to_checksum_address(tx["from"]) if tx.get("from") else None
            recipient = Web3.to_checksum_address(tx["to"]) if tx.get("to") else None
            val_wei = int(tx.get("value", 0))

            # Early check even when pending: if sender or recipient mismatch, fail immediately
            if norm_expected_sender and sender and sender.lower() != norm_expected_sender.lower():
                return {
                    "verified": False,
                    "status": "failed",
                    "reason": f"Sender mismatch (expected {norm_expected_sender}, found {sender})",
                    "transaction_reference": raw_hash,
                    "wallet_address": sender,
                    "recipient_address": recipient,
                    "chain_id": cid,
                    "verification_source": rpc_source,
                }
            # A contract-creation tx (to=None) can never pay the authorized destination, so it
            # fails immediately too, exactly like the mined-path check below.
            if not recipient or recipient.lower() != norm_expected_recipient.lower():
                return {
                    "verified": False,
                    "status": "failed",
                    "reason": f"Recipient mismatch (expected {norm_expected_recipient}, found {recipient})",
                    "transaction_reference": raw_hash,
                    "wallet_address": sender,
                    "recipient_address": recipient,
                    "chain_id": cid,
                    "verification_source": rpc_source,
                }

            return {
                "verified": False,
                "status": "pending",
                "reason": "Transaction pending confirmation on-chain",
                "transaction_reference": raw_hash,
                "wallet_address": sender,
                "recipient_address": recipient,
                "amount_atomic": str(val_wei),
                "amount_formatted": str(Web3.from_wei(val_wei, "ether")),
                "currency": "ETH",
                "network": "sepolia" if cid == 11155111 else "ethereum",
                "chain_id": cid,
                "verification_source": rpc_source,
            }

        status_code = int(receipt.get("status", 0))
        block_num = int(receipt.get("blockNumber", 0))

        tx = w3.eth.get_transaction(raw_hash)
        sender = Web3.to_checksum_address(tx["from"]) if tx.get("from") else None
        recipient = Web3.to_checksum_address(tx["to"]) if tx.get("to") else None
        val_wei = int(tx.get("value", 0))

        # 1. Verify sender
        if not sender or (norm_expected_sender and sender.lower() != norm_expected_sender.lower()):
            return {
                "verified": False,
                "status": "failed",
                "reason": f"Sender mismatch (expected {norm_expected_sender}, found {sender})",
                "transaction_reference": raw_hash,
                "wallet_address": sender,
                "recipient_address": recipient,
                "chain_id": cid,
                "block_number": block_num,
                "verification_source": rpc_source,
            }

        # 2. Verify recipient matches authorized destination
        if not recipient or recipient.lower() != norm_expected_recipient.lower():
            return {
                "verified": False,
                "status": "failed",
                "reason": f"Recipient mismatch (expected {norm_expected_recipient}, found {recipient})",
                "transaction_reference": raw_hash,
                "wallet_address": sender,
                "recipient_address": recipient,
                "chain_id": cid,
                "block_number": block_num,
                "verification_source": rpc_source,
            }

        # 3. Verify on-chain success
        if status_code == 0:
            return {
                "verified": False,
                "status": "failed",
                "reason": "Transaction reverted on-chain",
                "transaction_reference": raw_hash,
                "wallet_address": sender,
                "recipient_address": recipient,
                "chain_id": cid,
                "block_number": block_num,
                "verification_source": rpc_source,
            }

        network_name = "sepolia" if cid == 11155111 else "ethereum"
        return {
            "verified": True,
            "status": "verified",
            "wallet_address": sender,
            "recipient_address": recipient,
            "amount_atomic": str(val_wei),
            "amount_formatted": str(Web3.from_wei(val_wei, "ether")),
            "currency": "ETH",
            "network": network_name,
            "chain_id": cid,
            "block_number": block_num,
            "transaction_reference": raw_hash,
            "verification_source": rpc_source,
        }
    except EthereumRpcUnavailableError:
        raise
    except Exception as exc:
        raise EthereumRpcUnavailableError(f"RPC query error for transaction {raw_hash}: {exc}") from exc