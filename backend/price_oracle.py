"""
ETH/USD price oracle used to convert the admin's USD membership price into ETH.

- Reads a live spot price from Coinbase, then Kraken as a second source.
- Caches the result for a short time so the pricing endpoint stays fast.
- If every live source fails, it keeps serving the last known good price for up to
  an hour, then falls back to the admin-configured fixed rate (`eth_usd_price`).
- Under tests (TESTING=1 / unittest) it never touches the network and always uses
  the fixed rate.
"""

import json
import os
import sys
import threading
import time
import urllib.request
from typing import Optional, Tuple

_CACHE_TTL_SECS = float(os.getenv("ETH_PRICE_CACHE_SECS", "60"))
_STALE_OK_SECS = float(os.getenv("ETH_PRICE_STALE_OK_SECS", "3600"))
_HTTP_TIMEOUT_SECS = 2.0
_RETRY_AFTER_FAILURE_SECS = 30.0  # after every source failed, don't hammer them / block requests
_MIN_SANE_USD = 50.0
_MAX_SANE_USD = 1_000_000.0

_lock = threading.Lock()
_cache = {"rate": None, "at": 0.0, "failed_at": -1e9}


def _is_test_env() -> bool:
    return os.getenv("TESTING") == "1" or "unittest" in sys.modules or "pytest" in sys.modules


def _http_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "zyphra-price-oracle/1.0"})
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SECS) as resp:  # nosec - fixed HTTPS URLs
        return json.loads(resp.read().decode("utf-8"))


def _from_coinbase() -> Optional[float]:
    data = _http_json("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    return float(data["data"]["amount"])


def _from_kraken() -> Optional[float]:
    data = _http_json("https://api.kraken.com/0/public/Ticker?pair=ETHUSD")
    result = data["result"]
    first = next(iter(result.values()))
    return float(first["c"][0])


def _fetch_live() -> Optional[float]:
    for source in (_from_coinbase, _from_kraken):
        try:
            rate = source()
            if rate is not None and _MIN_SANE_USD <= rate <= _MAX_SANE_USD:
                return rate
        except Exception:
            continue
    return None


def get_eth_usd_rate(fixed_fallback: float, use_live: bool = True) -> Tuple[float, str]:
    """Returns (usd_per_eth, source) where source is one of:
    'live', 'live_cached', 'live_stale', 'admin_fixed'."""
    fixed = float(fixed_fallback) if fixed_fallback and float(fixed_fallback) > 0 else 2500.0
    if not use_live or _is_test_env():
        return fixed, "admin_fixed"

    now = time.monotonic()
    rate, at = _cache["rate"], _cache["at"]
    if rate is not None and now - at < _CACHE_TTL_SECS:
        return rate, "live_cached"

    with _lock:
        now = time.monotonic()
        rate, at = _cache["rate"], _cache["at"]
        if rate is not None and now - at < _CACHE_TTL_SECS:
            return rate, "live_cached"
        if now - _cache["failed_at"] < _RETRY_AFTER_FAILURE_SECS:
            live = None
        else:
            live = _fetch_live()
            if live is None:
                _cache["failed_at"] = time.monotonic()
        if live is not None:
            _cache["rate"], _cache["at"] = live, time.monotonic()
            return live, "live"
        if rate is not None and now - at < _STALE_OK_SECS:
            return rate, "live_stale"
    return fixed, "admin_fixed"
