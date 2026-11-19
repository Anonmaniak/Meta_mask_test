"""
Tiny in-process TTL cache for hot, read-mostly lookups on the chat send path.

Why this exists
---------------
Every authenticated request used to re-read the same rows from the database
(session -> user -> wallets -> profile -> admin role -> platform settings).
Against a remote Neon database each of those reads is a network round trip, so
one chat message cost ~9 sequential round trips.

The cryptographic verification (SIWE signature) still happens exactly ONCE, at
login. After that the session is just a database row. This module remembers the
result of looking that row up for a few seconds so the database is not asked the
same question for every single message.

Safety properties
-----------------
* Only SUCCESSFUL lookups are cached (a missing/invalid token is never cached).
* Entries expire after `AUTH_CACHE_TTL_SEC` (default 30 s, `0` disables caching).
* Every function that writes sessions, users, wallets, admin roles or platform
  settings is decorated with `@invalidates_auth_cache`, which clears the cache
  immediately after the write, so revoke / suspend / mute / role changes take
  effect right away inside this process.
* Cached values are deep-copied on the way in and out, so callers can never
  mutate shared state.
* Session expiry is re-checked on every cache hit by the caller.

Multi-process note: the cache is per process. With more than one worker or
instance, a change made on one instance is seen by the others within at most
`AUTH_CACHE_TTL_SEC` seconds.
"""

import copy
import functools
import os
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

_MAX_ENTRIES = 5000


def _ttl() -> float:
    try:
        return max(0.0, float(os.getenv("AUTH_CACHE_TTL_SEC", "30")))
    except ValueError:
        return 30.0


_lock = threading.Lock()
_local = threading.local()  # per-thread "inside a write" depth
# namespace -> key -> (expires_monotonic, value)
_store: Dict[str, Dict[str, Tuple[float, Any]]] = {}
_generation = 0


def _in_write() -> bool:
    return getattr(_local, "depth", 0) > 0


def get(namespace: str, key: str) -> Optional[Any]:
    # Inside a write function, always read fresh data (never a pre-write cached copy).
    if _ttl() <= 0 or _in_write():
        return None
    now = time.monotonic()
    with _lock:
        entry = _store.get(namespace, {}).get(key)
        if not entry:
            return None
        if entry[0] <= now:
            _store[namespace].pop(key, None)
            return None
        return copy.deepcopy(entry[1])


def put(namespace: str, key: str, value: Any, generation: Optional[int] = None) -> None:
    """Store a value. If `generation` is given and the cache was invalidated since
    it was read (a concurrent write happened), the stale value is discarded."""
    ttl = _ttl()
    if ttl <= 0 or value is None or _in_write():
        return
    now = time.monotonic()
    with _lock:
        if generation is not None and generation != _generation:
            return
        bucket = _store.setdefault(namespace, {})
        if len(bucket) >= _MAX_ENTRIES:
            for k in [k for k, (exp, _) in bucket.items() if exp <= now]:
                bucket.pop(k, None)
            if len(bucket) >= _MAX_ENTRIES:
                bucket.clear()
        bucket[key] = (now + ttl, copy.deepcopy(value))


def generation() -> int:
    """Snapshot BEFORE reading from the database; pass to put() afterwards."""
    with _lock:
        return _generation


def invalidate_all() -> None:
    global _generation
    with _lock:
        _generation += 1
        _store.clear()


def invalidate(namespaces: Optional[Tuple[str, ...]] = None) -> None:
    """Clear only the named namespaces (or everything when None). The generation always
    advances, so any lookup that was in flight while a write happened is discarded."""
    global _generation
    with _lock:
        _generation += 1
        if namespaces is None:
            _store.clear()
        else:
            for ns in namespaces:
                _store.pop(ns, None)


def invalidates_auth_cache(func: Optional[Callable] = None, *, namespaces: Optional[Tuple[str, ...]] = None):
    """Decorator: clear cached reads right after (and even if) the wrapped write runs.

    Bare `@invalidates_auth_cache` clears everything (use for session/user/wallet writes).
    `@invalidates_auth_cache(namespaces=("group", ...))` clears only what that write can change,
    so e.g. creating a group does not throw away every user's cached session.
    """

    def deco(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            _local.depth = getattr(_local, "depth", 0) + 1
            try:
                return f(*args, **kwargs)
            finally:
                _local.depth -= 1
                invalidate(namespaces)

        return wrapper

    return deco(func) if callable(func) else deco


def make_key(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> str:
    """The cache key `read_cached` uses for a call - lets a batch loader pre-fill single lookups."""
    return repr((args, sorted(kwargs.items())))


def read_cached(namespace: str) -> Callable:
    """Decorator for a read-only lookup: serve a recent result from memory instead of the database.

    The cache key is built from the call arguments. `None` / empty-dict results are never cached
    (so "not found yet" can't hide a record created a moment later). Any function decorated with
    `@invalidates_auth_cache` clears every namespace right after it writes.
    """

    def deco(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = make_key(args, kwargs)
            hit = get(namespace, key)
            if hit is not None:
                return hit
            gen = generation()
            value = func(*args, **kwargs)
            if value is not None and value != {}:
                put(namespace, key, value, gen)
            return value

        return wrapper

    return deco