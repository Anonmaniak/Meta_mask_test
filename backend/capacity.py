"""
Capacity planning: how many people can be online at once on THIS server?

The realtime part of Zyphra lives inside one Python process (it can use one CPU core), and every
online person holds up to three live connections. So the safe number of online users depends on the
CPU share and the memory the hosting plan gives the process. This module reads those limits from the
container (Render, Docker, Kubernetes all expose them through cgroups) and turns them into a user cap.
When the plan is upgraded, the next restart reads the bigger limits and raises the cap by itself:
no code change is needed.

Override at any time (no code change) with the environment variable:
    MAX_ONLINE_USERS=500        # fixed cap
    MAX_ONLINE_USERS=0          # no cap (not recommended)

Tuning constants below come from load tests of this code (see the capacity notes).
"""

import os
from typing import Any, Dict, Optional

# --- measured / chosen constants -------------------------------------------------------------
PER_USER_MEM_KB = int(os.getenv("CAP_PER_USER_MEM_KB", "600"))      # 3 live connections per user, measured
BASE_MEM_MB = int(os.getenv("CAP_BASE_MEM_MB", "150"))               # app + libraries + headroom
USERS_PER_CPU = int(os.getenv("CAP_USERS_PER_CPU", "2000"))          # online users one full core can serve
UNDETECTED_DEFAULT = int(os.getenv("CAP_UNDETECTED_DEFAULT", "300")) # when limits cannot be read
MIN_CAP = 50
MAX_CPU_USED = 1.0  # one Python process uses at most one core, however many the plan has

_cache: Optional[Dict[str, Any]] = None


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None


def read_cpu_quota() -> Optional[float]:
    """CPU cores the container may use (0.1 = a tenth of a core), or None if unlimited / unknown."""
    v2 = _read("/sys/fs/cgroup/cpu.max")
    if v2:
        parts = v2.split()
        if parts and parts[0] != "max" and len(parts) == 2:
            try:
                return float(parts[0]) / float(parts[1])
            except (ValueError, ZeroDivisionError):
                pass
        elif parts and parts[0] == "max":
            return None
    quota = _read("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
    period = _read("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    if quota and period:
        try:
            q, p = float(quota), float(period)
            if q > 0 and p > 0:
                return q / p
        except ValueError:
            pass
    return None


def read_memory_limit_mb() -> Optional[float]:
    """Memory limit of the container in MB, or None if unlimited / unknown."""
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        raw = _read(path)
        if not raw or raw == "max":
            continue
        try:
            val = float(raw)
        except ValueError:
            continue
        if val <= 0 or val > 1 << 50:  # "unlimited" shows up as a huge number
            continue
        return val / (1024 * 1024)
    return None


def compute_capacity(cpu_quota: Optional[float], mem_limit_mb: Optional[float], env_override: Optional[str] = None) -> Dict[str, Any]:
    """Pure function: limits in, user cap out (easy to test)."""
    if env_override not in (None, ""):
        try:
            n = int(env_override)  # type: ignore[arg-type]
            if n <= 0:
                return {"max_online_users": 0, "source": "MAX_ONLINE_USERS=0 (no cap)", "enforced": False}
            return {"max_online_users": n, "source": "MAX_ONLINE_USERS environment variable", "enforced": True}
        except ValueError:
            pass

    if cpu_quota is None and mem_limit_mb is None:
        return {
            "max_online_users": UNDETECTED_DEFAULT,
            "source": "limits not detected: using safe default. Set MAX_ONLINE_USERS to your plan's size",
            "enforced": True,
        }

    by_cpu = int(USERS_PER_CPU * min(cpu_quota if cpu_quota is not None else MAX_CPU_USED, MAX_CPU_USED))
    by_mem = (
        int((mem_limit_mb - BASE_MEM_MB) * 1024 / PER_USER_MEM_KB) if mem_limit_mb is not None else by_cpu
    )
    cap = max(MIN_CAP, min(by_cpu, by_mem))
    limiter = "CPU" if by_cpu <= by_mem else "memory"
    return {"max_online_users": cap, "source": f"detected from container limits (limited by {limiter})", "enforced": True}


def get_capacity(refresh: bool = False) -> Dict[str, Any]:
    """Capacity for this server, computed once per process start (a plan change restarts the service)."""
    global _cache
    if _cache is not None and not refresh:
        return _cache
    cpu = read_cpu_quota()
    mem = read_memory_limit_mb()
    result = compute_capacity(cpu, mem, os.getenv("MAX_ONLINE_USERS"))
    result["detected_cpu_cores"] = round(cpu, 3) if cpu is not None else None
    result["detected_memory_mb"] = round(mem) if mem is not None else None
    _cache = result
    return result


def default_pool_max() -> int:
    """Database connections to keep: a bigger server (1000+ online users) gets more, so saving
    messages keeps up. Neon allows ~100 direct connections, so 20 is safe for one server.
    Override with DB_POOL_MAX."""
    return 20 if max_online_users() >= 1000 or max_online_users() == 0 else 10


def max_online_users() -> int:
    """0 means 'no cap'."""
    cap = get_capacity()
    return int(cap["max_online_users"]) if cap.get("enforced") else 0
