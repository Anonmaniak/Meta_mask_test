"""
Capacity check: simulates N signed-in members, each polling the server the way the app does
(sidebar + account lookups every 4.5 s), against a REAL running server, and prints how it coped.

    python loadtest_polling.py            # 100 members, 30 seconds
    USERS=300 SECONDS=60 python loadtest_polling.py

SAFE BY DESIGN: it never touches your real database.
  - the server is started from a TEMPORARY COPY of the code with no .env file (your .env is loaded with
    override=True, so running inside the real folder could have reached your live database);
  - the temporary server uses an in-memory SQLite database (TESTING=1);
  - before any load is sent it asks /api/health and aborts unless storage is "sqlite_fallback".

What the numbers mean: this measures the Python app's own cost (CPU per request, speed, memory) with a
local database. It does NOT include network distance to your real database (Neon) or your hosting
plan's CPU share. See SCALING.md ("Measured: 100 members polling") for how to read it.
"""
import asyncio
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import httpx  # noqa: E402
import psutil  # noqa: E402
from eth_account import Account  # noqa: E402
from eth_account.messages import encode_defunct  # noqa: E402

USERS = int(os.environ.get("USERS", "100"))
SECONDS = int(os.environ.get("SECONDS", "30"))
POLL_EVERY = 4.5  # seconds: the app's own polling interval (Chat.tsx)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    try:
        from test_e2ee_security import generate_signed_test_device
    except Exception as exc:  # pragma: no cover
        print("Run this from the backend folder (needs test_e2ee_security.py):", exc)
        return 2

    tmp = tempfile.mkdtemp(prefix="zyphra_loadtest_")
    for name in os.listdir(HERE):
        if name.endswith(".py") and not name.startswith("test_"):
            shutil.copy(os.path.join(HERE, name), tmp)
    shutil.copytree(os.path.join(HERE, "migrations"), os.path.join(tmp, "migrations"))
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    env.update({"TESTING": "1", "NEON_DATABASE_URL": "", "DATABASE_URL": "", "POSTGRES_URL": ""})
    srv = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app:app", "--port", str(port), "--no-access-log", "--log-level", "warning"],
        cwd=tmp, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,  # never PIPE: an unread pipe blocks the server
    )
    try:
        health = None
        for _ in range(120):
            try:
                r = httpx.get(base + "/api/health", timeout=2)
                if r.status_code == 200:
                    health = r.json()
                    break
            except Exception:
                time.sleep(0.5)
        if not health:
            print("The test server did not start.")
            return 1
        if health.get("storage") != "sqlite_fallback":
            print("ABORTED: the test server is not using the temporary in-memory database. Nothing was sent.")
            return 1
        print(f"Temporary server up (in-memory database). Signing in {USERS} test members...")

        sessions = []
        with httpx.Client(base_url=base, timeout=30) as c:
            for i in range(USERS):
                acc = Account.create()
                ch = c.post("/api/e2ee/auth/challenge", json={"wallet_address": acc.address}).json()
                sig = acc.sign_message(encode_defunct(text=ch["message"])).signature.hex()
                v = c.post("/api/e2ee/auth/verify", json={"challenge_id": ch["challenge_id"], "wallet_address": acc.address, "signature": sig}).json()
                h = {"Authorization": f"Bearer {v['session_token']}"}
                dev = f"dev_lt_{i:04d}_{random.randrange(10**8):08d}"
                bundle, _ = generate_signed_test_device(v["user"]["user_id"], dev)
                c.post("/api/e2ee/devices/register", json=bundle, headers=h)
                sessions.append((h, dev))

        lat, cnt = [], {"err": 0, "bad": 0}

        async def member(h, dev, client, stop):
            await asyncio.sleep(random.random() * POLL_EVERY)  # members are not in lock-step
            paths = ["/api/e2ee/dm/conversations", "/api/e2ee/groups", f"/api/e2ee/groups/welcomes?device_id={dev}", "/api/e2ee/me"]
            while time.monotonic() < stop:
                for p in paths:
                    t = time.perf_counter()
                    try:
                        r = await client.get(p, headers=h)
                        if r.status_code >= 400:
                            cnt["bad"] += 1
                    except Exception:
                        cnt["err"] += 1
                    lat.append((time.perf_counter() - t) * 1000)
                await asyncio.sleep(POLL_EVERY)

        async def run():
            async with httpx.AsyncClient(base_url=base, timeout=30, limits=httpx.Limits(max_connections=max(200, USERS * 2))) as client:
                stop = time.monotonic() + SECONDS
                await asyncio.gather(*[member(h, d, client, stop) for h, d in sessions])

        proc = psutil.Process(srv.pid)
        cpu0 = sum(proc.cpu_times()[:2])
        t0 = time.monotonic()
        idle_mb = proc.memory_info().rss / 1e6
        asyncio.run(run())
        wall = time.monotonic() - t0
        cpu = sum(proc.cpu_times()[:2]) - cpu0
        lat.sort()
        n = len(lat)
        q = lambda f: lat[min(n - 1, int(n * f))]
        print()
        print(f"{USERS} members, {SECONDS} s: {n} requests ({n / wall:.0f} per second), {cnt['err']} failed, {cnt['bad']} error replies")
        print(f"Response time (ms): median {q(.5):.0f}, 95th percentile {q(.95):.0f}, 99th {q(.99):.0f}, slowest {lat[-1]:.0f}")
        print(f"Server CPU: {cpu:.1f} s over {wall:.0f} s = {100 * cpu / wall:.0f}% of one core ({1000 * cpu / n:.1f} ms of CPU per request)")
        print(f"Server memory: {proc.memory_info().rss / 1e6:.0f} MB (idle {idle_mb:.0f} MB)")
        return 0 if cnt["err"] == 0 and cnt["bad"] == 0 else 1
    finally:
        srv.terminate()
        try:
            srv.wait(8)
        except Exception:
            srv.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
