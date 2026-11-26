"""Tests for scaling: plan-based capacity, admission control, and the live-connection hub's cost."""

import asyncio
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient
from eth_account import Account
from eth_account.messages import encode_defunct
from starlette.websockets import WebSocketDisconnect

import capacity
import chat_db
import e2ee_db
import e2ee_routes
import platform_db
from app import app


class FakeWS:
    """Stands in for a WebSocket: records what the server sends."""
    def __init__(self):
        self.sent = []

    async def send_text(self, text):
        self.sent.append(text)

    async def send_json(self, data):  # must NOT be used for broadcasts any more
        raise AssertionError("broadcasts must be encoded once and sent with send_text")


class TestPlanCapacity(unittest.TestCase):
    """What the server sizes itself to on each Render plan (CPU cores, memory MB)."""

    def cap(self, cpu, mem):
        return capacity.compute_capacity(cpu, mem)["max_online_users"]

    def test_free_plan_covers_100_users(self):
        self.assertGreaterEqual(self.cap(0.1, 512), 100)
        self.assertEqual(self.cap(0.1, 512), 200)  # limited by CPU

    def test_starter_is_limited_by_memory(self):
        r = capacity.compute_capacity(0.5, 512)
        self.assertIn("memory", r["source"])
        self.assertTrue(500 < r["max_online_users"] < 1000)

    def test_standard_plan_reaches_2000(self):
        self.assertEqual(self.cap(1.0, 2048), 2000)

    def test_more_cores_do_not_raise_the_cap_for_a_single_process(self):
        self.assertEqual(self.cap(2.0, 4096), self.cap(1.0, 2048))
        self.assertEqual(self.cap(4.0, 8192), 2000)

    def test_upgrading_never_lowers_the_cap(self):
        plans = [(0.1, 512), (0.5, 512), (1.0, 2048), (2.0, 4096)]
        caps = [self.cap(c, m) for c, m in plans]
        self.assertEqual(caps, sorted(caps))

    def test_environment_override_and_undetected_default(self):
        self.assertEqual(capacity.compute_capacity(0.1, 512, "750")["max_online_users"], 750)
        r = capacity.compute_capacity(0.1, 512, "0")
        self.assertFalse(r["enforced"])
        und = capacity.compute_capacity(None, None)
        self.assertEqual(und["max_online_users"], capacity.UNDETECTED_DEFAULT)
        self.assertIn("MAX_ONLINE_USERS", und["source"])
        self.assertEqual(capacity.compute_capacity(0.1, 512, "not-a-number")["max_online_users"], 200)

    def test_reads_container_limits_cgroup_v2_and_v1(self):
        files = {"/sys/fs/cgroup/cpu.max": "10000 100000", "/sys/fs/cgroup/memory.max": "536870912"}
        with patch.object(capacity, "_read", side_effect=lambda p: files.get(p)):
            self.assertAlmostEqual(capacity.read_cpu_quota(), 0.1)
            self.assertAlmostEqual(capacity.read_memory_limit_mb(), 512.0)
        files = {"/sys/fs/cgroup/cpu.max": "max 100000", "/sys/fs/cgroup/memory.max": "max"}
        with patch.object(capacity, "_read", side_effect=lambda p: files.get(p)):
            self.assertIsNone(capacity.read_cpu_quota())
            self.assertIsNone(capacity.read_memory_limit_mb())
        v1 = {"/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "50000", "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000",
              "/sys/fs/cgroup/memory/memory.limit_in_bytes": "2147483648"}
        with patch.object(capacity, "_read", side_effect=lambda p: v1.get(p)):
            self.assertAlmostEqual(capacity.read_cpu_quota(), 0.5)
            self.assertAlmostEqual(capacity.read_memory_limit_mb(), 2048.0)
        huge = {"/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712"}  # "unlimited"
        with patch.object(capacity, "_read", side_effect=lambda p: huge.get(p)):
            self.assertIsNone(capacity.read_memory_limit_mb())


class TestPoolSizing(unittest.TestCase):
    def test_pool_grows_with_the_plan(self):
        with patch.object(capacity, "max_online_users", return_value=200):
            self.assertEqual(capacity.default_pool_max(), 10)   # Free
        with patch.object(capacity, "max_online_users", return_value=617):
            self.assertEqual(capacity.default_pool_max(), 10)   # Starter
        with patch.object(capacity, "max_online_users", return_value=2000):
            self.assertEqual(capacity.default_pool_max(), 20)   # Standard and up


class TestHubCost(unittest.TestCase):
    def setUp(self):
        self.hub = e2ee_routes.E2EERealtimeHub()

    def test_broadcast_encodes_once_and_sends_text(self):
        async def run():
            socks = [FakeWS() for _ in range(50)]
            for w in socks:
                self.hub.register_public(w, member_ident="user:u1")
            await self.hub.broadcast_public_event({"type": "public_message_created", "message": {"content": "héllo ✓"}})
            return socks
        socks = asyncio.run(run())
        texts = {w.sent[0] for w in socks}
        self.assertEqual(len(texts), 1)           # everyone got the identical, pre-encoded text
        self.assertIn("héllo ✓", texts.pop())     # unicode preserved

    def test_many_joins_are_merged_into_few_presence_updates(self):
        async def run():
            socks = [FakeWS() for _ in range(300)]  # above the instant-update limit
            for i, w in enumerate(socks):
                self.hub.register_public(w, member_ident=f"user:u{i}")
            with patch.object(e2ee_routes, "_PRESENCE_MIN_INTERVAL_SECS", 0.05):
                for _ in range(200):               # 200 joins/leaves in a burst
                    await self.hub.broadcast_public_presence()
                await asyncio.sleep(0.4)
            return socks
        socks = asyncio.run(run())
        most = max(len(w.sent) for w in socks)
        self.assertLessEqual(most, 4, f"expected a few merged updates, got {most} per socket")
        self.assertGreaterEqual(min(len(w.sent) for w in socks), 1)

    def test_small_servers_get_instant_presence_updates(self):
        async def run():
            w = FakeWS()
            self.hub.register_public(w, member_ident="user:u1")
            await self.hub.broadcast_public_presence()
            await asyncio.sleep(0.05)
            return w
        self.assertEqual(len(asyncio.run(run()).sent), 1)

    def test_online_counts_make_no_database_calls_and_hide_admins(self):
        boom = AssertionError("database must not be queried while counting online users")
        with patch.object(platform_db, "list_admin_user_ids", return_value={"adm1"}), \
             patch.object(platform_db, "get_admin_role", side_effect=boom), \
             patch.object(e2ee_db, "get_user_by_id", side_effect=boom), \
             patch.object(e2ee_db, "get_user_by_wallet", side_effect=boom):
            for i in range(400):  # above the cached-stats threshold too
                self.hub.register_public(FakeWS(), member_ident=f"user:u{i}")
            self.hub.register_public(FakeWS(), member_ident="user:adm1")
            for i in range(50):
                self.hub.register_member_presence(FakeWS(), f"user:u{i}")
            stats = self.hub.get_online_stats(True)
        self.assertEqual(stats["active_live"], 400)  # the admin is not counted

    def test_stats_are_cached_when_large(self):
        for i in range(400):
            self.hub.register_public(FakeWS(), member_ident=f"user:u{i}")
        with patch.object(self.hub, "_compute_online_stats", wraps=self.hub._compute_online_stats) as spy:
            for _ in range(100):
                self.hub.get_online_stats(True)
        self.assertEqual(spy.call_count, 1)


class TestAdmissionControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig = (chat_db._use_sqlite_fallback, chat_db._sqlite_conn,
                     e2ee_db._e2ee_tables_initialized, platform_db._platform_tables_initialized)
        chat_db._use_sqlite_fallback = True
        chat_db._sqlite_conn = None
        chat_db._init_sqlite_engine()
        e2ee_db._e2ee_tables_initialized = False
        platform_db._platform_tables_initialized = False
        e2ee_db.ensure_e2ee_tables()
        platform_db.ensure_platform_tables()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        (chat_db._use_sqlite_fallback, chat_db._sqlite_conn,
         e2ee_db._e2ee_tables_initialized, platform_db._platform_tables_initialized) = cls._orig

    def _login(self):
        acct = Account.create()
        c = self.client.post("/api/e2ee/auth/challenge", json={"wallet_address": acct.address}).json()
        sig = acct.sign_message(encode_defunct(text=c["message"])).signature.hex()
        v = self.client.post("/api/e2ee/auth/verify", json={
            "challenge_id": c["challenge_id"], "wallet_address": acct.address, "signature": sig}).json()
        self.client.cookies.clear()
        return v["session_token"]

    def test_server_full_refuses_new_connections_with_4503(self):
        platform_db.update_platform_settings({"platform_entry_fee_usd": 0}, "test")
        t1, t2 = self._login(), self._login()
        with patch.object(capacity, "max_online_users", return_value=1):
            with self.client.websocket_connect("/ws/public-chat") as first:
                first.send_json({"type": "auth", "token": t1})
                self.assertEqual(first.receive_json()["type"], "public_connected")
                # the room is full: a second person is told so right away
                with self.client.websocket_connect("/ws/public-chat") as second:
                    with self.assertRaises(WebSocketDisconnect) as cm:
                        second.send_json({"type": "auth", "token": t2})
                        second.receive_json()
                    self.assertEqual(cm.exception.code, 4503)
        # with room again, the same person gets in
        with patch.object(capacity, "max_online_users", return_value=5):
            with self.client.websocket_connect("/ws/public-chat") as again:
                again.send_json({"type": "auth", "token": t2})
                self.assertEqual(again.receive_json()["type"], "public_connected")

    def test_health_reports_capacity_and_connections(self):
        h = self.client.get("/api/health").json()["realtime"]
        self.assertIn("connections", h)
        self.assertIn("capacity_source", h)
        self.assertIn("max_online_users", h)


if __name__ == "__main__":
    unittest.main()
