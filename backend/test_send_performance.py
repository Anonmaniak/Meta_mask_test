"""
Regression tests for the chat-send speed-up.

1. Real-time delivery: a message POSTed through a (threadpool) sync route MUST reach other
   connected viewers over /ws/public-chat. (It silently never did before.)
2. Verify-once caching: repeated requests do not repeat the same database reads ...
3. ... but security changes (logout/revoke, suspension, mute, settings) take effect IMMEDIATELY.
4. Duplicate-burst protection still works after being folded into the INSERT.
"""

import os
import queue
import sys
import threading
import time
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient

import auth_cache
import chat_db
import e2ee_db
import platform_db
from app import app

WALLET_A = "0x" + "a1" * 20
WALLET_B = "0x" + "b2" * 20


def _session_for(wallet: str):
    user, _ = e2ee_db.get_or_create_user_for_wallet(wallet)
    exp = (e2ee_db.now_utc() + timedelta(hours=1)).isoformat()
    token, _ = e2ee_db.create_auth_session(user["user_id"], wallet, exp)
    return user, token


def _post(client, token, text):
    return client.post(
        "/api/platform/public-chat/messages",
        json={"content": text},
        headers={"Authorization": f"Bearer {token}"},
    )


class SendPerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        auth_cache.invalidate_all()

    # ------------------------------------------------------------------ 1
    def test_post_reaches_other_viewers_in_realtime(self):
        _, token = _session_for(WALLET_A)
        frames: "queue.Queue[dict]" = queue.Queue()
        with self.client.websocket_connect("/ws/public-chat") as ws:
            ws.send_json({"type": "auth", "token": token})  # members-only stream
            ws.receive_json()  # public_connected

            def reader():
                try:
                    while True:
                        frames.put(ws.receive_json())
                except Exception:
                    pass

            threading.Thread(target=reader, daemon=True).start()
            res = _post(self.client, token, "realtime delivery check")
            self.assertEqual(res.status_code, 200, res.text)
            sent_id = res.json()["message"]["message_id"]

            deadline = time.time() + 3
            seen = []
            while time.time() < deadline:
                try:
                    evt = frames.get(timeout=0.2)
                except queue.Empty:
                    continue
                if evt.get("type") == "public_message_created":
                    seen.append(evt["message"]["message_id"])
                    break
            self.assertIn(sent_id, seen, "other viewers never received the broadcast")

    # ------------------------------------------------------------------ 2
    def test_repeat_requests_hit_cache(self):
        _, token = _session_for(WALLET_A)
        _post(self.client, token, "warm-up message one")  # populates cache
        stmts = []
        chat_db._sqlite_conn.set_trace_callback(lambda s: stmts.append(s))
        try:
            res = _post(self.client, token, "second message uses the cache")
        finally:
            chat_db._sqlite_conn.set_trace_callback(None)
        self.assertEqual(res.status_code, 200, res.text)
        reads = [s for s in stmts if s.lstrip().upper().startswith("SELECT")]
        self.assertFalse(
            any("chat_auth_sessions" in s or "platform_settings" in s or "FROM chat_users" in s for s in reads),
            f"session/user/settings were re-read from the DB: {reads}",
        )

    # ------------------------------------------------------------------ 3
    def test_logout_revoke_is_immediate_despite_cache(self):
        _, token = _session_for(WALLET_A)
        self.assertEqual(_post(self.client, token, "before revoke").status_code, 200)  # cached now
        e2ee_db.revoke_session_token(token)
        # Public chat allows guests, so an invalid token falls back to guest posting; the
        # authoritative check is that the session no longer resolves.
        self.assertIsNone(e2ee_db.get_session_by_token(token))
        res = self.client.get("/api/e2ee/account/profile", headers={"Authorization": f"Bearer {token}"})
        self.assertIn(res.status_code, (401, 403, 404))

    def test_suspension_is_immediate_despite_cache(self):
        user, token = _session_for(WALLET_B)
        self.assertEqual(_post(self.client, token, "before suspension").status_code, 200)  # cached now
        platform_db.admin_moderate_user_account(
            target_user_id=user["user_id"], action_type="suspend", reason="test", moderator_user_id="admin_console"
        )
        self.assertIsNone(e2ee_db.get_session_by_token(token))  # sessions revoked on suspend

    def test_mute_is_immediate_despite_cache(self):
        user, token = _session_for("0x" + "c3" * 20)
        self.assertEqual(_post(self.client, token, "before mute").status_code, 200)  # cached now
        platform_db.admin_moderate_user_account(
            target_user_id=user["user_id"], action_type="mute", reason="test", moderator_user_id="admin_console"
        )
        res = _post(self.client, token, "after mute should be refused")
        self.assertEqual(res.status_code, 403, res.text)

    def test_settings_change_is_immediate(self):
        before = platform_db.get_platform_settings()["public_chat_max_length"]
        platform_db.update_platform_settings({"public_chat_max_length": 77}, actor_user_id="admin_console")
        try:
            self.assertEqual(platform_db.get_platform_settings()["public_chat_max_length"], 77)
        finally:
            platform_db.update_platform_settings({"public_chat_max_length": before}, actor_user_id="admin_console")

    def test_cached_session_still_respects_expiry(self):
        user, _ = e2ee_db.get_or_create_user_for_wallet("0x" + "d4" * 20)
        exp = (e2ee_db.now_utc() + timedelta(seconds=1)).isoformat()
        token, _ = e2ee_db.create_auth_session(user["user_id"], "0x" + "d4" * 20, exp)
        self.assertIsNotNone(e2ee_db.get_session_by_token(token))  # cached
        time.sleep(1.3)
        self.assertIsNone(e2ee_db.get_session_by_token(token), "expired session served from cache")

    def test_invalid_tokens_are_never_cached(self):
        self.assertIsNone(e2ee_db.get_session_by_token("not-a-real-token"))
        user, _ = e2ee_db.get_or_create_user_for_wallet("0x" + "e5" * 20)
        self.assertIsNone(e2ee_db.get_session_by_token("not-a-real-token"))

    # ------------------------------------------------------------------ 4
    def test_duplicate_burst_still_blocked_and_distinct_allowed(self):
        _, token = _session_for("0x" + "f6" * 20)
        self.assertEqual(_post(self.client, token, "same text twice").status_code, 200)
        dup = _post(self.client, token, "same text twice")
        self.assertEqual(dup.status_code, 429, dup.text)
        self.assertEqual(_post(self.client, token, "different text now").status_code, 200)

    def test_duplicate_guard_is_per_author(self):
        _, tok1 = _session_for("0x" + "17" * 20)
        _, tok2 = _session_for("0x" + "28" * 20)
        self.assertEqual(_post(self.client, tok1, "shared sentence").status_code, 200)
        self.assertEqual(_post(self.client, tok2, "shared sentence").status_code, 200)


if __name__ == "__main__":
    unittest.main()