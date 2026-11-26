"""
Regression tests for the private-message and group speed-ups.

* Both sides get live updates (sender confirmation + receiver notification).
* Cached device / group / policy / block lookups NEVER outlive a security change:
  device revoke, block, group policy change take effect on the very next request.
* One-statement inserts keep duplicate-message protection.
* The in-memory group-create response is identical to what a fresh read returns.
"""

import base64
import os
import queue
import secrets
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
import e2ee_routes
import platform_db
from app import app
from test_e2ee_security import generate_signed_test_device


def _b64(n: int = 40) -> str:
    return base64.b64encode(secrets.token_bytes(n)).decode()


class GroupDmSpeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def setUp(self):
        auth_cache.invalidate_all()

    # ------------------------------------------------------------------ helpers
    def _user(self):
        wallet = "0x" + secrets.token_hex(20)
        user, _ = e2ee_db.get_or_create_user_for_wallet(wallet)
        exp = (e2ee_db.now_utc() + timedelta(hours=1)).isoformat()
        token, _ = e2ee_db.create_auth_session(user["user_id"], wallet, exp)
        dev = "dev_" + secrets.token_hex(8)
        payload, _ = generate_signed_test_device(user["user_id"], dev)
        h = {"Authorization": f"Bearer {token}"}
        r = self.client.post("/api/e2ee/devices/register", json=payload, headers=h)
        self.assertIn(r.status_code, (200, 201), r.text)
        return {"id": user["user_id"], "token": token, "h": h, "dev": dev}

    def _dm(self, sender, recipient, message_id=None):
        return self.client.post(
            "/api/e2ee/dm/messages",
            headers=sender["h"],
            json={
                "message_id": message_id or "msg_" + secrets.token_hex(8),
                "recipient_user_id": recipient["id"],
                "sender_device_id": sender["dev"],
                "protocol": e2ee_routes.OLM_PROTOCOL_ID,
                "device_ciphertexts": {recipient["dev"]: {"message_type": 1, "ciphertext_b64": _b64()}},
            },
        )

    def _group(self, owner, **extra):
        body = {
            "name": "Speed Group",
            "mls_group_id_b64": _b64(32),
            "creator_device_id": owner["dev"],
            "ciphersuite": e2ee_routes.MLS_CIPHERSUITE_ID,
        }
        body.update(extra)
        r = self.client.post("/api/e2ee/groups", headers=owner["h"], json=body)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["group"]

    def _group_msg(self, owner, gid, epoch=0, message_id=None):
        return self.client.post(
            f"/api/e2ee/groups/{gid}/messages",
            headers=owner["h"],
            json={
                "message_id": message_id or "gmsg_" + secrets.token_hex(8),
                "sender_device_id": owner["dev"],
                "epoch": epoch,
                "mls_ciphertext_b64": _b64(),
            },
        )

    @staticmethod
    def _collect(ws, out: "queue.Queue[dict]"):
        def rd():
            try:
                while True:
                    out.put(ws.receive_json())
            except Exception:
                pass

        threading.Thread(target=rd, daemon=True).start()

    @staticmethod
    def _wait_for(q: "queue.Queue[dict]", type_: str, timeout=3.0):
        end = time.time() + timeout
        while time.time() < end:
            try:
                evt = q.get(timeout=0.2)
            except queue.Empty:
                continue
            if evt.get("type") == type_:
                return evt
        return None

    # ------------------------------------------------------------------ private chats
    def test_dm_receiver_gets_live_event_and_sender_gets_confirmation(self):
        a, b = self._user(), self._user()
        frames: "queue.Queue[dict]" = queue.Queue()
        with self.client.websocket_connect("/ws/e2ee") as ws:
            ws.send_json({"type": "auth", "token": b["token"]})
            self.assertEqual(ws.receive_json()["type"], "authenticated")
            self._collect(ws, frames)
            res = self._dm(a, b)
            self.assertEqual(res.status_code, 200, res.text)
            self.assertTrue(res.json()["success"])  # sender-side confirmation
            evt = self._wait_for(frames, "dm_ciphertext")  # receiver-side live notification
            self.assertIsNotNone(evt, "receiver never got the live DM notification")
            self.assertEqual(evt["message_id"], res.json()["message_id"])

    def test_dm_duplicate_message_id_still_rejected(self):
        a, b = self._user(), self._user()
        mid = "msg_" + secrets.token_hex(8)
        self.assertEqual(self._dm(a, b, mid).status_code, 200)
        self.assertEqual(self._dm(a, b, mid).status_code, 409)

    def test_block_takes_effect_immediately_despite_cache(self):
        a, b = self._user(), self._user()
        self.assertEqual(self._dm(a, b).status_code, 200)  # populates caches
        r = self.client.post("/api/platform/blocks", headers=b["h"], json={"target_user_id": a["id"], "reason": "t"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._dm(a, b).status_code, 403)
        self.client.delete(f"/api/platform/blocks/{a['id']}", headers=b["h"])
        self.assertEqual(self._dm(a, b).status_code, 200)

    def test_device_revoke_takes_effect_immediately_despite_cache(self):
        a, b = self._user(), self._user()
        self.assertEqual(self._dm(a, b).status_code, 200)  # device cached
        r = self.client.post(f"/api/e2ee/devices/{a['dev']}/revoke", headers=a["h"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._dm(a, b).status_code, 403)

    def test_dm_fetch_returns_new_message_to_receiver(self):
        a, b = self._user(), self._user()
        sent = self._dm(a, b).json()
        self.client.get("/api/e2ee/dm/messages", headers=b["h"], params={"peer_user_id": a["id"], "device_id": b["dev"]})
        res = self.client.get(
            "/api/e2ee/dm/messages", headers=b["h"], params={"peer_user_id": a["id"], "device_id": b["dev"]}
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertIn(sent["message_id"], [m["message_id"] for m in res.json()["messages"]])

    # ------------------------------------------------------------------ groups
    def test_group_create_response_matches_a_fresh_read(self):
        a = self._user()
        created = self._group(a, description="hello", visibility="public")
        auth_cache.invalidate_all()
        fetched = self.client.get(f"/api/e2ee/groups/{created['group_id']}", headers=a["h"]).json()["group"]
        self.assertEqual(created, fetched)

    def test_group_send_duplicate_and_epoch_rules_preserved(self):
        a = self._user()
        gid = self._group(a)["group_id"]
        mid = "gmsg_" + secrets.token_hex(8)
        self.assertEqual(self._group_msg(a, gid, 0, mid).status_code, 200)
        self.assertEqual(self._group_msg(a, gid, 0, mid).status_code, 409)  # duplicate id
        self.assertEqual(self._group_msg(a, gid, 5).status_code, 409)  # wrong epoch

    def test_group_members_get_live_event(self):
        a = self._user()
        gid = self._group(a)["group_id"]
        frames: "queue.Queue[dict]" = queue.Queue()
        with self.client.websocket_connect("/ws/e2ee") as ws:
            ws.send_json({"type": "auth", "token": a["token"]})
            self.assertEqual(ws.receive_json()["type"], "authenticated")
            self._collect(ws, frames)
            res = self._group_msg(a, gid)
            self.assertEqual(res.status_code, 200, res.text)
            evt = self._wait_for(frames, "group_ciphertext")
            self.assertIsNotNone(evt, "group members never got the live notification")
            self.assertEqual(evt["group_id"], gid)

    def test_group_policy_change_takes_effect_immediately(self):
        a = self._user()
        gid = self._group(a)["group_id"]
        self.assertEqual(self._group_msg(a, gid).status_code, 200)  # policy cached
        platform_db.upsert_group_access_policy(
            group_id=gid,
            description="",
            visibility="invite_only",
            min_eth_balance_wei="999999999999999999999",
            require_invitation=True,
            actor_user_id=a["id"],
        )
        res = self._group_msg(a, gid)
        self.assertEqual(res.status_code, 403, res.text)

    def test_group_send_after_device_revoke_is_refused_immediately(self):
        a = self._user()
        gid = self._group(a)["group_id"]
        self.assertEqual(self._group_msg(a, gid).status_code, 200)
        self.assertEqual(self.client.post(f"/api/e2ee/devices/{a['dev']}/revoke", headers=a["h"]).status_code, 200)
        self.assertIn(self._group_msg(a, gid).status_code, (403, 404))

    def test_group_list_is_cached_but_new_group_appears_immediately(self):
        a = self._user()
        g1 = self._group(a)["group_id"]
        first = self.client.get("/api/e2ee/groups", headers=a["h"]).json()["groups"]
        self.assertEqual([g["group_id"] for g in first], [g1])
        g2 = self._group(a)["group_id"]  # must not be hidden by the cached list
        second = self.client.get("/api/e2ee/groups", headers=a["h"]).json()["groups"]
        self.assertEqual({g["group_id"] for g in second}, {g1, g2})

    def test_batched_group_list_equals_individual_reads(self):
        a = self._user()
        for i in range(3):
            self._group(a, name=f"Batch {i}", description=f"d{i}", visibility="public")
        auth_cache.invalidate_all()
        listed = e2ee_db.list_groups_for_user(a["id"])
        auth_cache.invalidate_all()
        single = [e2ee_db.get_mls_group.__wrapped__(g["group_id"]) for g in listed]  # bypass cache
        self.assertEqual(len(listed), 3)
        self.assertEqual(sorted(listed, key=lambda g: g["group_id"]), sorted(single, key=lambda g: g["group_id"]))

    def test_group_create_does_not_throw_away_session_cache(self):
        a = self._user()
        self.client.get("/api/e2ee/me", headers=a["h"])  # warm session + user cache
        self._group(a)
        stmts = []
        chat_db._sqlite_conn.set_trace_callback(lambda s: stmts.append(s))
        try:
            self.client.get("/api/e2ee/me", headers=a["h"])
        finally:
            chat_db._sqlite_conn.set_trace_callback(None)
        self.assertFalse(
            any("chat_auth_sessions" in s for s in stmts),
            "group creation needlessly evicted the cached session",
        )


if __name__ == "__main__":
    unittest.main()
