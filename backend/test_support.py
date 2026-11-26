"""Tests for "Talk to admin": member conversations, admin inbox, privacy and limits."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient
from eth_account import Account
from eth_account.messages import encode_defunct

from app import app
import chat_db
import e2ee_db
import platform_db
import support_db


class TestSupport(unittest.TestCase):
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
        support_db.reset_for_tests()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        if chat_db._sqlite_conn is not None and chat_db._sqlite_conn is not cls._orig[1]:
            try:
                chat_db._sqlite_conn.close()
            except Exception:
                pass
        (chat_db._use_sqlite_fallback, chat_db._sqlite_conn,
         e2ee_db._e2ee_tables_initialized, platform_db._platform_tables_initialized) = cls._orig

    def setUp(self):
        self.client.cookies.clear()

    def _login(self, account=None):
        account = account or Account.create()
        c = self.client.post("/api/e2ee/auth/challenge", json={"wallet_address": account.address}).json()
        sig = account.sign_message(encode_defunct(text=c["message"])).signature.hex()
        v = self.client.post("/api/e2ee/auth/verify", json={
            "challenge_id": c["challenge_id"], "wallet_address": account.address, "signature": sig}).json()
        self.client.cookies.clear()
        return v["user"]["user_id"], {"Authorization": f"Bearer {v['session_token']}"}

    def _admin(self, role="superadmin"):
        uid, h = self._login()
        platform_db.set_admin_role(uid, role, actor_user_id="system")
        return uid, h

    def test_01_member_opens_conversation_and_admin_replies(self):
        uid, uh = self._login()
        _, ah = self._admin()
        r = self.client.post("/api/platform/support/threads", headers=uh,
                             json={"subject": "Payment stuck", "message": "I paid but nothing happened"})
        self.assertEqual(r.status_code, 200, r.text)
        tid = r.json()["thread"]["thread_id"]

        # Admin sees it as unread, with who wrote it
        lst = self.client.get("/api/platform/admin/support/threads", headers=ah).json()
        row = next(t for t in lst["threads"] if t["thread_id"] == tid)
        self.assertEqual(row["unread"], 1)
        self.assertEqual(row["user_id"], uid)
        self.assertGreaterEqual(lst["unread_total"], 1)

        # Opening it marks it read for the admin; admin replies
        det = self.client.get(f"/api/platform/admin/support/threads/{tid}", headers=ah).json()
        self.assertEqual([m["sender_role"] for m in det["messages"]], ["user"])
        rep = self.client.post(f"/api/platform/admin/support/threads/{tid}/reply", headers=ah,
                               json={"content": "Thanks, checking your transaction now."})
        self.assertEqual(rep.status_code, 200, rep.text)
        lst = self.client.get("/api/platform/admin/support/threads", headers=ah).json()
        self.assertEqual(next(t for t in lst["threads"] if t["thread_id"] == tid)["unread"], 0)

        # Member sees one unread reply, reads it, counter clears
        self.assertEqual(self.client.get("/api/platform/support/unread", headers=uh).json()["unread_total"], 1)
        det = self.client.get(f"/api/platform/support/threads/{tid}", headers=uh).json()
        self.assertEqual([m["sender_role"] for m in det["messages"]], ["user", "admin"])
        self.assertEqual(self.client.get("/api/platform/support/unread", headers=uh).json()["unread_total"], 0)

    def test_02_privacy_between_users_and_admin_only_endpoints(self):
        _, a = self._login()
        _, b = self._login()
        tid = self.client.post("/api/platform/support/threads", headers=a,
                               json={"subject": "Private matter", "message": "secret"}).json()["thread"]["thread_id"]
        # Another member gets the same 404 as for a missing id, for read AND write
        self.assertEqual(self.client.get(f"/api/platform/support/threads/{tid}", headers=b).status_code, 404)
        self.assertEqual(self.client.post(f"/api/platform/support/threads/{tid}/messages", headers=b,
                                          json={"content": "hi"}).status_code, 404)
        self.assertEqual(self.client.get("/api/platform/support/threads", headers=b).json()["threads"], [])
        # Members cannot use the admin inbox; anonymous cannot use anything
        self.assertEqual(self.client.get("/api/platform/admin/support/threads", headers=a).status_code, 403)
        self.assertEqual(self.client.post(f"/api/platform/admin/support/threads/{tid}/reply", headers=a,
                                          json={"content": "I am admin"}).status_code, 403)
        self.assertEqual(self.client.get("/api/platform/support/threads").status_code, 401)

    def test_03_unpaid_member_can_still_contact_admin(self):
        platform_db.update_platform_settings({"platform_entry_fee_usd": 10, "use_live_eth_price": False}, "test")
        try:
            uid, h = self._login()
            self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=h).status_code, 402)
            r = self.client.post("/api/platform/support/threads", headers=h,
                                 json={"subject": "Cannot pay", "message": "MetaMask shows an error"})
            self.assertEqual(r.status_code, 200, r.text)
        finally:
            platform_db.update_platform_settings({"platform_entry_fee_usd": 0}, "test")

    def test_04_user_reply_reopens_closed_conversation(self):
        _, uh = self._login()
        _, ah = self._admin("moderator")  # moderators can handle support too
        tid = self.client.post("/api/platform/support/threads", headers=uh,
                               json={"subject": "Question", "message": "How do groups work?"}).json()["thread"]["thread_id"]
        self.assertEqual(self.client.post(f"/api/platform/admin/support/threads/{tid}/status", headers=ah,
                                          json={"status": "closed"}).status_code, 200)
        closed = self.client.get("/api/platform/admin/support/threads?status=closed", headers=ah).json()["threads"]
        self.assertTrue(any(t["thread_id"] == tid for t in closed))
        self.client.post(f"/api/platform/support/threads/{tid}/messages", headers=uh, json={"content": "One more thing"})
        opened = self.client.get("/api/platform/admin/support/threads?status=open", headers=ah).json()["threads"]
        self.assertTrue(any(t["thread_id"] == tid for t in opened))
        self.assertEqual(self.client.post(f"/api/platform/admin/support/threads/{tid}/status", headers=ah,
                                          json={"status": "bogus"}).status_code, 422)

    def test_05_validation_and_limits(self):
        _, h = self._login()
        bad = [
            {"subject": "ok subject", "message": ""},
            {"subject": "no", "message": "subject too short"},
            {"subject": "ok subject", "message": "x" * 2001},
            {"subject": "ok subject", "message": "click javascript:alert(1)"},
        ]
        for body in bad:
            self.assertIn(self.client.post("/api/platform/support/threads", headers=h, json=body).status_code,
                          (400, 422), body)
        # At most 5 open conversations per member
        _, h2 = self._login()
        for i in range(support_db.MAX_OPEN_THREADS_PER_USER):
            self.assertEqual(self.client.post("/api/platform/support/threads", headers=h2,
                             json={"subject": f"Topic number {i}", "message": "hello"}).status_code, 200)
        self.assertEqual(self.client.post("/api/platform/support/threads", headers=h2,
                         json={"subject": "One too many", "message": "hello"}).status_code, 429)

    def test_06_admin_replies_are_audit_logged(self):
        _, uh = self._login()
        aid, ah = self._admin()
        tid = self.client.post("/api/platform/support/threads", headers=uh,
                               json={"subject": "Audit me", "message": "hello"}).json()["thread"]["thread_id"]
        self.client.post(f"/api/platform/admin/support/threads/{tid}/reply", headers=ah, json={"content": "hi"})
        logs = self.client.get("/api/platform/admin/audit-logs?limit=50", headers=ah).json()
        text = str(logs)
        self.assertIn("support_reply", text)


if __name__ == "__main__":
    unittest.main()
