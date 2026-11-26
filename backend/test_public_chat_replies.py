"""
Replies in the Members' room (open chat).

Covers:
- A reply stores which message it answers; the feed and the live event carry the quote
  (who wrote the original + a short excerpt).
- A deleted (moderated) original shows no text in any quote, and cannot be replied to any more.
- Originals from a member the viewer blocked show no text in the quote.
- Long originals are shortened; file-only originals say "Photo" / "File: name".
- Bad or unknown ids are refused.
"""
import base64
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient
from eth_account import Account
from eth_account.messages import encode_defunct

from app import app
import chat_db
import e2ee_db
import platform_db
import platform_routes
import e2ee_routes

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class TestPublicChatReplies(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_use_sqlite = chat_db._use_sqlite_fallback
        cls._orig_sqlite_conn = chat_db._sqlite_conn
        cls._orig_e2ee_init = e2ee_db._e2ee_tables_initialized
        cls._orig_plat_init = platform_db._platform_tables_initialized

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
        if chat_db._sqlite_conn is not None and chat_db._sqlite_conn is not cls._orig_sqlite_conn:
            try:
                chat_db._sqlite_conn.close()
            except Exception:
                pass
        chat_db._use_sqlite_fallback = cls._orig_use_sqlite
        chat_db._sqlite_conn = cls._orig_sqlite_conn
        e2ee_db._e2ee_tables_initialized = cls._orig_e2ee_init
        platform_db._platform_tables_initialized = cls._orig_plat_init

    def setUp(self):
        self.client.cookies.clear()
        e2ee_routes._rate_buckets.clear()
        platform_db.update_platform_settings(
            {"platform_entry_fee_usd": 0, "use_live_eth_price": False, "eth_usd_price": 2500.0},
            actor_user_id="test_setup",
        )

    # ------------------------------------------------------------------ helpers
    def _member(self):
        acc = Account.create()
        chal = self.client.post("/api/e2ee/auth/challenge", json={"wallet_address": acc.address}).json()
        sig = acc.sign_message(encode_defunct(text=chal["message"])).signature.hex()
        res = self.client.post(
            "/api/e2ee/auth/verify",
            json={"challenge_id": chal["challenge_id"], "wallet_address": acc.address, "signature": sig},
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.client.cookies.clear()
        d = res.json()
        return d["user"]["user_id"], {"Authorization": f"Bearer {d['session_token']}"}

    def _post(self, h, content, reply_to=None, attachment_ids=None):
        body = {"content": content}
        if reply_to:
            body["reply_to_message_id"] = reply_to
        if attachment_ids:
            body["attachment_ids"] = attachment_ids
        return self.client.post("/api/platform/public-chat/messages", headers=h, json=body)

    def _feed_msg(self, h, message_id):
        feed = self.client.get("/api/platform/public-chat/messages", headers=h).json()["messages"]
        return next(m for m in feed if m["message_id"] == message_id)

    # ------------------------------------------------------------------ tests
    def test_01_reply_carries_a_quote_in_feed_and_live_event(self):
        _, h1 = self._member()
        _, h2 = self._member()
        orig = self._post(h1, "Who is coming to the meetup on Friday?")
        self.assertEqual(orig.status_code, 200, orig.text)
        oid = orig.json()["message"]["message_id"]

        sent = []
        with patch.object(platform_routes, "schedule_public_ws_broadcast", side_effect=lambda e: sent.append(e)):
            rep = self._post(h2, "I am!", reply_to=oid)
        self.assertEqual(rep.status_code, 200, rep.text)
        msg = rep.json()["message"]
        self.assertEqual(msg["reply_to_message_id"], oid)
        self.assertTrue(msg["reply_to"]["available"])
        self.assertEqual(msg["reply_to"]["preview"], "Who is coming to the meetup on Friday?")
        live = [e for e in sent if e.get("type") == "public_message_created"][0]["message"]
        self.assertEqual(live["reply_to"]["message_id"], oid)

        # Everyone reading the room sees the quote; plain messages have reply_to = None
        _, h3 = self._member()
        in_feed = self._feed_msg(h3, msg["message_id"])
        self.assertEqual(in_feed["reply_to"]["preview"], "Who is coming to the meetup on Friday?")
        self.assertIsNone(self._feed_msg(h3, oid)["reply_to"])

    def test_02_deleted_original_shows_no_text_and_cannot_be_replied_to(self):
        _, h1 = self._member()
        _, h2 = self._member()
        oid = self._post(h1, "Something rude").json()["message"]["message_id"]
        rid = self._post(h2, "Please don't", reply_to=oid).json()["message"]["message_id"]

        d = self.client.delete(f"/api/platform/public-chat/messages/{oid}", headers=h1)
        self.assertEqual(d.status_code, 200, d.text)

        quote = self._feed_msg(h2, rid)["reply_to"]
        self.assertFalse(quote["available"])
        self.assertIsNone(quote["preview"])
        self.assertIsNone(quote["display_name"])
        late = self._post(h2, "too late", reply_to=oid)
        self.assertEqual(late.status_code, 400)

    def test_03_blocked_authors_text_is_hidden_from_the_blocker(self):
        uid1, h1 = self._member()
        _, h2 = self._member()
        _, h3 = self._member()
        oid = self._post(h1, "Buy my coins").json()["message"]["message_id"]
        rid = self._post(h2, "No thanks", reply_to=oid).json()["message"]["message_id"]

        b = self.client.post("/api/platform/blocks", headers=h3, json={"target_user_id": uid1, "reason": "spam"})
        self.assertIn(b.status_code, (200, 201), b.text)
        self.assertFalse(self._feed_msg(h3, rid)["reply_to"]["available"])
        # Others still see it
        self.assertTrue(self._feed_msg(h2, rid)["reply_to"]["available"])

    def test_04_long_and_file_only_originals(self):
        _, h1 = self._member()
        _, h2 = self._member()
        long_text = "word " * 80
        oid = self._post(h1, long_text).json()["message"]["message_id"]
        q = self._post(h2, "tl;dr?", reply_to=oid).json()["message"]["reply_to"]
        self.assertLessEqual(len(q["preview"]), 120)
        self.assertTrue(q["preview"].endswith("\u2026"))

        up = self.client.post(
            "/api/platform/public-chat/attachments",
            headers=h1,
            json={"file_name": "pic.png", "mime_type": "image/png", "data_b64": base64.b64encode(PNG).decode()},
        )
        self.assertEqual(up.status_code, 200, up.text)
        pid = self._post(h1, "", attachment_ids=[up.json()["attachment"]["attachment_id"]]).json()["message"]["message_id"]
        q2 = self._post(h2, "Nice photo", reply_to=pid).json()["message"]["reply_to"]
        self.assertEqual(q2["preview"], "Photo")

    def test_05_bad_or_unknown_ids_are_refused(self):
        _, h = self._member()
        self.assertEqual(self._post(h, "x", reply_to="pub_doesnotexist000").status_code, 400)
        self.assertEqual(self._post(h, "x", reply_to="<script>").status_code, 422)
        self.assertEqual(self._post(h, "x", reply_to="emsg_123456").status_code, 422)


if __name__ == "__main__":
    unittest.main()
