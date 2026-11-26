"""
Unread counts behind the notification badges (private chats and groups).

Covers:
- Existing history is never counted as new: the first unread request marks it all read.
- New messages from other people count; your own messages never do.
- Opening a conversation (read marker) clears its count; markers never move backwards.
- Groups: only active members get counts, only for messages from others, never before they joined.
- People who are not in a conversation cannot set markers for it.
- The live group-message event names the sender (so the app can skip your own messages).
"""

import os
import sys
import base64
import secrets
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from app import app
import chat_db
import e2ee_db
import e2ee_routes
import read_markers_db
from test_e2ee_security import generate_signed_test_device


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class TestUnreadNotifications(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_use_sqlite = chat_db._use_sqlite_fallback
        cls._orig_sqlite_conn = chat_db._sqlite_conn
        cls._orig_e2ee_init = e2ee_db._e2ee_tables_initialized

        chat_db._use_sqlite_fallback = True
        chat_db._sqlite_conn = None
        chat_db._init_sqlite_engine()
        e2ee_db._e2ee_tables_initialized = False
        e2ee_db.ensure_e2ee_tables()
        read_markers_db._schema_ready_for = None

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
        read_markers_db._schema_ready_for = None

    def setUp(self):
        e2ee_routes._rate_buckets.clear()

    # ------------------------------------------------------------------ helpers
    def _h(self, tok: str) -> dict:
        return {"Authorization": f"Bearer {tok}"}

    def _member(self, name: str) -> dict:
        acct = Account.create()
        addr = Web3.to_checksum_address(acct.address)
        chal = self.client.post(
            "/api/e2ee/auth/challenge", json={"wallet_address": addr, "purpose": "login", "chain_id": 1}
        ).json()
        sig = acct.sign_message(encode_defunct(text=chal["message"])).signature.hex()
        res = self.client.post(
            "/api/e2ee/auth/verify",
            json={"challenge_id": chal["challenge_id"], "wallet_address": addr, "signature": sig},
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.client.cookies.clear()
        data = res.json()
        uid, tok = data["user"]["user_id"], data["session_token"]
        dev = f"dev_{name}_{secrets.token_hex(6)}"
        bundle, _ = generate_signed_test_device(uid, dev)
        r = self.client.post("/api/e2ee/devices/register", json=bundle, headers=self._h(tok))
        self.assertEqual(r.status_code, 200, r.text)
        return {"uid": uid, "tok": tok, "dev": dev}

    def _dm(self, sender: dict, recipient: dict) -> int:
        r = self.client.post(
            "/api/e2ee/dm/messages",
            headers=self._h(sender["tok"]),
            json={
                "message_id": f"dm_{secrets.token_hex(8)}",
                "recipient_user_id": recipient["uid"],
                "sender_device_id": sender["dev"],
                "device_ciphertexts": {
                    recipient["dev"]: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(64))},
                    sender["dev"]: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(64))},
                },
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        return int(r.json()["seq"])

    def _unread(self, m: dict) -> dict:
        r = self.client.get("/api/e2ee/unread", headers=self._h(m["tok"]))
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def _dm_unread(self, m: dict, peer: dict) -> int:
        return sum(d["unread"] for d in self._unread(m)["dm"] if d["peer_user_id"] == peer["uid"])

    def _grp_unread(self, m: dict, gid: str) -> int:
        return sum(g["unread"] for g in self._unread(m)["groups"] if g["group_id"] == gid)

    def _mark_dm(self, m: dict, peer: dict, seq: int):
        return self.client.post(
            "/api/e2ee/read-markers",
            headers=self._h(m["tok"]),
            json={"scope_type": "dm", "peer_user_id": peer["uid"], "last_read_seq": seq},
        )

    def _mark_grp(self, m: dict, gid: str, seq: int):
        return self.client.post(
            "/api/e2ee/read-markers",
            headers=self._h(m["tok"]),
            json={"scope_type": "group", "group_id": gid, "last_read_seq": seq},
        )

    def _group_with(self, admin: dict, member: dict) -> str:
        r = self.client.post(
            "/api/e2ee/groups",
            headers=self._h(admin["tok"]),
            json={
                "name": "Notify Club",
                "mls_group_id_b64": _b64(secrets.token_bytes(24)),
                "creator_device_id": admin["dev"],
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        gid = r.json()["group"]["group_id"]
        add = self.client.post(
            f"/api/e2ee/groups/{gid}/commits",
            headers=self._h(admin["tok"]),
            json={
                "committer_device_id": admin["dev"],
                "expected_epoch": 0,
                "commit_type": "add",
                "mls_commit_b64": _b64(secrets.token_bytes(96)),
                "added_members": [{"user_id": member["uid"], "device_id": member["dev"], "role": "member"}],
                "welcomes": [
                    {
                        "target_user_id": member["uid"],
                        "target_device_id": member["dev"],
                        "mls_welcome_b64": _b64(secrets.token_bytes(120)),
                    }
                ],
            },
        )
        self.assertEqual(add.status_code, 200, add.text)
        return gid

    def _gmsg(self, sender: dict, gid: str) -> int:
        r = self.client.post(
            f"/api/e2ee/groups/{gid}/messages",
            headers=self._h(sender["tok"]),
            json={
                "message_id": f"gmsg_{secrets.token_hex(8)}",
                "sender_device_id": sender["dev"],
                "epoch": e2ee_db.get_mls_group(gid)["current_epoch"],
                "mls_ciphertext_b64": _b64(secrets.token_bytes(64)),
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        return int(r.json()["message"]["seq"])

    # ------------------------------------------------------------------ tests
    def test_01_old_history_is_not_new_and_new_messages_count(self):
        alice, bob = self._member("alice"), self._member("bob")
        # History from before notifications existed
        self._dm(bob, alice)
        self._dm(bob, alice)
        # Both open the app (first unread check marks their existing history as read)
        self.assertEqual(self._dm_unread(alice, bob), 0)
        self.assertEqual(self._unread(alice)["total"], 0)
        self.assertEqual(self._unread(bob)["total"], 0)

        # New messages from Bob count; Alice's own messages never do
        self._dm(bob, alice)
        s2 = self._dm(bob, alice)
        self._dm(alice, bob)
        self.assertEqual(self._dm_unread(alice, bob), 2)
        row = [d for d in self._unread(alice)["dm"] if d["peer_user_id"] == bob["uid"]][0]
        self.assertEqual(row["last_seq"], s2)

        # Alice opens the chat -> cleared; an older marker never moves it back
        self.assertEqual(self._mark_dm(alice, bob, s2).status_code, 200)
        self.assertEqual(self._dm_unread(alice, bob), 0)
        self.assertEqual(self._mark_dm(alice, bob, 1).status_code, 200)
        self.assertEqual(self._dm_unread(alice, bob), 0)

        # Bob's own count only reflects Alice's message (sent after his baseline)
        self.assertEqual(self._dm_unread(bob, alice), 1)

    def test_02_brand_new_conversation_counts_everything(self):
        carol, dave = self._member("carol"), self._member("dave")
        self.assertEqual(self._unread(carol)["total"], 0)  # baseline taken with no chats yet
        self._dm(dave, carol)
        self._dm(dave, carol)
        self._dm(dave, carol)
        self.assertEqual(self._dm_unread(carol, dave), 3)
        self.assertEqual(self._unread(carol)["total"], 3)

    def test_03_group_counts_only_for_active_members_and_others_messages(self):
        admin, eve = self._member("admin"), self._member("eve")
        self.assertEqual(self._unread(eve)["total"], 0)
        self.assertEqual(self._unread(admin)["total"], 0)
        gid = self._group_with(admin, eve)

        # Eve has not accepted yet: no counts for her
        self._gmsg(admin, gid)
        self.assertEqual(self._grp_unread(eve, gid), 0)
        self.assertEqual(self._mark_grp(eve, gid, 1).status_code, 403)

        acc = self.client.post(f"/api/e2ee/groups/{gid}/invitation/accept", headers=self._h(eve["tok"]))
        self.assertEqual(acc.status_code, 200, acc.text)

        last = self._gmsg(admin, gid)
        self._gmsg(eve, gid)  # her own: not counted
        # Message sent while she was invited (same epoch she joined at) plus the new one
        self.assertEqual(self._grp_unread(eve, gid), 2)
        self.assertEqual(self._mark_grp(eve, gid, last).status_code, 200)
        self.assertEqual(self._grp_unread(eve, gid), 0)
        # The admin never counts his own messages, only Eve's
        self.assertEqual(self._grp_unread(admin, gid), 1)

    def test_04_strangers_cannot_set_markers(self):
        frank = self._member("frank")
        self.assertEqual(
            self.client.post(
                "/api/e2ee/read-markers",
                headers=self._h(frank["tok"]),
                json={"scope_type": "dm", "peer_user_id": "usr_doesnotexist", "last_read_seq": 5},
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                "/api/e2ee/read-markers",
                headers=self._h(frank["tok"]),
                json={"scope_type": "group", "group_id": "grp_doesnotexist", "last_read_seq": 5},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/api/e2ee/read-markers",
                headers=self._h(frank["tok"]),
                json={"scope_type": "everything", "last_read_seq": 5},
            ).status_code,
            422,
        )
        self.assertEqual(self.client.get("/api/e2ee/unread").status_code, 401)

    def test_05_group_message_event_names_the_sender(self):
        admin, gina = self._member("admin2"), self._member("gina")
        gid = self._group_with(admin, gina)
        sent = []
        with patch.object(e2ee_routes, "_schedule_ws_notify", side_effect=lambda uids, evt: sent.append(evt)):
            self._gmsg(admin, gid)
        evts = [e for e in sent if e.get("type") == "group_ciphertext"]
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0]["sender_user_id"], admin["uid"])


if __name__ == "__main__":
    unittest.main()
