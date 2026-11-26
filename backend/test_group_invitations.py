"""
Group invitations: when a group admin adds someone, that person gets an Accept / Reject
invitation (like Instagram) instead of being put into the group straight away.

Covers:
- An added member is 'invited': no group keys (Welcome), no group in their list, no messages.
- Accept: the member becomes active, gets the Welcome and can read and send.
- Reject: the member is never added, the Welcome is deleted, and accepting later is refused.
- Someone who asked to join themselves (join request / invite code) is added directly by the admin.
- An admin can cancel an invitation (remove), and invite again after a rejection.
- The group creator is the group's admin; Admin456 sees who created each group.
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
from test_e2ee_security import generate_signed_test_device


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class TestGroupInvitations(unittest.TestCase):
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

    def setUp(self):
        e2ee_routes._rate_buckets.clear()

    # ------------------------------------------------------------------ helpers
    def _login(self, acct) -> dict:
        addr = Web3.to_checksum_address(acct.address)
        chal = self.client.post(
            "/api/e2ee/auth/challenge",
            json={"wallet_address": addr, "purpose": "login", "chain_id": 1},
        ).json()
        sig = acct.sign_message(encode_defunct(text=chal["message"])).signature.hex()
        res = self.client.post(
            "/api/e2ee/auth/verify",
            json={"challenge_id": chal["challenge_id"], "wallet_address": addr, "signature": sig},
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.client.cookies.clear()
        return res.json()

    def _h(self, tok: str) -> dict:
        return {"Authorization": f"Bearer {tok}"}

    def _member(self, name: str, acct=None) -> dict:
        auth = self._login(acct or Account.create())
        uid, tok = auth["user"]["user_id"], auth["session_token"]
        dev = f"dev_{name}_{secrets.token_hex(6)}"
        bundle, _ = generate_signed_test_device(uid, dev)
        r = self.client.post("/api/e2ee/devices/register", json=bundle, headers=self._h(tok))
        self.assertEqual(r.status_code, 200, r.text)
        return {"uid": uid, "tok": tok, "dev": dev, "username": auth["user"].get("username")}

    def _create_group(self, admin: dict, name: str, visibility: str = "invite_only") -> str:
        r = self.client.post(
            "/api/e2ee/groups",
            headers=self._h(admin["tok"]),
            json={
                "name": name,
                "mls_group_id_b64": _b64(secrets.token_bytes(24)),
                "creator_device_id": admin["dev"],
                "visibility": visibility,
                "require_invitation": False,
            },
        )
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["group"]["group_id"]

    def _epoch(self, gid: str) -> int:
        return e2ee_db.get_mls_group(gid)["current_epoch"]

    def _add(self, admin: dict, gid: str, target: dict):
        return self.client.post(
            f"/api/e2ee/groups/{gid}/commits",
            headers=self._h(admin["tok"]),
            json={
                "committer_device_id": admin["dev"],
                "expected_epoch": self._epoch(gid),
                "commit_type": "add",
                "mls_commit_b64": _b64(secrets.token_bytes(96)),
                "added_members": [{"user_id": target["uid"], "device_id": target["dev"], "role": "member"}],
                "welcomes": [
                    {
                        "target_user_id": target["uid"],
                        "target_device_id": target["dev"],
                        "mls_welcome_b64": _b64(secrets.token_bytes(120)),
                    }
                ],
            },
        )

    def _remove(self, admin: dict, gid: str, target: dict):
        return self.client.post(
            f"/api/e2ee/groups/{gid}/commits",
            headers=self._h(admin["tok"]),
            json={
                "committer_device_id": admin["dev"],
                "expected_epoch": self._epoch(gid),
                "commit_type": "remove",
                "mls_commit_b64": _b64(secrets.token_bytes(96)),
                "removed_members": [{"user_id": target["uid"]}],
            },
        )

    def _welcomes(self, m: dict) -> list:
        return self.client.get(
            f"/api/e2ee/groups/welcomes?device_id={m['dev']}&consume=false", headers=self._h(m["tok"])
        ).json()["welcomes"]

    def _invitations(self, m: dict) -> list:
        r = self.client.get("/api/e2ee/groups/invitations", headers=self._h(m["tok"]))
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["invitations"]

    def _my_group_ids(self, m: dict) -> list:
        return [g["group_id"] for g in self.client.get("/api/e2ee/groups", headers=self._h(m["tok"])).json()["groups"]]

    def _status_of(self, gid: str, m: dict) -> set:
        return {r["status"] for r in e2ee_db.get_member_record(gid, m["uid"])}

    # ------------------------------------------------------------------ tests
    def test_01_added_member_must_accept_before_joining(self):
        admin, bob = self._member("admin"), self._member("bob")
        gid = self._create_group(admin, "Accept Club")

        r = self._add(admin, gid, bob)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._status_of(gid, bob), {"invited"})

        # While invited: no group keys, not in the group list, no messages, cannot post
        self.assertEqual(self._welcomes(bob), [])
        self.assertNotIn(gid, self._my_group_ids(bob))
        self.assertEqual(self.client.get(f"/api/e2ee/groups/{gid}/messages", headers=self._h(bob["tok"])).status_code, 403)
        self.assertEqual(self.client.get(f"/api/e2ee/groups/{gid}/commits", headers=self._h(bob["tok"])).json()["commits"], [])
        send = self.client.post(
            f"/api/e2ee/groups/{gid}/messages",
            headers=self._h(bob["tok"]),
            json={
                "message_id": f"gmsg_{secrets.token_hex(6)}",
                "sender_device_id": bob["dev"],
                "epoch": self._epoch(gid),
                "mls_ciphertext_b64": _b64(secrets.token_bytes(64)),
            },
        )
        self.assertEqual(send.status_code, 403)

        # The invitation shows who invited them and the group's details
        invs = self._invitations(bob)
        self.assertEqual(len(invs), 1)
        self.assertEqual(invs[0]["group_id"], gid)
        self.assertEqual(invs[0]["group_name"], "Accept Club")
        self.assertEqual(invs[0]["invited_by_user_id"], admin["uid"])
        self.assertEqual(invs[0]["member_count"], 1)

        # Accept -> joined: Welcome released, group listed, can read
        acc = self.client.post(f"/api/e2ee/groups/{gid}/invitation/accept", headers=self._h(bob["tok"]))
        self.assertEqual(acc.status_code, 200, acc.text)
        self.assertEqual(acc.json()["status"], "joined")
        self.assertEqual(self._status_of(gid, bob), {"active"})
        self.assertEqual(len(self._welcomes(bob)), 1)
        self.assertIn(gid, self._my_group_ids(bob))
        self.assertEqual(self.client.get(f"/api/e2ee/groups/{gid}/messages", headers=self._h(bob["tok"])).status_code, 200)
        self.assertEqual(self._invitations(bob), [])

        # Accepting twice is refused politely
        again = self.client.post(f"/api/e2ee/groups/{gid}/invitation/accept", headers=self._h(bob["tok"]))
        self.assertEqual(again.status_code, 404)

    def test_02_rejected_member_is_never_added(self):
        admin, carol = self._member("admin2"), self._member("carol")
        gid = self._create_group(admin, "Reject Club")
        self.assertEqual(self._add(admin, gid, carol).status_code, 200)

        dec = self.client.post(f"/api/e2ee/groups/{gid}/invitation/decline", headers=self._h(carol["tok"]))
        self.assertEqual(dec.status_code, 200, dec.text)
        self.assertEqual(dec.json()["status"], "declined")
        self.assertEqual(self._status_of(gid, carol), {"declined"})

        # Welcome deleted for good, no access, no invitation, cannot accept afterwards
        self.assertEqual(self._welcomes(carol), [])
        self.assertEqual(self._invitations(carol), [])
        self.assertNotIn(gid, self._my_group_ids(carol))
        self.assertEqual(self.client.get(f"/api/e2ee/groups/{gid}/messages", headers=self._h(carol["tok"])).status_code, 403)
        self.assertEqual(self.client.get(f"/api/e2ee/groups/{gid}/commits", headers=self._h(carol["tok"])).json()["commits"], [])
        late = self.client.post(f"/api/e2ee/groups/{gid}/invitation/accept", headers=self._h(carol["tok"]))
        self.assertEqual(late.status_code, 404)
        self.assertEqual(
            self.client.post(f"/api/e2ee/groups/{gid}/invitation/decline", headers=self._h(carol["tok"])).status_code,
            404,
        )

        # The admin can invite again later: remove the old entry, add again -> a fresh invitation
        self.assertEqual(self._remove(admin, gid, carol).status_code, 200)
        carol2_bundle, _ = generate_signed_test_device(carol["uid"], f"dev_carol2_{secrets.token_hex(6)}")
        r = self.client.post("/api/e2ee/devices/register", json=carol2_bundle, headers=self._h(carol["tok"]))
        self.assertEqual(r.status_code, 200, r.text)
        carol2 = dict(carol, dev=carol2_bundle["device_id"])
        self.assertEqual(self._add(admin, gid, carol2).status_code, 200)
        self.assertEqual([i["group_id"] for i in self._invitations(carol)], [gid])

    def test_03_member_who_asked_to_join_is_added_directly(self):
        admin, dave = self._member("admin3"), self._member("dave")
        gid = self._create_group(admin, "Open Club", visibility="public")

        jr = self.client.post(f"/api/platform/groups/{gid}/join-request", headers=self._h(dave["tok"]))
        self.assertEqual(jr.status_code, 200, jr.text)

        # Admin approves -> Dave is in straight away (he already agreed by asking)
        self.assertEqual(self._add(admin, gid, dave).status_code, 200)
        self.assertEqual(self._status_of(gid, dave), {"active"})
        self.assertEqual(self._invitations(dave), [])
        self.assertEqual(len(self._welcomes(dave)), 1)
        self.assertIn(gid, self._my_group_ids(dave))

    def test_04_admin_can_cancel_an_invitation(self):
        admin, erin = self._member("admin4"), self._member("erin")
        gid = self._create_group(admin, "Cancel Club")
        self.assertEqual(self._add(admin, gid, erin).status_code, 200)
        self.assertEqual(len(self._invitations(erin)), 1)

        # Admin removes the invited person -> invitation disappears and cannot be accepted
        self.assertEqual(self._remove(admin, gid, erin).status_code, 200)
        self.assertEqual(self._invitations(erin), [])
        self.assertEqual(
            self.client.post(f"/api/e2ee/groups/{gid}/invitation/accept", headers=self._h(erin["tok"])).status_code,
            404,
        )

    def test_05_strangers_cannot_answer_and_invited_cannot_manage(self):
        admin, frank, gina = self._member("admin5"), self._member("frank"), self._member("gina")
        gid = self._create_group(admin, "Guarded Club")
        self.assertEqual(self._add(admin, gid, frank).status_code, 200)

        # Gina was never invited
        self.assertEqual(
            self.client.post(f"/api/e2ee/groups/{gid}/invitation/accept", headers=self._h(gina["tok"])).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(f"/api/e2ee/groups/{gid}/invitation/decline", headers=self._h(gina["tok"])).status_code,
            404,
        )
        # An invited (not yet accepted) person cannot add others
        self.assertEqual(self._add(frank, gid, gina).status_code, 403)

    def test_06_creator_is_admin_and_admin456_sees_creator(self):
        boss = Account.create()
        with patch.dict(os.environ, {"ADMIN_WALLET_ADDRESSES": boss.address}):
            platform_admin = self._member("platformadmin", acct=boss)
        creator = self._member("creator")
        self.client.post(
            "/api/e2ee/account/username", headers=self._h(creator["tok"]), json={"username": "groupmaker"}
        )
        gid = self._create_group(creator, "Creator Club")

        grp = e2ee_db.get_mls_group(gid)
        creator_rows = [m for m in grp["members"] if m["user_id"] == creator["uid"]]
        self.assertEqual({m["role"] for m in creator_rows}, {"admin"})
        self.assertEqual({m["status"] for m in creator_rows}, {"active"})

        res = self.client.get("/api/platform/admin/groups", headers=self._h(platform_admin["tok"]))
        self.assertEqual(res.status_code, 200, res.text)
        row = [g for g in res.json()["groups"] if g["group_id"] == gid][0]
        self.assertEqual(row["creator_user_id"], creator["uid"])
        self.assertIn("creator_username", row)
        self.assertIn("creator_wallet", row)
        self.assertTrue(row["creator_wallet"])


if __name__ == "__main__":
    unittest.main()
