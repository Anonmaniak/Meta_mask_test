"""
Data isolation: a signed-in member must never read or change another member's private data.

User A owns a private group (with member C), a DM conversation with C, a support thread, devices
and an encrypted attachment. User B is a normal, paid, signed-in member with no relationship to any
of it. Every request B makes against A's ids must be refused (403 / 404 / 410) — never answered with
A's data.
"""
import base64
import hashlib
import os
import secrets
import sys
import unittest

os.environ["TESTING"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account

import e2ee_db
import e2ee_routes
import platform_db
from test_paid_membership_and_groups import TestPaidMembershipAndGroups as _Base
from test_e2ee_security import generate_signed_test_device

REFUSED = (403, 404, 410)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class _Fixtures(unittest.TestCase):
    __test__ = False


for _name in ("setUpClass", "tearDownClass", "setUp", "_enable_paywall", "_tx_result", "_siwe_login",
              "_make_admin", "_create_group"):
    setattr(_Fixtures, _name, _Base.__dict__[_name])
del _Base


class TestUserIsolation(_Fixtures):
    __test__ = True

    def setUp(self):
        super().setUp()
        e2ee_routes._rate_buckets.clear()
        platform_db.auth_cache.invalidate_all()

    def _member(self):
        data = self._siwe_login(Account.create())
        self.client.cookies.clear()
        uid = data["user"]["user_id"]
        h = {"Authorization": f"Bearer {data['session_token']}"}
        dev = f"dev_m_{secrets.token_hex(5)}"
        bundle, _ = generate_signed_test_device(uid, dev)
        self.assertEqual(self.client.post("/api/e2ee/devices/register", json=bundle, headers=h).status_code, 200)
        return {"uid": uid, "h": h, "dev": dev}

    def _world(self):
        a, b, c = self._member(), self._member(), self._member()
        gid = self._create_group(a["h"], a["dev"], visibility="invite_only").json()["group"]["group_id"]
        # C joins A's group
        epoch = e2ee_db.get_mls_group(gid)["current_epoch"]
        r = self.client.post(f"/api/e2ee/groups/{gid}/commits", headers=a["h"], json={
            "committer_device_id": a["dev"], "expected_epoch": epoch, "commit_type": "add",
            "mls_commit_b64": _b64(secrets.token_bytes(96)),
            "added_members": [{"user_id": c["uid"], "device_id": c["dev"], "role": "member"}],
            "welcomes": [{"target_user_id": c["uid"], "target_device_id": c["dev"],
                          "mls_welcome_b64": _b64(secrets.token_bytes(120))}]})
        self.assertEqual(r.status_code, 200, r.text)
        self.client.post(f"/api/e2ee/groups/{gid}/invitation/accept", headers=c["h"])
        # a group message by A
        epoch = e2ee_db.get_mls_group(gid)["current_epoch"]
        gm = self.client.post(f"/api/e2ee/groups/{gid}/messages", headers=a["h"], json={
            "message_id": "msg_" + secrets.token_hex(8), "epoch": epoch, "sender_device_id": a["dev"],
            "mls_ciphertext_b64": _b64(secrets.token_bytes(40))})
        self.assertEqual(gm.status_code, 200, gm.text)
        # a DM from A to C
        cts = {a["dev"]: {"message_type": 1, "ciphertext_b64": _b64(secrets.token_bytes(40))},
               c["dev"]: {"message_type": 1, "ciphertext_b64": _b64(secrets.token_bytes(40))}}
        dm = self.client.post("/api/e2ee/dm/messages", headers=a["h"], json={
            "message_id": "dm_" + secrets.token_hex(8), "recipient_user_id": c["uid"],
            "sender_device_id": a["dev"], "device_ciphertexts": cts})
        self.assertEqual(dm.status_code, 200, dm.text)
        # an encrypted attachment in A's group
        ct = secrets.token_bytes(64)
        att = self.client.post("/api/e2ee/attachments", headers=a["h"], json={
            "scope_type": "group", "scope_id": gid, "uploader_device_id": a["dev"],
            "ciphertext_b64": _b64(ct), "ciphertext_sha256": hashlib.sha256(ct).hexdigest()})
        self.assertEqual(att.status_code, 200, att.text)
        # a support thread by A
        st = self.client.post("/api/platform/support/threads", headers=a["h"],
                              json={"subject": "My private issue", "message": "secret details"})
        self.assertEqual(st.status_code, 200, st.text)
        thread_id = st.json().get("thread", st.json()).get("thread_id")
        return a, b, c, {
            "gid": gid, "gmsg": gm.json()["message"]["message_id"], "dm": dm.json()["message_id"],
            "att": att.json()["attachment"]["attachment_id"], "thread": thread_id,
        }

    def _refused(self, r, what):
        self.assertIn(r.status_code, REFUSED, f"{what} -> {r.status_code}: {r.text[:200]}")

    def test_outsider_cannot_read_or_change_a_private_group(self):
        a, b, c, ids = self._world()
        g = ids["gid"]
        self._refused(self.client.get(f"/api/e2ee/groups/{g}/messages", headers=b["h"]), "read group messages")
        self._refused(self.client.get(f"/api/e2ee/groups/{g}/commits", headers=b["h"]), "read group commits")
        self._refused(self.client.get(f"/api/e2ee/groups/{g}", headers=b["h"]), "read group membership")
        self._refused(self.client.get(f"/api/platform/groups/{g}/join-requests", headers=b["h"]), "list join requests")
        self._refused(self.client.post(f"/api/e2ee/groups/{g}/settings", headers=b["h"],
                                       json={"admins_only_posting": True}), "change group settings")
        self._refused(self.client.post(f"/api/platform/groups/{g}/members/{c['uid']}/role", headers=b["h"],
                                       json={"role": "admin"}), "promote a member")
        self._refused(self.client.delete(f"/api/platform/groups/{g}", headers=b["h"]), "delete the group")
        self._refused(self.client.post(f"/api/e2ee/groups/{g}/messages/{ids['gmsg']}/delete", headers=b["h"]),
                      "delete a group message")
        self._refused(self.client.get(f"/api/e2ee/conversations/state?scope_type=group&group_id={g}", headers=b["h"]),
                      "read group pins/timers")
        self._refused(self.client.post("/api/e2ee/pins", headers=b["h"], json={
            "scope_type": "group", "group_id": g, "message_id": ids["gmsg"], "pinned": True}), "pin in group")
        self._refused(self.client.put(f"/api/platform/groups/{g}/policy", headers=b["h"], json={
            "description": "hijacked", "visibility": "public", "require_invitation": False}), "edit group policy")
        # Group still intact for its real members
        self.assertEqual(self.client.get(f"/api/e2ee/groups/{g}/messages", headers=c["h"]).status_code, 200)

    def test_outsider_cannot_touch_someone_elses_dm_attachment_or_devices(self):
        a, b, c, ids = self._world()
        self._refused(self.client.post(f"/api/e2ee/dm/messages/{ids['dm']}/delete", headers=b["h"]), "delete A's DM")
        self._refused(self.client.get(f"/api/e2ee/attachments/{ids['att']}", headers=b["h"]), "download A's attachment")
        self._refused(self.client.post(f"/api/e2ee/attachments/{ids['att']}/revoke", headers=b["h"]), "revoke A's attachment")
        self._refused(self.client.get(f"/api/e2ee/devices/{a['dev']}/prekey-count", headers=b["h"]), "A's prekey count")
        self._refused(self.client.post(f"/api/e2ee/devices/{a['dev']}/revoke", headers=b["h"]), "revoke A's device")
        # Reading A<->C messages with B's own device returns only B's (empty) conversation with C
        r = self.client.get(f"/api/e2ee/dm/messages?peer_user_id={c['uid']}&device_id={b['dev']}", headers=b["h"])
        if r.status_code == 200:
            self.assertNotIn(ids["dm"], {m["message_id"] for m in r.json()["messages"]})
        # B cannot read using A's device id
        r = self.client.get(f"/api/e2ee/dm/messages?peer_user_id={c['uid']}&device_id={a['dev']}", headers=b["h"])
        self._refused(r, "read DMs with A's device id")
        # A's device still active
        self.assertEqual(e2ee_db.get_device(a["dev"])["status"], "active")

    def test_outsider_cannot_read_someone_elses_support_thread_or_payments(self):
        a, b, c, ids = self._world()
        t = ids["thread"]
        self.assertTrue(t)
        self._refused(self.client.get(f"/api/platform/support/threads/{t}", headers=b["h"]), "read A's support thread")
        self._refused(self.client.post(f"/api/platform/support/threads/{t}/messages", headers=b["h"],
                                       json={"content": "intrude"}), "post in A's support thread")
        mine = self.client.get("/api/platform/support/threads", headers=b["h"])
        self.assertEqual(mine.status_code, 200)
        self.assertNotIn(t, str(mine.json()))
        hist = self.client.get("/api/platform/payments/history", headers=b["h"])
        self.assertEqual(hist.status_code, 200)
        self.assertNotIn(a["uid"], str(hist.json()))

    def test_owner_reaches_the_same_endpoints(self):
        """Positive control: the refusals above are real refusals, not mistyped URLs."""
        a, _, c, ids = self._world()
        g = ids["gid"]
        for path in (
            f"/api/e2ee/groups/{g}/messages",
            f"/api/e2ee/groups/{g}/commits",
            f"/api/e2ee/groups/{g}",
            f"/api/platform/groups/{g}/join-requests",
            f"/api/e2ee/conversations/state?scope_type=group&group_id={g}",
            f"/api/e2ee/attachments/{ids['att']}",
            f"/api/e2ee/devices/{a['dev']}/prekey-count",
            f"/api/platform/support/threads/{ids['thread']}",
        ):
            r = self.client.get(path, headers=a["h"])
            self.assertEqual(r.status_code, 200, f"owner {path} -> {r.status_code}: {r.text[:200]}")
        r = self.client.get(f"/api/e2ee/dm/messages?peer_user_id={a['uid']}&device_id={c['dev']}", headers=c["h"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn(ids["dm"], {m["message_id"] for m in r.json()["messages"]})

    def test_members_cannot_call_admin_endpoints(self):
        _, b, _, _ = self._world()
        for path in ("/api/platform/admin/overview", "/api/platform/admin/users", "/api/platform/admin/payments"):
            r = self.client.get(path, headers=b["h"])
            self.assertIn(r.status_code, (401, 403, 404), f"{path} -> {r.status_code}")


if __name__ == "__main__":
    unittest.main()
