"""
Free access granted by an admin (no payment needed).

Covers:
- A platform grant opens a paywalled membership; revoking it closes it AGAIN IMMEDIATELY
  (the 30 s "paid" cache must not keep a revoked member inside).
- Timed grants end by themselves; "no end date" grants last until revoked.
- Only a superadmin can grant / revoke; a moderator can only look.
- A group grant waives that group's fee AND minimum-balance rule, opens invite-only groups to a
  join request, and lets a group admin add the member. A suspended account is still blocked.
- Grants are scoped: one group's grant does not open another; a membership grant does not pay for groups.
- Grants never count as paying members, never show the admin's note to the member, are audited,
  and disappear with a deleted group.
"""
import base64
import os
import secrets
import sys
import unittest

os.environ["TESTING"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import timedelta
from eth_account import Account

import e2ee_routes
import platform_db
from test_paid_membership_and_groups import TestPaidMembershipAndGroups as _Base
from test_e2ee_security import generate_signed_test_device


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class _Fixtures(unittest.TestCase):
    """The paywall fixtures (sqlite, wallet sign-in, admin / group helpers) without their tests."""

    __test__ = False  # not a test class itself


for _name in ("setUpClass", "tearDownClass", "setUp", "_enable_paywall", "_tx_result", "_siwe_login",
              "_make_admin", "_create_group"):
    setattr(_Fixtures, _name, _Base.__dict__[_name])
del _Base  # keeps the paywall tests from being collected a second time from this module


class TestAccessGrants(_Fixtures):
    __test__ = True

    def setUp(self):
        super().setUp()
        e2ee_routes._rate_buckets.clear()
        platform_db.auth_cache.invalidate_all()

    # ------------------------------------------------------------------ helpers
    def _admin(self):
        _, data, h, dev = self._make_admin()
        self.client.cookies.clear()
        return {"uid": data["user"]["user_id"], "h": h, "dev": dev}

    def _member(self):
        acc = Account.create()
        data = self._siwe_login(acc)
        self.client.cookies.clear()
        uid = data["user"]["user_id"]
        h = {"Authorization": f"Bearer {data['session_token']}"}
        dev = f"dev_m_{secrets.token_hex(5)}"
        bundle, _ = generate_signed_test_device(uid, dev)
        r = self.client.post("/api/e2ee/devices/register", json=bundle, headers=h)
        self.assertEqual(r.status_code, 200, r.text)
        return {"uid": uid, "h": h, "dev": dev, "acc": acc}

    def _grant(self, admin, member, scope="platform", group_id=None, days=None, note=""):
        body = {"user_id": member["uid"], "scope_type": scope, "days": days, "note": note}
        if group_id:
            body["group_id"] = group_id
        return self.client.post("/api/platform/admin/access-grants", headers=admin["h"], json=body)

    def _revoke(self, admin, member, scope="platform", group_id=None):
        body = {"user_id": member["uid"], "scope_type": scope}
        if group_id:
            body["group_id"] = group_id
        return self.client.post("/api/platform/admin/access-grants/revoke", headers=admin["h"], json=body)

    def _room(self, member):
        return self.client.get("/api/platform/public-chat/messages", headers=member["h"]).status_code

    def _expire_grant(self, uid, scope_type="platform", scope_id="platform"):
        past = (platform_db._now() - timedelta(days=1)).isoformat()
        with platform_db.chat_db._sqlite_lock:
            platform_db.chat_db._sqlite_conn.execute(
                "UPDATE access_grants SET expires_at = ? WHERE user_id = ? AND scope_type = ? AND scope_id = ?",
                (past, uid, scope_type, scope_id))
            platform_db.chat_db._sqlite_conn.commit()
        platform_db.auth_cache.invalidate_all()

    def _paid_group(self, admin, fee=20, visibility="public", **extra):
        r = self._create_group(admin["h"], admin["dev"], is_paid=True, entry_fee_usd=fee, visibility=visibility, **extra)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["group"]["group_id"]

    def _add(self, admin, gid, target):
        epoch = platform_db.e2ee_db.get_mls_group(gid)["current_epoch"]
        return self.client.post(
            f"/api/e2ee/groups/{gid}/commits", headers=admin["h"],
            json={
                "committer_device_id": admin["dev"], "expected_epoch": epoch, "commit_type": "add",
                "mls_commit_b64": _b64(secrets.token_bytes(96)),
                "added_members": [{"user_id": target["uid"], "device_id": target["dev"], "role": "member"}],
                "welcomes": [{"target_user_id": target["uid"], "target_device_id": target["dev"],
                              "mls_welcome_b64": _b64(secrets.token_bytes(120))}],
            })

    def _send(self, gid, member):
        epoch = platform_db.e2ee_db.get_mls_group(gid)["current_epoch"]
        return self.client.post(f"/api/e2ee/groups/{gid}/messages", headers=member["h"], json={
            "message_id": "msg_" + secrets.token_hex(8), "epoch": epoch, "sender_device_id": member["dev"],
            "mls_ciphertext_b64": _b64(secrets.token_bytes(40)), "attachment_ids": []})

    # ------------------------------------------------------------------ platform membership
    def test_platform_grant_opens_membership_and_revoke_closes_it_at_once(self):
        self._enable_paywall(usd=10)
        admin, m = self._admin(), self._member()
        self.assertEqual(self._room(m), 402)  # not paid

        r = self._grant(admin, m, note="friend of the club")
        self.assertEqual(r.status_code, 200, r.text)
        g = r.json()["grant"]
        self.assertTrue(g["active"] and g["lifetime"] and g["expires_at"] is None)

        self.assertEqual(self._room(m), 200)  # in
        self.assertEqual(self._room(m), 200)  # (this one is served from the 30 s cache)
        st = self.client.get("/api/platform/membership/status", headers=m["h"]).json()
        self.assertTrue(st["is_platform_paid"])
        self.assertEqual(st["platform_free_access"], {"expires_at": None, "lifetime": True})
        self.assertIsNone(st["platform_paid_until"])  # nothing was paid
        self.assertNotIn("friend of the club", str(st))  # the admin's private note is never shown

        # Revoke: the cached "paid" answer must not keep them inside.
        self.assertEqual(self._revoke(admin, m).status_code, 200)
        self.assertEqual(self._room(m), 402)
        st = self.client.get("/api/platform/membership/status", headers=m["h"]).json()
        self.assertFalse(st["is_platform_paid"])
        self.assertIsNone(st["platform_free_access"])
        # Nothing active left to revoke
        self.assertEqual(self._revoke(admin, m).status_code, 404)

    def test_grant_is_a_gift_not_a_payment(self):
        self._enable_paywall(usd=10)
        admin, m = self._admin(), self._member()
        before = self.client.get("/api/platform/admin/overview", headers=admin["h"]).json()["stats"]["paid_members"]
        self.assertEqual(self._grant(admin, m).status_code, 200)
        after = self.client.get("/api/platform/admin/overview", headers=admin["h"]).json()["stats"]["paid_members"]
        self.assertEqual(before, after)  # revenue numbers stay honest
        self.assertIsNone(platform_db.get_subscription(m["uid"], "platform", "platform"))
        self.assertEqual(platform_db.list_user_payment_records(m["uid"]), [])

    def test_timed_grant_ends_by_itself_and_regrant_replaces_it(self):
        self._enable_paywall(usd=10)
        admin, m = self._admin(), self._member()
        r = self._grant(admin, m, days=30)
        g = r.json()["grant"]
        self.assertFalse(g["lifetime"])
        self.assertIsNotNone(g["expires_at"])
        self.assertEqual(self._room(m), 200)

        self._expire_grant(m["uid"])
        self.assertEqual(self._room(m), 402)  # ran out
        st = self.client.get("/api/platform/membership/status", headers=m["h"]).json()
        self.assertIsNone(st["platform_free_access"])

        # Granting again switches it back on with the new length (one row, no duplicates)
        self.assertEqual(self._grant(admin, m, days=365).status_code, 200)
        self.assertEqual(self._room(m), 200)
        rows = platform_db.admin_list_access_grants(user_id=m["uid"], include_inactive=True)
        self.assertEqual(len(rows), 1)

        # Revoked, then granted again, works too
        self._revoke(admin, m)
        self.assertEqual(self._room(m), 402)
        self.assertEqual(self._grant(admin, m).status_code, 200)
        self.assertEqual(self._room(m), 200)

    def test_real_payment_still_works_alongside_a_grant(self):
        self._enable_paywall(usd=10)
        admin, m = self._admin(), self._member()
        self._grant(admin, m)
        from unittest.mock import patch
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(m["acc"].address, "0.004")):
            r = self.client.post("/api/platform/payments/verify", headers=m["h"], json={
                "transaction_reference": "0x" + secrets.token_hex(32), "chain_id": 1, "purpose": "platform_entry"})
        self.assertTrue(r.json()["success"], r.text)
        self._revoke(admin, m)  # the gift ends, the paid month stays
        self.assertEqual(self._room(m), 200)

    # ------------------------------------------------------------------ who may grant
    def test_only_superadmin_grants_moderator_can_look(self):
        self._enable_paywall(usd=10)
        admin, m, other = self._admin(), self._member(), self._member()
        mod = self._member()
        platform_db.set_admin_role(mod["uid"], "moderator", actor_user_id="system")
        body = {"user_id": m["uid"], "scope_type": "platform"}
        url = "/api/platform/admin/access-grants"

        self.assertEqual(self.client.post(url, json=body).status_code, 401)  # nobody signed in
        self.assertEqual(self.client.post(url, headers=other["h"], json=body).status_code, 403)  # a member
        self.assertEqual(self.client.post(url, headers=mod["h"], json=body).status_code, 403)  # a moderator
        self.assertEqual(self._room(m), 402)

        self.assertEqual(self._grant(admin, m).status_code, 200)
        self.assertEqual(self.client.post(url + "/revoke", headers=mod["h"], json=body).status_code, 403)
        self.assertEqual(self._room(m), 200)

        listing = self.client.get(f"{url}?user_id={m['uid']}", headers=mod["h"])  # moderators may look
        self.assertEqual(listing.status_code, 200)
        self.assertEqual([g["user_id"] for g in listing.json()["grants"]], [m["uid"]])
        self.assertEqual(self.client.get(url, headers=other["h"]).status_code, 403)

    def test_input_is_validated(self):
        admin, m = self._admin(), self._member()
        url = "/api/platform/admin/access-grants"
        ok = {"user_id": m["uid"], "scope_type": "platform"}
        self.assertEqual(self.client.post(url, headers=admin["h"], json={**ok, "user_id": "usr_doesnotexist"}).status_code, 404)
        self.assertEqual(self.client.post(url, headers=admin["h"], json={**ok, "scope_type": "group"}).status_code, 400)  # no group
        self.assertEqual(self.client.post(url, headers=admin["h"],
                                          json={**ok, "scope_type": "group", "group_id": "grp_nope"}).status_code, 404)
        for bad_days in (0, -5, 3651, 1.5):
            self.assertEqual(self.client.post(url, headers=admin["h"], json={**ok, "days": bad_days}).status_code, 422, bad_days)
        self.assertEqual(self.client.post(url, headers=admin["h"], json={**ok, "scope_type": "everything"}).status_code, 422)
        self.assertEqual(self.client.post(url, headers=admin["h"], json={**ok, "note": "x" * 201}).status_code, 422)
        self.assertEqual(self.client.post(url, headers=admin["h"], json={**ok, "sneaky": 1}).status_code, 422)
        # Control characters in a note are cleaned, not stored
        r = self.client.post(url, headers=admin["h"], json={**ok, "note": "a\x00b\x07c  "})
        self.assertEqual(r.json()["grant"]["note"], "abc")

    # ------------------------------------------------------------------ groups
    def test_group_grant_waives_the_fee_and_lets_a_group_admin_add_the_member(self):
        self._enable_paywall(usd=0)  # membership free; the group is paid
        admin, m = self._admin(), self._member()
        gid = self._paid_group(admin, fee=20)

        # Without a grant: not eligible, join refused with 402, and an admin cannot add them either.
        self.assertFalse(platform_db.verify_user_meets_group_policy(gid, m["uid"])[0])
        self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"]).status_code, 402)
        self.assertEqual(self._add(admin, gid, m).status_code, 403)

        self.assertEqual(self._grant(admin, m, scope="group", group_id=gid, note="vip").status_code, 200)
        self.assertTrue(platform_db.verify_user_meets_group_policy(gid, m["uid"])[0])
        gp = self.client.get(f"/api/platform/groups/{gid}/pricing", headers=m["h"]).json()
        self.assertTrue(gp["has_paid"])
        disc = self.client.get("/api/platform/groups/discover", headers=m["h"]).json()["groups"]
        entry = next(x for x in disc if x["group_id"] == gid)
        self.assertTrue(entry["eligible"] and entry["has_paid"])
        st = self.client.get("/api/platform/membership/status", headers=m["h"]).json()
        self.assertEqual([x["group_id"] for x in st["group_free_access"]], [gid])
        self.assertEqual(st["group_subscriptions"], [])  # still not a payment

        # The group admin adds them; they get the invitation (consent is kept), accept, and can read.
        add = self._add(admin, gid, m)
        self.assertEqual(add.status_code, 200, add.text)
        acc = self.client.post(f"/api/e2ee/groups/{gid}/invitation/accept", headers=m["h"])
        self.assertEqual(acc.status_code, 200, acc.text)
        self.assertEqual(self.client.get(f"/api/e2ee/groups/{gid}/messages", headers=m["h"]).status_code, 200)

        # They can send while the grant is on.
        self.assertEqual(self._send(gid, m).status_code, 200)

        # Revoke: reading AND sending are closed again, both with 402 + the group's id and name
        # (sending used to answer 403, so the app never offered to renew).
        self.assertEqual(self._revoke(admin, m, scope="group", group_id=gid).status_code, 200)
        self.assertEqual(self.client.get(f"/api/e2ee/groups/{gid}/messages", headers=m["h"]).status_code, 402)
        sent = self._send(gid, m)
        self.assertEqual(sent.status_code, 402, sent.text)
        self.assertEqual(sent.json()["detail"]["code"], "group_payment_required")
        self.assertEqual(sent.json()["detail"]["group_id"], gid)
        self.assertEqual(sent.json()["detail"]["group_name"], "VIP Alpha Traders")
        self.assertFalse(platform_db.verify_user_meets_group_policy(gid, m["uid"])[0])

    def test_group_grant_waives_minimum_balance_but_not_a_suspension(self):
        self._enable_paywall(usd=0)
        admin, m = self._admin(), self._member()
        r = self._create_group(admin["h"], admin["dev"], visibility="public",
                               min_eth_balance_wei="1000000000000000000")  # needs 1 ETH verified
        self.assertEqual(r.status_code, 200, r.text)
        gid = r.json()["group"]["group_id"]
        ok, reason = platform_db.verify_user_meets_group_policy(gid, m["uid"])
        self.assertFalse(ok)
        self.assertIn("balance", reason)

        self._grant(admin, m, scope="group", group_id=gid)
        self.assertTrue(platform_db.verify_user_meets_group_policy(gid, m["uid"])[0])
        disc = self.client.get("/api/platform/groups/discover", headers=m["h"]).json()["groups"]
        self.assertTrue(next(x for x in disc if x["group_id"] == gid)["eligible"])

        # A suspended account stays out whatever it was granted
        platform_db.admin_moderate_user_account(m["uid"], "suspend", "test", admin["uid"], None)
        ok, reason = platform_db.verify_user_meets_group_policy(gid, m["uid"])
        self.assertFalse(ok)
        self.assertIn("suspended", reason.lower())

    def test_group_grant_lets_a_member_ask_to_join_an_invite_only_group(self):
        self._enable_paywall(usd=0)
        admin, m = self._admin(), self._member()
        r = self._create_group(admin["h"], admin["dev"], visibility="invite_only")
        gid = r.json()["group"]["group_id"]
        self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"]).status_code, 403)
        self._grant(admin, m, scope="group", group_id=gid)
        self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"]).status_code, 200)

    def test_grants_are_scoped(self):
        self._enable_paywall(usd=10)
        admin, m = self._admin(), self._member()
        # a group grant is not a membership
        self._enable_paywall(usd=0)
        gid_a, gid_b = self._paid_group(admin, fee=20), self._paid_group(admin, fee=30)
        self._enable_paywall(usd=10)
        self._grant(admin, m, scope="group", group_id=gid_a)
        self.assertEqual(self._room(m), 402)
        # a group grant opens that group only
        self._enable_paywall(usd=0)
        self.assertTrue(platform_db.verify_user_meets_group_policy(gid_a, m["uid"])[0])
        self.assertFalse(platform_db.verify_user_meets_group_policy(gid_b, m["uid"])[0])
        # a membership grant does not pay for a group
        self._enable_paywall(usd=10)
        self._grant(admin, m)
        self.assertEqual(self._room(m), 200)
        self.assertFalse(platform_db.verify_user_meets_group_policy(gid_b, m["uid"])[0])

    def test_deleting_a_group_removes_its_grants(self):
        self._enable_paywall(usd=0)
        admin, m = self._admin(), self._member()
        gid = self._paid_group(admin)
        self._grant(admin, m, scope="group", group_id=gid)
        self.assertEqual(len(platform_db.admin_list_access_grants(scope_type="group", scope_id=gid)), 1)
        r = self.client.delete(f"/api/platform/admin/groups/{gid}", headers=admin["h"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(platform_db.admin_list_access_grants(scope_type="group", scope_id=gid), [])

    # ------------------------------------------------------------------ records
    def test_listing_names_people_and_groups_and_everything_is_audited(self):
        self._enable_paywall(usd=0)
        admin, m = self._admin(), self._member()
        gid = self._paid_group(admin)
        self._grant(admin, m, note="vip", days=10)
        self._grant(admin, m, scope="group", group_id=gid)
        mine = f"/api/platform/admin/access-grants?user_id={m['uid']}"  # tests share one database
        rows = self.client.get(mine, headers=admin["h"]).json()["grants"]
        self.assertEqual({(g["scope_type"], g["group_name"]) for g in rows}, {("platform", None), ("group", "VIP Alpha Traders")})
        self.assertTrue(all(g["granted_by"] == admin["uid"] for g in rows))
        only_group = self.client.get(f"/api/platform/admin/access-grants?scope_type=group&group_id={gid}",
                                     headers=admin["h"]).json()["grants"]
        self.assertEqual(len(only_group), 1)

        self._revoke(admin, m)
        active = self.client.get(mine, headers=admin["h"]).json()["grants"]
        self.assertEqual([g["scope_type"] for g in active], ["group"])
        everything = self.client.get(mine + "&include_inactive=true", headers=admin["h"]).json()["grants"]
        self.assertEqual(len(everything), 2)

        logs = platform_db.list_audit_logs(limit=50)
        logs = logs["logs"] if isinstance(logs, dict) else logs
        actions = [(l["action"], l["entity_id"]) for l in logs]
        self.assertIn(("access_granted", m["uid"]), actions)
        self.assertIn(("access_revoked", m["uid"]), actions)


if __name__ == "__main__":
    unittest.main()
