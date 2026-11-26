"""Regression tests for the group join / policy wiring fixes (audit round, Nov 2026)."""
import os
import sys
import secrets
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from eth_account import Account

import platform_db
from test_e2ee_security import generate_signed_test_device
from test_paid_membership_and_groups import TestPaidMembershipAndGroups as _Base


class TestGroupJoinFixes(_Base):
    def _member(self):
        acc = Account.create()
        d = self._siwe_login(acc)
        h = {"Authorization": f"Bearer {d['session_token']}"}
        dev = f"dev_m_{secrets.token_hex(4)}"
        b, _ = generate_signed_test_device(d["user"]["user_id"], dev)
        self.client.post("/api/e2ee/devices/register", json=b, headers=h)
        return acc, d["user"]["user_id"], h

    def test_superadmin_saving_description_keeps_group_paid(self):
        """The in-app Access Policy form sends no is_paid; that must not turn a paid group free."""
        self._enable_paywall(usd=0, rate=2000.0)
        _, _, admin_h, admin_dev = self._make_admin()
        g = self._create_group(admin_h, admin_dev, is_paid=True, entry_fee_usd=20, visibility="public")
        gid = g.json()["group"]["group_id"]
        r = self.client.put(f"/api/platform/groups/{gid}/policy", headers=admin_h, json={
            "description": "New rules", "visibility": "public", "min_eth_balance_eth": "0", "require_invitation": False})
        self.assertEqual(r.status_code, 200, r.text)
        pol = platform_db.get_group_access_policy(gid)
        self.assertTrue(pol["is_paid"])
        self.assertEqual(float(pol["entry_fee_usd"]), 20.0)
        self.assertEqual(pol["description"], "New rules")
        # Explicitly making it free still works
        r = self.client.put(f"/api/platform/groups/{gid}/policy", headers=admin_h, json={
            "description": "Free now", "visibility": "public", "require_invitation": False, "is_paid": False})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(platform_db.get_group_access_policy(gid)["is_paid"])

    def test_invite_links_are_removed(self):
        """Invite links are gone: creating, listing, revoking and redeeming all answer 410 with a clear message.
        People join when a group admin adds them and they press Accept (or via a public join request)."""
        _, _, admin_h, admin_dev = self._make_admin()
        gid = self._create_group(admin_h, admin_dev).json()["group"]["group_id"]
        _, _, h = self._member()
        for method, url, who in (
            ("post", f"/api/platform/groups/{gid}/invites", admin_h),
            ("get", f"/api/platform/groups/{gid}/invites", admin_h),
            ("delete", f"/api/platform/groups/{gid}/invites/abc123", admin_h),
            ("post", "/api/platform/groups/join-by-invite/abc123", h),
        ):
            r = getattr(self.client, method)(url, headers=who) if method != "post" else self.client.post(url, headers=who, json={})
            self.assertEqual(r.status_code, 410, url)
            self.assertIn("Invite links have been removed", r.json()["detail"])

    def test_group_admin_can_decline_a_join_request(self):
        _, _, admin_h, admin_dev = self._make_admin()
        g = self._create_group(admin_h, admin_dev, visibility="public")
        gid = g.json()["group"]["group_id"]
        _, uid, h = self._member()
        req = self.client.post(f"/api/platform/groups/{gid}/join-request", headers=h)
        self.assertEqual(req.status_code, 200, req.text)
        rid = req.json()["request_id"]

        # A non-admin member cannot decline
        _, _, other_h = self._member()
        self.assertIn(self.client.post(f"/api/platform/groups/{gid}/join-requests/{rid}/decline",
                                       headers=other_h).status_code, (403, 404))

        r = self.client.post(f"/api/platform/groups/{gid}/join-requests/{rid}/decline", headers=admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        pending = self.client.get(f"/api/platform/groups/{gid}/join-requests", headers=admin_h).json()["requests"]
        self.assertFalse(any(p["request_id"] == rid for p in pending))
        # Declining twice -> 404; the member may ask again later
        self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-requests/{rid}/decline",
                                          headers=admin_h).status_code, 404)
        self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-request", headers=h).status_code, 200)


if __name__ == "__main__":
    unittest.main()