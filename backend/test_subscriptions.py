"""Monthly / yearly subscriptions: platform membership and paid groups."""
import os
import sys
import secrets
import unittest
from datetime import timedelta
from unittest.mock import patch

os.environ["TESTING"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web3 import Web3
from eth_account import Account

import platform_db
from test_paid_membership_and_groups import TestPaidMembershipAndGroups as _Base, AUTH_DESTINATION


class TestSubscriptions(_Base):
    """Reuses the paid-membership fixtures (sqlite, SIWE login helpers, admin/group helpers)."""

    # the inherited tests are run by their own class; only run ours here
    def _pay(self, headers, acc, eth, period="monthly", ref=None, purpose="platform_entry", group_id=None, chain=1):
        body = {"transaction_reference": ref or ("0x" + secrets.token_hex(32)), "chain_id": chain,
                "purpose": purpose, "billing_period": period}
        if group_id:
            body["group_id"] = group_id
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(acc.address, eth)):
            return self.client.post("/api/platform/payments/verify", headers=headers, json=body)

    def _expire(self, uid, scope_type="platform", scope_id="platform"):
        past = (platform_db._now() - timedelta(days=1)).isoformat()
        with platform_db.chat_db._sqlite_lock:
            platform_db.chat_db._sqlite_conn.execute(
                "UPDATE member_subscriptions SET paid_until = ? WHERE user_id = ? AND scope_type = ? AND scope_id = ?",
                (past, uid, scope_type, scope_id))
            platform_db.chat_db._sqlite_conn.commit()
        platform_db.auth_cache.invalidate_all()

    def test_plans_monthly_and_yearly(self):
        self._enable_paywall(usd=10, rate=2500.0)
        platform_db.update_platform_settings({"platform_yearly_fee_usd": 0}, actor_user_id="t")
        p = self.client.get("/api/platform/pricing").json()
        self.assertEqual(p["plans"]["monthly"]["usd"], 10.0)
        self.assertEqual(p["plans"]["monthly"]["eth"], "0.004")
        self.assertEqual(p["plans"]["yearly"]["usd"], 120.0)      # automatic: 12 x monthly
        self.assertEqual(p["plans"]["yearly"]["eth"], "0.048")
        self.assertTrue(p["yearly_is_auto"])
        self.assertEqual((p["plans"]["monthly"]["days"], p["plans"]["yearly"]["days"]), (30, 365))
        platform_db.update_platform_settings({"platform_yearly_fee_usd": 100}, actor_user_id="t")
        p = self.client.get("/api/platform/pricing").json()
        self.assertEqual(p["plans"]["yearly"]["usd"], 100.0)      # admin-set yearly discount
        self.assertFalse(p["yearly_is_auto"])
        platform_db.update_platform_settings({"platform_yearly_fee_usd": 0}, actor_user_id="t")

    def test_monthly_then_yearly_extend_access_and_expiry_blocks(self):
        self._enable_paywall(usd=10, rate=2500.0)
        platform_db.update_platform_settings({"platform_yearly_fee_usd": 0}, actor_user_id="t")
        acc = Account.create()
        d = self._siwe_login(acc)
        uid = d["user"]["user_id"]
        h = {"Authorization": f"Bearer {d['session_token']}"}
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=h).status_code, 402)

        # Monthly payment -> ~30 days
        r = self._pay(h, acc, "0.004", "monthly")
        self.assertTrue(r.json()["success"], r.text)
        sub = r.json()["subscription"]
        self.assertEqual(sub["last_period"], "monthly")
        self.assertTrue(sub["active"])
        days = (platform_db._to_dt(sub["paid_until"]) - platform_db._now()).days
        self.assertIn(days, (29, 30))
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=h).status_code, 200)

        # Paying yearly on top STACKS (30 + 365 days), nothing is lost
        r = self._pay(h, acc, "0.048", "yearly")
        self.assertTrue(r.json()["success"], r.text)
        days = (platform_db._to_dt(r.json()["subscription"]["paid_until"]) - platform_db._now()).days
        self.assertTrue(393 <= days <= 395, days)

        # Status endpoint shows the expiry
        st = self.client.get("/api/platform/membership/status", headers=h).json()
        self.assertTrue(st["is_platform_paid"])
        self.assertIsNotNone(st["platform_paid_until"])

    def test_yearly_needs_the_yearly_amount(self):
        self._enable_paywall(usd=10, rate=2500.0)
        platform_db.update_platform_settings({"platform_yearly_fee_usd": 0}, actor_user_id="t")
        acc = Account.create()
        d = self._siwe_login(acc)
        h = {"Authorization": f"Bearer {d['session_token']}"}
        # A MONTHLY-sized payment must not buy a YEAR
        r = self._pay(h, acc, "0.004", "yearly")
        self.assertFalse(r.json()["success"])
        self.assertIn("Insufficient", r.json()["reason"])
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=h).status_code, 402)

    def test_expired_subscription_is_locked_out_until_renewed(self):
        self._enable_paywall(usd=10, rate=2500.0)
        acc = Account.create()
        d = self._siwe_login(acc)
        uid = d["user"]["user_id"]
        h = {"Authorization": f"Bearer {d['session_token']}"}
        self.assertTrue(self._pay(h, acc, "0.004", "monthly").json()["success"])
        self.assertTrue(platform_db.has_active_subscription(uid, "platform", "platform"))
        self._expire(uid)
        self.assertFalse(platform_db.has_active_subscription(uid, "platform", "platform"))
        sub = platform_db.get_subscription(uid, "platform", "platform")
        self.assertFalse(sub["active"])
        # renewing after expiry starts from NOW (not from the old date)
        self.assertTrue(self._pay(h, acc, "0.004", "monthly").json()["success"])
        sub = platform_db.get_subscription(uid, "platform", "platform")
        self.assertTrue(sub["active"])
        self.assertIn((platform_db._to_dt(sub["paid_until"]) - platform_db._now()).days, (29, 30))

    def test_same_payment_is_never_credited_twice(self):
        self._enable_paywall(usd=10, rate=2500.0)
        acc = Account.create()
        d = self._siwe_login(acc)
        uid = d["user"]["user_id"]
        h = {"Authorization": f"Bearer {d['session_token']}"}
        ref = "0x" + "ab" * 32
        self.assertTrue(self._pay(h, acc, "0.004", "monthly", ref=ref).json()["success"])
        until1 = platform_db.get_subscription(uid, "platform", "platform")["paid_until"]
        r2 = self._pay(h, acc, "0.004", "monthly", ref=ref)
        self.assertTrue(r2.json().get("already_verified"))
        self.assertEqual(platform_db.get_subscription(uid, "platform", "platform")["paid_until"], until1)

    def test_bad_billing_period_rejected(self):
        self._enable_paywall(usd=10, rate=2500.0)
        acc = Account.create()
        d = self._siwe_login(acc)
        h = {"Authorization": f"Bearer {d['session_token']}"}
        r = self._pay(h, acc, "0.004", "weekly")
        self.assertEqual(r.status_code, 422)

    def test_admin_retry_cannot_credit_an_underpayment(self):
        """Regression: the admin retry button used to credit ANY amount (even 1 wei)."""
        self._enable_paywall(usd=10, rate=2500.0)
        _, admin_data, admin_h, _ = self._make_admin()
        acc = Account.create()
        d = self._siwe_login(acc)
        uid = d["user"]["user_id"]
        h = {"Authorization": f"Bearer {d['session_token']}"}
        ref = "0x" + "cd" * 32
        # first look: transaction not mined yet -> pending, requirement stored on the record
        pending = {"status": "pending", "reason": "Awaiting confirmation"}
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=pending):
            self.client.post("/api/platform/payments/verify", headers=h, json={
                "transaction_reference": ref, "chain_id": 1, "purpose": "platform_entry", "billing_period": "monthly"})
        rec = platform_db.get_payment_by_tx_ref(ref)
        self.assertEqual(int(rec["metadata"]["required_wei"]) > 0, True)
        # admin retries; the chain now shows a 1 wei transfer
        tiny = self._tx_result(acc.address, "0.000000000000000001")
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=tiny):
            r = self.client.post(f"/api/platform/admin/payments/{rec['payment_id']}/retry", headers=admin_h)
        self.assertFalse(r.json()["success"], r.text)
        self.assertFalse(platform_db.has_active_subscription(uid, "platform", "platform"))

    def test_paid_group_monthly_yearly_and_lapse(self):
        self._enable_paywall(usd=0, rate=2000.0)  # platform free; group paid
        _, admin_data, admin_h, admin_dev = self._make_admin()
        g = self._create_group(admin_h, admin_dev, is_paid=True, entry_fee_usd=20, visibility="public")
        gid = g.json()["group"]["group_id"]
        # yearly defaults to 12 x monthly
        gp = platform_db.get_group_pricing(gid)
        self.assertEqual((gp["plans"]["monthly"]["usd"], gp["plans"]["yearly"]["usd"]), (20.0, 240.0))
        self.assertEqual((gp["plans"]["monthly"]["eth"], gp["plans"]["yearly"]["eth"]), ("0.01", "0.12"))
        # admin sets a yearly discount through the policy endpoint
        policy = {"description": "x", "visibility": "public", "require_invitation": False,
                  "is_paid": True, "entry_fee_usd": 20, "entry_fee_yearly_usd": 200}
        up = self.client.put(f"/api/platform/groups/{gid}/policy", headers=admin_h, json=policy)
        self.assertEqual(up.status_code, 200, up.text)
        self.assertEqual(platform_db.get_group_pricing(gid)["plans"]["yearly"]["usd"], 200.0)
        self.assertEqual(platform_db.get_group_pricing(gid)["plans"]["yearly"]["eth"], "0.1")

        acc = Account.create()
        c = self._siwe_login(acc)
        uid = c["user"]["user_id"]
        ch = {"Authorization": f"Bearer {c['session_token']}"}
        self.assertFalse(platform_db.verify_user_meets_group_policy(gid, uid)[0])
        # monthly amount does not buy the yearly plan
        r = self._pay(ch, acc, "0.01", "yearly", purpose="group_entry", group_id=gid)
        self.assertFalse(r.json()["success"])
        # yearly amount buys 365 days
        r = self._pay(ch, acc, "0.1", "yearly", purpose="group_entry", group_id=gid)
        self.assertTrue(r.json()["success"], r.text)
        self.assertEqual(r.json()["subscription"]["last_period"], "yearly")
        self.assertTrue(platform_db.verify_user_meets_group_policy(gid, uid)[0])
        self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-request", headers=ch).status_code, 200)
        # status endpoint lists the group subscription
        st = self.client.get("/api/platform/membership/status", headers=ch).json()
        self.assertEqual([s["group_id"] for s in st["group_subscriptions"]], [gid])
        # lapse -> blocked again; renew -> back
        self._expire(uid, "group", gid)
        self.assertFalse(platform_db.verify_user_meets_group_policy(gid, uid)[0])
        r = self._pay(ch, acc, "0.01", "monthly", purpose="group_entry", group_id=gid)
        self.assertTrue(r.json()["success"], r.text)
        self.assertTrue(platform_db.verify_user_meets_group_policy(gid, uid)[0])

    def test_group_owner_cannot_change_yearly_price(self):
        self._enable_paywall(usd=0, rate=2000.0)
        _, admin_data, admin_h, admin_dev = self._make_admin()
        g = self._create_group(admin_h, admin_dev, is_paid=True, entry_fee_usd=20, visibility="public")
        gid = g.json()["group"]["group_id"]
        before = platform_db.get_group_access_policy(gid)["entry_fee_yearly_usd"]
        policy = {"description": "x", "visibility": "public", "require_invitation": False,
                  "is_paid": True, "entry_fee_usd": 20, "entry_fee_yearly_usd": 1}
        # superadmin console path is allowed; a plain owner is ignored (covered by existing price-lock tests)
        self.client.put(f"/api/platform/groups/{gid}/policy", headers=admin_h, json=policy)
        self.assertNotEqual(before, platform_db.get_group_access_policy(gid)["entry_fee_yearly_usd"])


if __name__ == "__main__":
    unittest.main()
