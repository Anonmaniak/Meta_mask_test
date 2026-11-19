"""
Focused Test Suite for Direct Platform Admission Paywall, Admin-Controlled ETH/USD Pricing, and Paid Groups.
"""

import os
import sys
import secrets
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from fastapi.testclient import TestClient
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

from app import app
import chat_db
import e2ee_db
import platform_db
from test_e2ee_security import generate_signed_test_device, _b64

AUTH_DESTINATION = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"


class TestPaidMembershipAndGroups(unittest.TestCase):
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
        platform_db.update_platform_settings(
            {
                "authorized_payment_destination": AUTH_DESTINATION,
                "platform_entry_fee_usd": 0,  # membership free by default; paywall tests switch it on
                "use_live_eth_price": False,  # never hit the network in tests
                "eth_usd_price": 2500.0,
            },
            actor_user_id="test_setup",
        )

    def _enable_paywall(self, usd=10, rate=2500.0):
        platform_db.update_platform_settings(
            {"platform_entry_fee_usd": usd, "use_live_eth_price": False, "eth_usd_price": rate},
            actor_user_id="test_setup",
        )

    @staticmethod
    def _tx_result(wallet, eth, tx_chain=1):
        return {
            "status": "verified",
            "wallet_address": wallet,
            "recipient_address": AUTH_DESTINATION,
            "amount_atomic": str(Web3.to_wei(eth, "ether")),
            "amount_formatted": str(eth),
            "currency": "ETH",
            "network": "ethereum",
            "chain_id": tx_chain,
            "block_number": 19500100,
            "verification_source": "ethereum_rpc",
        }

    def _siwe_login(self, account: Account) -> dict:
        c_res = self.client.post("/api/e2ee/auth/challenge", json={"wallet_address": account.address})
        self.assertEqual(c_res.status_code, 200, c_res.text)
        c_data = c_res.json()
        signable_msg = encode_defunct(text=c_data["message"])
        signed = account.sign_message(signable_msg)
        v_res = self.client.post(
            "/api/e2ee/auth/verify",
            json={
                "challenge_id": c_data["challenge_id"],
                "wallet_address": account.address,
                "signature": signed.signature.hex(),
            },
        )
        self.assertEqual(v_res.status_code, 200, v_res.text)
        return v_res.json()

    def test_01_pricing_is_set_in_usd_and_converted_to_eth(self):
        self._enable_paywall(usd=10, rate=2500.0)
        data = self.client.get("/api/platform/pricing").json()
        self.assertEqual(data["platform_entry_fee_usd"], 10.0)
        self.assertEqual(data["eth_usd_price"], 2500.0)
        self.assertEqual(data["platform_entry_fee_eth"], "0.004")  # $10 / $2500
        self.assertEqual(data["platform_entry_fee_wei"], str(Web3.to_wei("0.004", "ether")))
        self.assertEqual(data["rate_source"], "admin_fixed")
        self.assertEqual(data["authorized_payment_destination"], AUTH_DESTINATION)

        # Superadmin changes the USD price through the dedicated pricing endpoint
        admin_data = self._siwe_login(Account.create())
        platform_db.set_admin_role(admin_data["user"]["user_id"], "superadmin", actor_user_id="system")
        headers = {"Authorization": f"Bearer {admin_data['session_token']}"}
        up = self.client.put(
            "/api/platform/admin/pricing", headers=headers,
            json={"platform_entry_fee_usd": 25, "eth_usd_price": 3000.0},
        )
        self.assertEqual(up.status_code, 200, up.text)
        pr = up.json()["pricing"]
        self.assertEqual(pr["platform_entry_fee_usd"], 25.0)
        # 25 / 3000 = 0.008333... -> rounded UP to 6 decimals so it never underpays
        self.assertEqual(pr["platform_entry_fee_eth"], "0.008334")

        # The admin dashboard's generic "Save Platform Settings" must persist the fee too
        # (it used to be silently dropped by the request model).
        st = self.client.put(
            "/api/platform/admin/settings", headers=headers,
            json={"platform_entry_fee_usd": 40},
        )
        self.assertEqual(st.status_code, 200, st.text)
        self.assertEqual(self.client.get("/api/platform/pricing").json()["platform_entry_fee_usd"], 40.0)

    def test_02_server_enforces_membership_and_payment_amount(self):
        self._enable_paywall(usd=10, rate=2500.0)  # needs 0.004 ETH (>= 0.0038 with 5% tolerance)
        acc = Account.create()
        data = self._siwe_login(acc)
        headers = {"Authorization": f"Bearer {data['session_token']}"}
        self.assertFalse(data["user"].get("is_platform_paid"))

        # --- Unpaid: every premium endpoint is blocked server-side, not just in the UI
        self.client.cookies.clear()  # the login set a session cookie; test the anonymous case
        self.assertEqual(self.client.get("/api/platform/public-chat/messages").status_code, 401)
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=headers).status_code, 402)
        self.assertEqual(
            self.client.post("/api/platform/public-chat/messages", headers=headers, json={"content": "hi"}).status_code, 402)
        self.assertEqual(self.client.get("/api/platform/users/search?q=a", headers=headers).status_code, 402)
        self.assertEqual(self.client.get("/api/e2ee/dm/conversations", headers=headers).status_code, 402)
        self.assertEqual(self.client.get("/api/e2ee/groups", headers=headers).status_code, 402)
        # ...but sign-in / status / pricing stay reachable so the user can pay
        self.assertEqual(self.client.get("/api/e2ee/me", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/platform/membership/status", headers=headers).status_code, 200)

        # --- Underpayment (1 wei would previously have unlocked everything)
        tx_low = "0x" + "7a" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(acc.address, "0.001")):
            r = self.client.post("/api/platform/payments/verify", headers=headers,
                                 json={"transaction_reference": tx_low, "chain_id": 1, "purpose": "platform_entry"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["success"])
        self.assertIn("Insufficient payment", r.json()["reason"])
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=headers).status_code, 402)

        # --- Another account cannot claim or interfere with someone else's tx hash
        thief = self._siwe_login(Account.create())
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(acc.address, "0.004")):
            r = self.client.post("/api/platform/payments/verify",
                                 headers={"Authorization": f"Bearer {thief['session_token']}"},
                                 json={"transaction_reference": tx_low, "chain_id": 1, "purpose": "platform_entry"})
        self.assertEqual(r.status_code, 409, r.text)

        # --- Correct payment unlocks membership
        tx_ok = "0x" + "7b" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(acc.address, "0.004")):
            r = self.client.post("/api/platform/payments/verify", headers=headers,
                                 json={"transaction_reference": tx_ok, "chain_id": 1, "purpose": "platform_entry"})
        self.assertTrue(r.json()["success"], r.text)
        self.assertTrue(r.json()["is_platform_paid"])
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=headers).status_code, 200)
        self.assertEqual(
            self.client.post("/api/platform/public-chat/messages", headers=headers, json={"content": "hello members"}).status_code, 200)

        # --- Paid on one device, connect from another: same wallet -> verified -> no second payment
        second_device = self._siwe_login(acc)
        self.assertTrue(second_device["user"].get("is_platform_paid"))
        self.assertNotEqual(second_device["session_token"], data["session_token"])  # fresh session id
        h2 = {"Authorization": f"Bearer {second_device['session_token']}"}
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=h2).status_code, 200)

    def test_02b_price_tolerance_free_mode_and_bad_purpose(self):
        self._enable_paywall(usd=10, rate=2500.0)
        acc = Account.create()
        d = self._siwe_login(acc)
        h = {"Authorization": f"Bearer {d['session_token']}"}
        # 0.0039 ETH is within the 5% tolerance of 0.004 (ETH may move between quote and mining)
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(acc.address, "0.0039")):
            r = self.client.post("/api/platform/payments/verify", headers=h,
                                 json={"transaction_reference": "0x" + "7c" * 32, "chain_id": 1})
        self.assertTrue(r.json()["success"], r.text)

        bad = self.client.post("/api/platform/payments/verify", headers=h,
                               json={"transaction_reference": "0x" + "7d" * 32, "chain_id": 1, "purpose": "nonsense"})
        self.assertEqual(bad.status_code, 400)

        # Admin sets the price to $0 -> membership becomes free for everyone
        newbie = self._siwe_login(Account.create())
        hn = {"Authorization": f"Bearer {newbie['session_token']}"}
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=hn).status_code, 402)
        self._enable_paywall(usd=0)
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=hn).status_code, 200)
        # ...and the profile the app receives says "paid" too (so no payment popup is shown)
        self.assertTrue(self._siwe_login(Account.create())["user"]["is_platform_paid"])
        self.assertTrue(self.client.get("/api/e2ee/me", headers=hn).json()["user"]["is_platform_paid"])

    def test_02c_public_websocket_requires_paid_membership(self):
        from starlette.websockets import WebSocketDisconnect
        self._enable_paywall(usd=10, rate=2500.0)
        d = self._siwe_login(Account.create())
        self.client.cookies.clear()  # rely only on the token sent in the first frame

        with self.client.websocket_connect("/ws/public-chat") as ws:
            ws.send_json({"type": "auth", "token": "not-a-real-token"})
            with self.assertRaises(WebSocketDisconnect) as cm:
                ws.receive_json()
            self.assertEqual(cm.exception.code, 4401)

        with self.client.websocket_connect("/ws/public-chat") as ws:  # valid session but unpaid
            ws.send_json({"type": "auth", "token": d["session_token"]})
            with self.assertRaises(WebSocketDisconnect) as cm:
                ws.receive_json()
            self.assertEqual(cm.exception.code, 4402)

        platform_db.update_platform_settings({"platform_entry_fee_usd": 0}, "test")  # now free -> allowed
        with self.client.websocket_connect("/ws/public-chat") as ws:
            ws.send_json({"type": "auth", "token": d["session_token"]})
            self.assertEqual(ws.receive_json()["type"], "public_connected")

    # ------------------------------------------------------------------ paid groups
    def _make_admin(self):
        acc = Account.create()
        data = self._siwe_login(acc)
        platform_db.set_admin_role(data["user"]["user_id"], "superadmin", actor_user_id="system")
        headers = {"Authorization": f"Bearer {data['session_token']}"}
        dev = f"dev_adm_{secrets.token_hex(4)}"
        bundle, _ = generate_signed_test_device(data["user"]["user_id"], dev)
        self.client.post("/api/e2ee/devices/register", json=bundle, headers=headers)
        return acc, data, headers, dev

    def _create_group(self, headers, dev, **extra):
        return self.client.post(
            "/api/e2ee/groups", headers=headers,
            json={"name": "VIP Alpha Traders", "mls_group_id_b64": _b64(secrets.token_bytes(16)),
                  "creator_device_id": dev, **extra},
        )

    def test_03_admin_creates_paid_group_priced_in_usd(self):
        self._enable_paywall(usd=0, rate=2000.0)  # platform entry free; $1 = 0.0005 ETH
        _, admin_data, admin_h, admin_dev = self._make_admin()

        # A normal member cannot create a paid group
        member_acc = Account.create()
        member = self._siwe_login(member_acc)
        member_h = {"Authorization": f"Bearer {member['session_token']}"}
        mdev = f"dev_mem_{secrets.token_hex(4)}"
        mb, _ = generate_signed_test_device(member["user"]["user_id"], mdev)
        self.client.post("/api/e2ee/devices/register", json=mb, headers=member_h)
        denied = self._create_group(member_h, mdev, is_paid=True, entry_fee_usd=20)
        self.assertEqual(denied.status_code, 403, denied.text)

        # Paid group needs a price
        no_price = self._create_group(admin_h, admin_dev, is_paid=True)
        self.assertEqual(no_price.status_code, 400, no_price.text)

        # Admin creates it as a $20 group
        g = self._create_group(admin_h, admin_dev, is_paid=True, entry_fee_usd=20, visibility="public")
        self.assertEqual(g.status_code, 200, g.text)
        group_id = g.json()["group"]["group_id"]
        self.assertTrue(g.json()["group"]["policy"]["is_paid"])

        # Candidate sees the price in USD and ETH (20 / 2000 = 0.01)
        cand_acc = Account.create()
        cand = self._siwe_login(cand_acc)
        cand_uid = cand["user"]["user_id"]
        cand_h = {"Authorization": f"Bearer {cand['session_token']}"}
        gp = self.client.get(f"/api/platform/groups/{group_id}/pricing", headers=cand_h).json()
        self.assertTrue(gp["is_paid"])
        self.assertEqual(gp["entry_fee_usd"], 20.0)
        self.assertEqual(gp["entry_fee_eth"], "0.01")
        self.assertFalse(gp["has_paid"])

        # Shows up in discovery with the price
        disc = self.client.get("/api/platform/groups/discover", headers=cand_h).json()["groups"]
        entry = next(x for x in disc if x["group_id"] == group_id)
        self.assertEqual(entry["entry_fee_usd"], 20.0)

        # Not admitted before paying; join request is refused
        meets, reason = platform_db.verify_user_meets_group_policy(group_id, cand_uid)
        self.assertFalse(meets)
        self.assertIn("entry fee", reason)
        self.assertEqual(self.client.post(f"/api/platform/groups/{group_id}/join-request", headers=cand_h).status_code, 403)

        # Underpayment is rejected for the group too
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(cand_acc.address, "0.002")):
            r = self.client.post("/api/platform/payments/verify", headers=cand_h, json={
                "transaction_reference": "0x" + "8a" * 32, "chain_id": 1, "purpose": "group_entry", "group_id": group_id})
        self.assertFalse(r.json()["success"])
        self.assertIn("Insufficient", r.json()["reason"])

        # Correct payment admits them
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(cand_acc.address, "0.01")):
            r = self.client.post("/api/platform/payments/verify", headers=cand_h, json={
                "transaction_reference": "0x" + "8b" * 32, "chain_id": 1, "purpose": "group_entry", "group_id": group_id})
        self.assertTrue(r.json()["success"], r.text)
        meets, reason = platform_db.verify_user_meets_group_policy(group_id, cand_uid)
        self.assertTrue(meets, reason)
        self.assertTrue(self.client.get(f"/api/platform/groups/{group_id}/pricing", headers=cand_h).json()["has_paid"])
        self.assertEqual(self.client.post(f"/api/platform/groups/{group_id}/join-request", headers=cand_h).status_code, 200)

        # Paying for a FREE group is refused
        free = self._create_group(admin_h, admin_dev)
        free_id = free.json()["group"]["group_id"]
        with patch("eth_rpc.verify_onchain_payment_transaction", return_value=self._tx_result(cand_acc.address, "0.01")):
            r = self.client.post("/api/platform/payments/verify", headers=cand_h, json={
                "transaction_reference": "0x" + "8c" * 32, "chain_id": 1, "purpose": "group_entry", "group_id": free_id})
        self.assertEqual(r.status_code, 400)

    def test_03b_only_superadmin_changes_price_and_members_are_grandfathered(self):
        self._enable_paywall(usd=0, rate=2000.0)
        _, admin_data, admin_h, admin_dev = self._make_admin()
        g = self._create_group(admin_h, admin_dev, visibility="public")  # starts FREE
        group_id = g.json()["group"]["group_id"]
        policy = {"description": "x", "visibility": "public", "min_level": 7, "require_invitation": False}

        # A regular group owner (not platform admin) cannot make their own group paid
        owner_acc = Account.create()
        owner = self._siwe_login(owner_acc)
        owner_h = {"Authorization": f"Bearer {owner['session_token']}"}
        odev = f"dev_own_{secrets.token_hex(4)}"
        ob, _ = generate_signed_test_device(owner["user"]["user_id"], odev)
        self.client.post("/api/e2ee/devices/register", json=ob, headers=owner_h)
        own_group = self._create_group(owner_h, odev).json()["group"]["group_id"]
        r = self.client.put(f"/api/platform/groups/{own_group}/policy", headers=owner_h,
                            json={**policy, "is_paid": True, "entry_fee_usd": 5})
        self.assertEqual(r.status_code, 403, r.text)
        # ...but can still edit normal settings; payment fields are left alone
        r = self.client.put(f"/api/platform/groups/{own_group}/policy", headers=owner_h,
                            json={**policy, "description": "updated by owner"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["policy"]["is_paid"])

        # Superadmin makes the admin's group paid at $12.50
        r = self.client.put(f"/api/platform/groups/{group_id}/policy", headers=admin_h,
                            json={**policy, "is_paid": True, "entry_fee_usd": 12.5})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["policy"]["entry_fee_usd"], 12.5)
        self.assertEqual(r.json()["policy"]["entry_fee_eth"], "0.00625")  # 12.5 / 2000

        # Admin (a member of their own group) is never locked out by the new fee
        admin_uid = admin_data["user"]["user_id"]
        self.assertTrue(platform_db.verify_user_meets_group_policy(group_id, admin_uid)[0])

        # Someone who was already a member when the group turned paid keeps their place
        old_member = self._siwe_login(Account.create())["user"]["user_id"]
        self.assertFalse(platform_db.verify_user_meets_group_policy(group_id, old_member)[0])
        with patch("e2ee_db.is_active_group_member", return_value=True):
            self.assertTrue(platform_db.verify_user_meets_group_policy(group_id, old_member)[0])

        # Paid with no price is rejected; making it free again works
        bad = self.client.put(f"/api/platform/groups/{group_id}/policy", headers=admin_h,
                              json={**policy, "is_paid": True, "entry_fee_usd": 0})
        self.assertEqual(bad.status_code, 400, bad.text)
        free_again = self.client.put(f"/api/platform/groups/{group_id}/policy", headers=admin_h,
                                     json={**policy, "is_paid": False})
        self.assertFalse(free_again.json()["policy"]["is_paid"])
        self.assertEqual(free_again.json()["policy"]["entry_fee_usd"], 0.0 if isinstance(free_again.json()["policy"]["entry_fee_usd"], float) else "0")


if __name__ == "__main__":
    unittest.main()