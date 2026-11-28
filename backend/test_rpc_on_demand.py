"""
The Ethereum RPC (Alchemy) is used only when a real money / eligibility question needs it:

- payments are verified on-chain (covered by test_verified_payments.py);
- a group's minimum-ETH-balance rule reads the balance fresh from the RPC when the saved one is too
  low and old, at most once per member per refresh window, and never while sending messages;
- health checks (polled by every open tab and the keep-alive pings) never call the RPC.
"""
import base64
import os
import secrets
import sys
import unittest
from unittest.mock import patch

os.environ["TESTING"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account
from web3 import Web3

import e2ee_db
import e2ee_routes
import eth_rpc
import platform_db
from test_paid_membership_and_groups import TestPaidMembershipAndGroups as _Base
from test_e2ee_security import generate_signed_test_device

ONE_ETH = Web3.to_wei(1, "ether")


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class _Fixtures(unittest.TestCase):
    __test__ = False


for _name in ("setUpClass", "tearDownClass", "setUp", "_enable_paywall", "_tx_result", "_siwe_login",
              "_make_admin", "_create_group"):
    setattr(_Fixtures, _name, _Base.__dict__[_name])
del _Base


def _rpc_balance(wei):
    def fake(wallet, chain_id=1):
        return {"wallet_address": Web3.to_checksum_address(wallet), "chain_id": chain_id, "balance_wei": str(wei),
                "balance_wei_int": wei, "balance_eth": str(Web3.from_wei(wei, "ether")),
                "block_number": 123, "rpc_source": "test_rpc"}
    return fake


class TestRpcOnDemand(_Fixtures):
    __test__ = True

    def setUp(self):
        super().setUp()
        e2ee_routes._rate_buckets.clear()
        platform_db.auth_cache.invalidate_all()
        platform_db._balance_attempts.clear()

    def _member(self):
        data = self._siwe_login(Account.create())
        self.client.cookies.clear()
        uid = data["user"]["user_id"]
        h = {"Authorization": f"Bearer {data['session_token']}"}
        dev = f"dev_m_{secrets.token_hex(5)}"
        bundle, _ = generate_signed_test_device(uid, dev)
        self.assertEqual(self.client.post("/api/e2ee/devices/register", json=bundle, headers=h).status_code, 200)
        return {"uid": uid, "h": h, "dev": dev}

    def _min_balance_group(self):
        _, _, admin_h, admin_dev = self._make_admin()
        self.client.cookies.clear()
        r = self._create_group(admin_h, admin_dev, visibility="public", min_eth_balance_wei=str(ONE_ETH))
        self.assertEqual(r.status_code, 200, r.text)
        return {"h": admin_h, "dev": admin_dev}, r.json()["group"]["group_id"]

    def test_join_reads_balance_fresh_when_saved_one_is_too_low(self):
        _, gid = self._min_balance_group()
        m = self._member()  # never verified: saved balance 0
        with patch("eth_rpc.verify_onchain_eth_balance", side_effect=_rpc_balance(2 * ONE_ETH)) as rpc:
            r = self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(rpc.call_count, 1)
        self.assertEqual(int(platform_db.get_extended_user_fields(m["uid"])["qualifying_balance_wei"]), 2 * ONE_ETH)

    def test_too_little_balance_is_refused_with_a_clear_message_and_rpc_not_hammered(self):
        _, gid = self._min_balance_group()
        m = self._member()
        with patch("eth_rpc.verify_onchain_eth_balance", side_effect=_rpc_balance(ONE_ETH // 10)) as rpc:
            first = self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"])
            again = self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"])
        self.assertNotEqual(first.status_code, 200)
        self.assertIn("at least 1 ETH", first.text)
        self.assertNotEqual(again.status_code, 200)
        self.assertEqual(rpc.call_count, 1)  # the retry used the fresh saved balance, no second RPC call

    def test_rpc_outage_fails_closed_without_crashing(self):
        _, gid = self._min_balance_group()
        m = self._member()
        with patch("eth_rpc.verify_onchain_eth_balance", side_effect=eth_rpc.EthereumRpcUnavailableError("down")):
            r = self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"])
        self.assertNotEqual(r.status_code, 200)
        self.assertLess(r.status_code, 500, r.text)

    def test_sending_group_messages_never_calls_the_rpc(self):
        admin, gid = self._min_balance_group()
        m = self._member()
        with patch("eth_rpc.verify_onchain_eth_balance", side_effect=_rpc_balance(2 * ONE_ETH)):
            self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"]).status_code, 200)
        epoch = e2ee_db.get_mls_group(gid)["current_epoch"]
        r = self.client.post(f"/api/e2ee/groups/{gid}/commits", headers=admin["h"], json={
            "committer_device_id": admin["dev"], "expected_epoch": epoch, "commit_type": "add",
            "mls_commit_b64": _b64(secrets.token_bytes(96)),
            "added_members": [{"user_id": m["uid"], "device_id": m["dev"], "role": "member"}],
            "welcomes": [{"target_user_id": m["uid"], "target_device_id": m["dev"],
                          "mls_welcome_b64": _b64(secrets.token_bytes(120))}]})
        self.assertEqual(r.status_code, 200, r.text)
        platform_db._balance_attempts.clear()
        with patch("eth_rpc.verify_onchain_eth_balance", side_effect=AssertionError("RPC called while sending")) as rpc:
            for _ in range(5):
                epoch = e2ee_db.get_mls_group(gid)["current_epoch"]
                s = self.client.post(f"/api/e2ee/groups/{gid}/messages", headers=m["h"], json={
                    "message_id": "msg_" + secrets.token_hex(8), "epoch": epoch, "sender_device_id": m["dev"],
                    "mls_ciphertext_b64": _b64(secrets.token_bytes(40))})
                self.assertEqual(s.status_code, 200, s.text)
        self.assertEqual(rpc.call_count, 0)

    def test_login_does_not_call_the_rpc(self):
        with patch("eth_rpc.verify_onchain_eth_balance", side_effect=AssertionError("RPC at login")), \
             patch("eth_rpc.get_w3_with_source", side_effect=AssertionError("RPC at login")):
            self._member()


class TestHealthNeverProbes(unittest.TestCase):
    def test_health_peek_makes_no_network_call(self):
        eth_rpc._rpc_health_cache.update({"at": 0.0, "value": None})
        with patch("eth_rpc.is_test_environment", return_value=False), \
             patch("eth_rpc.get_rpc_health_status", side_effect=AssertionError("probe from /api/health")):
            got = eth_rpc.peek_rpc_health_status()
            self.assertIn("mainnet", got)
            known = {"mainnet": {"configured": True, "connected": True}}
            eth_rpc._rpc_health_cache.update({"at": 0.0, "value": known})  # stale on purpose
            self.assertIs(eth_rpc.peek_rpc_health_status(), known)  # reported, not refreshed
        eth_rpc._rpc_health_cache.update({"at": 0.0, "value": None})


if __name__ == "__main__":
    unittest.main()
