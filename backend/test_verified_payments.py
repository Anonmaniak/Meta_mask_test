"""
Focused Automated Test Suite for Server-Side Verified Payment Records & Authorized Destination.

Tests cover all required scenarios:
1. Valid transaction from user's wallet to authorized destination: Succeeded on-chain,
   sender matches user wallet, recipient matches authorized destination, allowed chain.
   Amount credited toward user's level qualification.
2. Valid transaction to a different destination: Must be permanently rejected, amount NOT credited.
3. Transaction from a different wallet: Must be rejected, amount NOT credited.
4. Failed/reverted transaction: Must be rejected, amount NOT credited.
5. Pending transaction: Awaiting confirmation, amount NOT credited.
6. Missing or invalid authorized destination configuration: Fails closed, returns safe error,
   never falls back to accepting transaction without recipient verification, rejects frontend-supplied destination.
7. Blockchain RPC failure: Kept pending/retryable, amount NOT credited, sanitized safe error.
8. Duplicate transaction submission: Enforces uniqueness, returns existing record without double-credit.
9. Admin controls & audit trail: Creation/change audit logging with actor, timestamp, previous_value,
   new_value, safe handling, role-based authorization, and safe authenticated user lookup.
10. Unsupported chain/network: Transactions on unauthorized chains rejected.
11. Database failure: Safe 500 error, payment not reported as verified, no internals leaked.
12. Safe retry / idempotency transition: Pending -> verified transition with retry tracking.
13. Admin retry endpoint: Enforces authorized destination during admin retry.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

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
import eth_rpc

AUTH_DESTINATION = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
OTHER_DESTINATION = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"


class TestVerifiedPaymentRecords(unittest.TestCase):
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
        # Ensure default authorized destination is set
        platform_db.update_platform_settings(
            {"authorized_payment_destination": AUTH_DESTINATION, "default_balance_chain_id": 1},
            actor_user_id="test_setup",
        )

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

    def _auth_headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def _setup_admin(self) -> str:
        admin_w = Account.create()
        with patch.dict(os.environ, {"ADMIN_WALLET_ADDRESSES": admin_w.address}):
            adm_auth = self._siwe_login(admin_w)
        return adm_auth["session_token"]

    # -------------------------------------------------------------------------
    # 1. Valid Transaction to Authorized Destination
    # -------------------------------------------------------------------------
    def test_01_valid_transaction_to_authorized_destination(self):
        """
        Valid on-chain transaction:
        - Succeeded on-chain
        - Sender matches authenticated user's wallet
        - Recipient matches currently authorized payment destination
        - Allowed chain (Ethereum Mainnet chain_id=1)
        -> Authoritatively verified, recipient recorded, amount credited to qualification.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "1a" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": True,
                "status": "verified",
                "wallet_address": Web3.to_checksum_address(user_w.address),
                "recipient_address": Web3.to_checksum_address(AUTH_DESTINATION),
                "amount_atomic": str(int(2.0 * 10**18)),
                "amount_formatted": "2.0",
                "currency": "ETH",
                "network": "ethereum",
                "chain_id": 1,
                "block_number": 21000000,
                "transaction_reference": tx_hash,
                "verification_source": "ethereum_rpc",
            }

            res = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res.status_code, 200, res.text)
            body = res.json()
            self.assertTrue(body["success"])
            self.assertEqual(body["status"], "verified")
            self.assertEqual(body["payment"]["amount_formatted"], "2.0")
            self.assertEqual(body["payment"]["recipient_address"], Web3.to_checksum_address(AUTH_DESTINATION))
            self.assertIsNotNone(body["payment"]["verified_at"])

        # Verify database record
        rec = platform_db.get_payment_by_tx_ref(tx_hash)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "verified")
        self.assertEqual(rec["recipient_address"], Web3.to_checksum_address(AUTH_DESTINATION))
        self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), int(2.0 * 10**18))

    # -------------------------------------------------------------------------
    # 2. Transaction to Different Destination — Must Be Rejected
    # -------------------------------------------------------------------------
    def test_02_transaction_to_different_destination_permanently_rejected(self):
        """
        Valid on-chain transaction from user's wallet, but recipient is NOT the authorized destination.
        Must be permanently rejected ('failed'), reason must indicate recipient mismatch,
        and amount must NOT count toward level qualification.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "2b" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": False,
                "status": "failed",
                "reason": f"Recipient mismatch (expected {AUTH_DESTINATION}, found {OTHER_DESTINATION})",
                "transaction_reference": tx_hash,
                "wallet_address": Web3.to_checksum_address(user_w.address),
                "recipient_address": Web3.to_checksum_address(OTHER_DESTINATION),
                "chain_id": 1,
            }

            res = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertFalse(body["success"])
            self.assertEqual(body["status"], "failed")
            self.assertEqual(body["payment"]["status"], "failed")
            self.assertIn("Recipient mismatch", body["reason"])

        # Crucial: Mismatched recipient payment must NOT count toward verified payment total!
        total_wei = platform_db.get_user_verified_payment_total_wei(uid)
        self.assertEqual(total_wei, 0, "Rejected payment must not count toward verified payment total")

        # Payment record is permanently failed
        rec = platform_db.get_payment_by_tx_ref(tx_hash)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "failed")

    # -------------------------------------------------------------------------
    # 3. Transaction from Different Wallet — Must Be Rejected
    # -------------------------------------------------------------------------
    def test_03_transaction_from_different_wallet_rejected(self):
        """
        Valid on-chain transaction to authorized destination, but sender wallet does not match
        the authenticated user's primary wallet. Must be rejected and not credited.
        """
        user_w = Account.create()
        other_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "3c" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": False,
                "status": "failed",
                "reason": f"Sender mismatch (expected {user_w.address}, found {other_w.address})",
                "transaction_reference": tx_hash,
                "wallet_address": Web3.to_checksum_address(other_w.address),
                "recipient_address": Web3.to_checksum_address(AUTH_DESTINATION),
                "chain_id": 1,
            }

            res = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertFalse(body["success"])
            self.assertEqual(body["status"], "failed")
            self.assertIn("Sender mismatch", body["reason"])

        self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), 0)

    # -------------------------------------------------------------------------
    # 4. Failed / Reverted Transaction — Must Be Rejected
    # -------------------------------------------------------------------------
    def test_04_failed_or_reverted_transaction_rejected(self):
        """
        On-chain transaction that reverted (status_code == 0).
        Must be marked as failed and not count toward qualification.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "4d" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": False,
                "status": "failed",
                "reason": "Transaction reverted on-chain (execution reverted)",
                "transaction_reference": tx_hash,
                "wallet_address": Web3.to_checksum_address(user_w.address),
                "recipient_address": Web3.to_checksum_address(AUTH_DESTINATION),
                "chain_id": 1,
            }

            res = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertFalse(body["success"])
            self.assertEqual(body["status"], "failed")
            self.assertIn("reverted", body["reason"].lower())

        self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), 0)

    # -------------------------------------------------------------------------
    # 5. Pending Transaction — Not Counted
    # -------------------------------------------------------------------------
    def test_05_pending_transaction_not_counted(self):
        """
        Transaction pending confirmation on-chain.
        Must be stored in pending state and must strictly count as 0 toward level qualification.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "5e" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": False,
                "status": "pending",
                "reason": "Transaction pending confirmation on-chain",
                "transaction_reference": tx_hash,
                "wallet_address": Web3.to_checksum_address(user_w.address),
                "recipient_address": Web3.to_checksum_address(AUTH_DESTINATION),
                "chain_id": 1,
            }

            res = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertFalse(body["success"])
            self.assertEqual(body["status"], "pending")
            self.assertEqual(body["payment"]["status"], "pending")

        self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), 0)

    # -------------------------------------------------------------------------
    # 6. Missing or Invalid Authorized Destination Configuration
    # -------------------------------------------------------------------------
    def test_06_missing_or_invalid_authorized_destination_fails_closed(self):
        """
        If the authorized payment destination is missing or invalid:
        - Must fail closed (HTTP 503).
        - Must not verify new payments.
        - Must keep payment pending/retryable without crediting.
        - Must reject frontend attempts to pass destination as authoritative input.
        - Must never fall back to accepting transaction without recipient verification.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        # Case A: Missing destination (set to None)
        with patch("platform_db.get_authorized_payment_destination", return_value=None):
            tx_hash_a = "0x" + "6a" * 32
            res_a = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash_a, "chain_id": 1},
            )
            self.assertEqual(res_a.status_code, 503)
            self.assertIn("temporarily unavailable", res_a.json()["detail"])
            self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), 0)

        # Case B: Invalid destination (not an EVM address)
        with patch("platform_db.get_authorized_payment_destination", return_value="invalid_not_an_address"):
            tx_hash_b = "0x" + "6b" * 32
            res_b = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash_b, "chain_id": 1},
            )
            self.assertEqual(res_b.status_code, 503)
            self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), 0)

        # Case C: Frontend cannot supply payment destination (StrictModel rejects extra fields)
        tx_hash_c = "0x" + "6c" * 32
        res_c = self.client.post(
            "/api/platform/payments/verify",
            headers=self._auth_headers(token),
            json={
                "transaction_reference": tx_hash_c,
                "chain_id": 1,
                "recipient": user_w.address,
                "destination": user_w.address,
            },
        )
        # StrictModel returns 422 Unprocessable Entity
        self.assertEqual(res_c.status_code, 422)

        # Case D: Direct call to eth_rpc without valid destination raises ValueError (fail closed)
        with self.assertRaises(ValueError):
            eth_rpc.verify_onchain_payment_transaction(
                tx_hash=tx_hash_c,
                chain_id=1,
                expected_sender=user_w.address,
                expected_recipient=None,
            )

    # -------------------------------------------------------------------------
    # 7. RPC Failure Handling
    # -------------------------------------------------------------------------
    def test_07_rpc_failure_handling(self):
        """
        When blockchain RPC is temporarily unavailable:
        - Keeps payment pending/retryable.
        - Does NOT count it toward qualification.
        - Returns safe HTTP 503 without leaking internal connection URLs or API keys.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "7f" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.side_effect = eth_rpc.EthereumRpcUnavailableError("RPC node timeout after 10s")

            res = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res.status_code, 503)
            self.assertIn("temporarily unavailable", res.json()["detail"])
            # Sanitization check: does not leak internal keys or hostnames
            self.assertNotIn("alchemy.com", res.text)
            self.assertNotIn("npg_", res.text)

        # Payment record is preserved in safe pending retry state
        rec = platform_db.get_payment_by_tx_ref(tx_hash)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["status"], "pending")
        self.assertGreaterEqual(rec["retry_count"], 1)

        # Unverified payment must NOT count toward qualification
        self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), 0)

    # -------------------------------------------------------------------------
    # 8. Duplicate Transaction Submission — Uniqueness & No Double Credit
    # -------------------------------------------------------------------------
    def test_08_duplicate_transaction_submission_no_double_credit(self):
        """
        Submitting the same transaction reference twice:
        - First submission verifies and credits 1.0 ETH.
        - Second submission returns existing record idempotently (already_verified=True).
        - Total verified payments must be strictly 1.0 ETH (NOT doubled to 2.0 ETH).
        - Database uniqueness constraints prevent duplicate row creation.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "8a" * 32
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": True,
                "status": "verified",
                "wallet_address": Web3.to_checksum_address(user_w.address),
                "recipient_address": Web3.to_checksum_address(AUTH_DESTINATION),
                "amount_atomic": str(int(1.0 * 10**18)),
                "amount_formatted": "1.0",
                "currency": "ETH",
                "network": "ethereum",
                "chain_id": 1,
                "block_number": 21000100,
                "transaction_reference": tx_hash,
                "verification_source": "ethereum_rpc",
            }

            # First submission
            res1 = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res1.status_code, 200)
            self.assertEqual(res1.json()["status"], "verified")

            # Second submission: idempotent return
            res2 = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res2.status_code, 200)
            body2 = res2.json()
            self.assertTrue(body2["success"])
            self.assertTrue(body2.get("already_verified"))
            self.assertEqual(body2["payment"]["payment_id"], res1.json()["payment"]["payment_id"])

        # Confirms amount was credited exactly once
        total_wei = platform_db.get_user_verified_payment_total_wei(uid)
        self.assertEqual(total_wei, int(1.0 * 10**18))

        # Enforcing DB uniqueness
        rec, created = platform_db.create_or_submit_payment_record(uid, tx_hash)
        self.assertFalse(created, "Must not create a duplicate row for the same transaction reference")
        self.assertEqual(rec["transaction_reference"], tx_hash)

    # -------------------------------------------------------------------------
    # 9. Admin Controls & Audit Trail for Authorized Destination
    # -------------------------------------------------------------------------
    def test_09_admin_controls_and_audit_trail_for_authorized_destination(self):
        """
        Admin security and audit requirements:
        - Only superadmin can change the authorized payment destination.
        - Non-admins and unauthorized users are forbidden (401/403).
        - Changes record audit log with actor, timestamp, previous_value, and new_value.
        - Invalid address formats are rejected (400).
        - Authenticated users can query the destination without exposing sensitive admin data.
        """
        user_w = Account.create()
        user_auth = self._siwe_login(user_w)
        user_tok = user_auth["session_token"]

        new_destination = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

        # 1. Non-admin attempting to change destination gets 403 Forbidden
        bad_res = self.client.put(
            "/api/platform/admin/payment-destination",
            headers=self._auth_headers(user_tok),
            json={"destination_address": new_destination},
        )
        self.assertEqual(bad_res.status_code, 403)

        # 2. Superadmin successfully updates destination
        adm_tok = self._setup_admin()
        prev_dest = platform_db.get_authorized_payment_destination()

        update_res = self.client.put(
            "/api/platform/admin/payment-destination",
            headers=self._auth_headers(adm_tok),
            json={"destination_address": new_destination},
        )
        self.assertEqual(update_res.status_code, 200)
        body = update_res.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["authorized_payment_destination"], Web3.to_checksum_address(new_destination))
        self.assertEqual(body["previous_value"], prev_dest)

        # 3. Check audit log was recorded with actor, timestamp, previous_value, new_value
        audit_logs = platform_db.list_audit_logs(limit=10, action="authorized_payment_destination_changed")
        self.assertTrue(len(audit_logs) > 0, "Audit log for destination change must be recorded")
        latest = audit_logs[0]
        self.assertIn("actor", latest["details"])
        self.assertIn("timestamp", latest["details"])
        self.assertEqual(latest["details"]["previous_value"], prev_dest)
        self.assertEqual(latest["details"]["new_value"], Web3.to_checksum_address(new_destination))

        # 4. Invalid EVM address rejected
        inv_res = self.client.put(
            "/api/platform/admin/payment-destination",
            headers=self._auth_headers(adm_tok),
            json={"destination_address": "0xinvalid_address_not_hex"},
        )
        self.assertIn(inv_res.status_code, (400, 422))

        inv_res_42 = self.client.put(
            "/api/platform/admin/payment-destination",
            headers=self._auth_headers(adm_tok),
            json={"destination_address": "0x" + "z" * 40},
        )
        self.assertEqual(inv_res_42.status_code, 400)

        # 5. Authenticated user can query destination safely
        user_dest_res = self.client.get("/api/platform/payments/destination", headers=self._auth_headers(user_tok))
        self.assertEqual(user_dest_res.status_code, 200)
        self.assertEqual(user_dest_res.json()["destination_address"], Web3.to_checksum_address(new_destination))

        # 6. Unauthenticated request to payments destination gets 401
        self.client.cookies.clear()
        unauth_res = self.client.get("/api/platform/payments/destination")
        self.assertEqual(unauth_res.status_code, 401)

    # -------------------------------------------------------------------------
    # 10. Unsupported Chain / Network Rejected
    # -------------------------------------------------------------------------
    def test_10_unsupported_chain_rejected(self):
        """
        When a transaction is submitted on an unsupported chain (e.g. chain_id=56):
        - Fails validation and is rejected.
        - Payment is not counted toward qualification.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "9b" * 32
        res = self.client.post(
            "/api/platform/payments/verify",
            headers=self._auth_headers(token),
            json={"transaction_reference": tx_hash, "chain_id": 56},
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Unsupported chain_id", res.json()["detail"])
        self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), 0)

    # -------------------------------------------------------------------------
    # 11. Database Failure Handling
    # -------------------------------------------------------------------------
    def test_11_database_failure_does_not_report_verified(self):
        """
        Database errors during payment submission or recording:
        - Must not report payment as verified.
        - Must return 500 without leaking database internals.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]

        tx_hash = "0x" + "ff" * 32

        # Simulate database failure during payment submission
        with patch("platform_db.create_or_submit_payment_record", side_effect=Exception("Disk write failure")):
            res = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res.status_code, 500)
            self.assertNotIn("Disk write failure", res.json().get("detail", ""))
            self.assertEqual(res.json()["detail"], "Database operation failed; payment was not recorded or verified.")

        # Simulate database failure during verification write
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": True,
                "status": "verified",
                "recipient_address": AUTH_DESTINATION,
                "amount_atomic": "1000000000000000000",
                "amount_formatted": "1.0",
                "currency": "ETH",
                "network": "ethereum",
            }
            with patch("platform_db.record_verified_payment", side_effect=Exception("Database lock timeout")):
                res2 = self.client.post(
                    "/api/platform/payments/verify",
                    headers=self._auth_headers(token),
                    json={"transaction_reference": tx_hash, "chain_id": 1},
                )
                self.assertEqual(res2.status_code, 500)
                self.assertEqual(res2.json()["detail"], "Database operation failed; payment was not recorded or verified.")

    # -------------------------------------------------------------------------
    # 12. Safe Retry & Idempotency Transition
    # -------------------------------------------------------------------------
    def test_12_safe_retry_and_idempotency_transition(self):
        """
        Transitioning pending -> verified safely, tracking retries, and preventing duplicate credit.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        uid = auth["user"]["user_id"]

        tx_hash = "0x" + "12" * 32

        # Step 1: Initial attempt is pending
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": False,
                "status": "pending",
                "reason": "Mined block pending",
            }
            res1 = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res1.status_code, 200)
            self.assertEqual(res1.json()["status"], "pending")
            p_id = res1.json()["payment"]["payment_id"]

        self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), 0)

        # Step 2: Retry after transaction is mined: transitions cleanly to verified!
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": True,
                "status": "verified",
                "wallet_address": Web3.to_checksum_address(user_w.address),
                "recipient_address": Web3.to_checksum_address(AUTH_DESTINATION),
                "amount_atomic": str(int(1.5 * 10**18)),
                "amount_formatted": "1.5",
                "currency": "ETH",
                "network": "ethereum",
                "chain_id": 1,
                "block_number": 21000500,
                "transaction_reference": tx_hash,
                "verification_source": "ethereum_rpc",
            }
            res2 = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            self.assertEqual(res2.status_code, 200)
            body2 = res2.json()
            self.assertTrue(body2["success"])
            self.assertEqual(body2["status"], "verified")
            self.assertEqual(body2["payment"]["payment_id"], p_id)
            self.assertEqual(body2["payment"]["amount_formatted"], "1.5")

        # Step 3: Third submission returns the verified record idempotently
        res3 = self.client.post(
            "/api/platform/payments/verify",
            headers=self._auth_headers(token),
            json={"transaction_reference": tx_hash, "chain_id": 1},
        )
        self.assertEqual(res3.status_code, 200)
        self.assertTrue(res3.json()["already_verified"])

        # Confirms amount was credited exactly once
        self.assertEqual(platform_db.get_user_verified_payment_total_wei(uid), int(1.5 * 10**18))

    # -------------------------------------------------------------------------
    # 13. Admin Retry Endpoint Enforces Authorized Destination
    # -------------------------------------------------------------------------
    def test_13_admin_retry_enforces_authorized_destination(self):
        """
        When retrying verification via Admin endpoint:
        - Mismatched recipient is rejected.
        - Matching recipient is verified.
        """
        user_w = Account.create()
        auth = self._siwe_login(user_w)
        token = auth["session_token"]
        adm_tok = self._setup_admin()

        tx_hash = "0x" + "13" * 32

        # Initial pending submission
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {"verified": False, "status": "pending", "reason": "Pending"}
            res1 = self.client.post(
                "/api/platform/payments/verify",
                headers=self._auth_headers(token),
                json={"transaction_reference": tx_hash, "chain_id": 1},
            )
            p_id = res1.json()["payment"]["payment_id"]

        # Admin retry with mismatched recipient -> rejected
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": False,
                "status": "failed",
                "reason": f"Recipient mismatch (expected {AUTH_DESTINATION}, found {OTHER_DESTINATION})",
                "recipient_address": OTHER_DESTINATION,
            }
            r_res1 = self.client.post(
                f"/api/platform/admin/payments/{p_id}/retry",
                headers=self._auth_headers(adm_tok),
            )
            self.assertEqual(r_res1.status_code, 200)
            self.assertFalse(r_res1.json()["success"])
            self.assertEqual(r_res1.json()["status"], "failed")

        # Admin retry with matching recipient -> verified
        with patch("eth_rpc.verify_onchain_payment_transaction") as mock_rpc:
            mock_rpc.return_value = {
                "verified": True,
                "status": "verified",
                "wallet_address": Web3.to_checksum_address(user_w.address),
                "recipient_address": Web3.to_checksum_address(AUTH_DESTINATION),
                "amount_atomic": str(int(1.0 * 10**18)),
                "amount_formatted": "1.0",
                "currency": "ETH",
                "network": "ethereum",
                "chain_id": 1,
            }
            r_res2 = self.client.post(
                f"/api/platform/admin/payments/{p_id}/retry",
                headers=self._auth_headers(adm_tok),
            )
            self.assertEqual(r_res2.status_code, 200)
            self.assertTrue(r_res2.json()["success"])
            self.assertEqual(r_res2.json()["status"], "verified")


if __name__ == "__main__":
    unittest.main()

class TestActiveNetworkOnly(unittest.TestCase):
    """Security: a payment is valid ONLY on the network the admin selected (no free-testnet-ETH bypass)."""

    def test_only_active_chain_is_allowed(self):
        platform_db.update_platform_settings({"default_balance_chain_id": 1}, actor_user_id="t")
        self.assertEqual(platform_db.get_allowed_payment_chain_ids(), [1])
        platform_db.update_platform_settings({"default_balance_chain_id": 11155111}, actor_user_id="t")
        self.assertEqual(platform_db.get_allowed_payment_chain_ids(), [11155111])

    def test_unsupported_chain_rejected_by_settings(self):
        with self.assertRaises(ValueError):
            platform_db.update_platform_settings({"default_balance_chain_id": 137}, actor_user_id="t")

    def test_destination_empty_by_default_fails_closed(self):
        self.assertIsNone(platform_db.DEFAULT_PLATFORM_SETTINGS["authorized_payment_destination"])
