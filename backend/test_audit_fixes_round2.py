"""
Regression tests for the second full-system audit (Nov 2026). One test (or a few) per fixed bug:

- Bogus X-Admin-Token no longer grants superadmin pricing control on a group policy.
- DM attachment upload enforces blocks, participant checks and refuses unknown peers.
- Group pricing reads the caller's session from cookies and lowercase "bearer" headers.
- Conversation prefs are refused for members who left the group.
- Admin overview uses the cached (non-blocking) RPC health.
- A pending contract-creation transaction fails instead of staying "pending".
- set_pin can never exceed PIN_LIMIT; the schema cache keys on object identity.
- Reaction emoji validation accepts keycaps and rejects text in other scripts.
- Test-environment detection agrees across modules (pytest included).
"""
import base64
import hashlib
import os
import secrets
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch

os.environ["TESTING"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account

import chat_features_db
import e2ee_db
import e2ee_routes
import eth_rpc
import platform_db
from test_paid_membership_and_groups import TestPaidMembershipAndGroups as _Base
from test_e2ee_security import generate_signed_test_device


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class _Fixtures(unittest.TestCase):
    __test__ = False


for _name in ("setUpClass", "tearDownClass", "setUp", "_enable_paywall", "_tx_result", "_siwe_login",
              "_make_admin", "_create_group"):
    setattr(_Fixtures, _name, _Base.__dict__[_name])
del _Base


class TestAuditFixesRound2(_Fixtures):
    __test__ = True

    def setUp(self):
        super().setUp()
        e2ee_routes._rate_buckets.clear()
        platform_db.auth_cache.invalidate_all()

    # ------------------------------------------------------------------ helpers
    def _member(self):
        data = self._siwe_login(Account.create())
        self.client.cookies.clear()
        uid, tok = data["user"]["user_id"], data["session_token"]
        h = {"Authorization": f"Bearer {tok}"}
        dev = f"dev_m_{secrets.token_hex(5)}"
        bundle, _ = generate_signed_test_device(uid, dev)
        self.assertEqual(self.client.post("/api/e2ee/devices/register", json=bundle, headers=h).status_code, 200)
        return {"uid": uid, "h": h, "dev": dev, "tok": tok}

    def _join(self, admin, gid, m):
        self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"]).status_code, 200)
        epoch = e2ee_db.get_mls_group(gid)["current_epoch"]
        r = self.client.post(f"/api/e2ee/groups/{gid}/commits", headers=admin["h"], json={
            "committer_device_id": admin["dev"], "expected_epoch": epoch, "commit_type": "add",
            "mls_commit_b64": _b64(secrets.token_bytes(96)),
            "added_members": [{"user_id": m["uid"], "device_id": m["dev"], "role": "member"}],
            "welcomes": [{"target_user_id": m["uid"], "target_device_id": m["dev"],
                          "mls_welcome_b64": _b64(secrets.token_bytes(120))}]})
        self.assertEqual(r.status_code, 200, r.text)

    def _upload(self, m, scope_type, scope_id):
        ct = secrets.token_bytes(64)
        return self.client.post("/api/e2ee/attachments", headers=m["h"], json={
            "scope_type": scope_type, "scope_id": scope_id, "uploader_device_id": m["dev"],
            "ciphertext_b64": _b64(ct), "ciphertext_sha256": hashlib.sha256(ct).hexdigest()})

    def _dm(self, sender, recipient):
        cts = {sender["dev"]: {"message_type": 1, "ciphertext_b64": _b64(secrets.token_bytes(40))},
               recipient["dev"]: {"message_type": 1, "ciphertext_b64": _b64(secrets.token_bytes(40))}}
        r = self.client.post("/api/e2ee/dm/messages", headers=sender["h"], json={
            "message_id": "dm_" + secrets.token_hex(8), "recipient_user_id": recipient["uid"],
            "sender_device_id": sender["dev"], "device_ciphertexts": cts})
        self.assertEqual(r.status_code, 200, r.text)

    # ------------------------------------------------------------------ 1. privilege escalation
    def test_bogus_admin_token_cannot_change_group_pricing(self):
        self._enable_paywall(usd=0, rate=2000.0)
        owner = self._member()
        gid = self._create_group(owner["h"], owner["dev"], visibility="public").json()["group"]["group_id"]
        self.assertTrue(platform_db.is_group_admin(gid, owner["uid"]))

        bad_headers = {**owner["h"], "X-Admin-Token": "totally-not-a-real-admin-token"}
        r = self.client.put(f"/api/platform/groups/{gid}/policy", headers=bad_headers, json={
            "description": "x", "visibility": "public", "require_invitation": False,
            "is_paid": True, "entry_fee_usd": 50})
        self.assertEqual(r.status_code, 403, r.text)
        pol = platform_db.get_group_access_policy(gid)
        self.assertFalse(pol.get("is_paid"))

        # The yearly price is ignored for non-superadmins even when the request otherwise succeeds.
        r = self.client.put(f"/api/platform/groups/{gid}/policy", headers=bad_headers, json={
            "description": "still free", "visibility": "public", "require_invitation": False,
            "entry_fee_yearly_usd": 999})
        self.assertEqual(r.status_code, 200, r.text)
        pol = platform_db.get_group_access_policy(gid)
        self.assertFalse(pol.get("is_paid"))
        self.assertNotEqual(float(pol.get("entry_fee_yearly_usd") or 0), 999.0)
        self.assertEqual(pol.get("description"), "still free")  # normal edits still work

    def test_real_superadmin_can_still_price_groups(self):
        self._enable_paywall(usd=0, rate=2000.0)
        _, _, admin_h, admin_dev = self._make_admin()
        self.client.cookies.clear()
        gid = self._create_group(admin_h, admin_dev, visibility="public").json()["group"]["group_id"]
        r = self.client.put(f"/api/platform/groups/{gid}/policy", headers=admin_h, json={
            "description": "paid", "visibility": "public", "require_invitation": False,
            "is_paid": True, "entry_fee_usd": 25})
        self.assertEqual(r.status_code, 200, r.text)
        pol = platform_db.get_group_access_policy(gid)
        self.assertTrue(pol["is_paid"])
        self.assertEqual(float(pol["entry_fee_usd"]), 25.0)

    # ------------------------------------------------------------------ 2. DM attachment authorization
    def test_dm_attachment_upload_refused_when_blocked(self):
        a, b = self._member(), self._member()
        self.assertEqual(self._upload(a, "dm", b["uid"]).status_code, 200)
        blk = self.client.post("/api/platform/blocks", headers=b["h"], json={"target_user_id": a["uid"], "reason": "x"})
        self.assertEqual(blk.status_code, 200, blk.text)
        # Blocked in either direction: both uploads are refused
        self.assertEqual(self._upload(a, "dm", b["uid"]).status_code, 403)
        self.assertEqual(self._upload(b, "dm", a["uid"]).status_code, 403)

    def test_dm_attachment_upload_to_foreign_conversation_id_refused(self):
        a, b, outsider = self._member(), self._member(), self._member()
        self._dm(a, b)
        conv = e2ee_db.make_dm_conversation_id(a["uid"], b["uid"])
        # A participant may upload into the conversation id...
        self.assertEqual(self._upload(a, "dm", conv).status_code, 200)
        # ...a stranger may not (previously accepted with no check at all)
        self.assertEqual(self._upload(outsider, "dm", conv).status_code, 403)
        # and a participant is refused once a block exists
        self.client.post("/api/platform/blocks", headers=b["h"], json={"target_user_id": a["uid"], "reason": "x"})
        self.assertEqual(self._upload(a, "dm", conv).status_code, 403)

    def test_dm_attachment_upload_rejects_unknown_self_and_garbage_scopes(self):
        a = self._member()
        self.assertEqual(self._upload(a, "dm", "usr_doesnotexist000").status_code, 404)
        self.assertEqual(self._upload(a, "dm", a["uid"]).status_code, 400)
        self.assertEqual(self._upload(a, "dm", "something_else_123").status_code, 400)

    def test_group_attachment_upload_still_requires_membership(self):
        _, _, admin_h, admin_dev = self._make_admin()
        self.client.cookies.clear()
        gid = self._create_group(admin_h, admin_dev, visibility="public").json()["group"]["group_id"]
        admin = {"h": admin_h, "dev": admin_dev}
        outsider = self._member()
        self.assertEqual(self._upload(admin, "group", gid).status_code, 200)
        self.assertEqual(self._upload(outsider, "group", gid).status_code, 403)

    # ------------------------------------------------------------------ 3. pricing session resolution
    def test_group_pricing_reads_cookie_and_lowercase_bearer(self):
        _, _, admin_h, admin_dev = self._make_admin()
        self.client.cookies.clear()
        gid = self._create_group(admin_h, admin_dev, visibility="public").json()["group"]["group_id"]
        m = self._member()
        with patch("platform_db.has_user_paid_group_entry", return_value=True) as paid:
            # lowercase scheme
            r = self.client.get(f"/api/platform/groups/{gid}/pricing", headers={"Authorization": f"bearer {m['tok']}"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json()["has_paid"])
            # cookie only, no header
            self.client.cookies.set(e2ee_routes.SESSION_COOKIE_NAME, m["tok"])
            try:
                r = self.client.get(f"/api/platform/groups/{gid}/pricing")
            finally:
                self.client.cookies.clear()
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json()["has_paid"])
            self.assertTrue(all(c.args[0] == m["uid"] for c in paid.call_args_list))
        # anonymous caller: has_paid False, endpoint still works
        r = self.client.get(f"/api/platform/groups/{gid}/pricing")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["has_paid"])

    # ------------------------------------------------------------------ 4. prefs for former members
    def test_conversation_prefs_refused_after_leaving_group(self):
        _, _, admin_h, admin_dev = self._make_admin()
        self.client.cookies.clear()
        admin = {"h": admin_h, "dev": admin_dev}
        gid = self._create_group(admin_h, admin_dev, visibility="public").json()["group"]["group_id"]
        m = self._member()
        self._join(admin, gid, m)
        ok = self.client.post("/api/e2ee/conversation-prefs", headers=m["h"], json={"scope_key": f"group:{gid}", "archived": True})
        self.assertEqual(ok.status_code, 200, ok.text)
        left = self.client.post(f"/api/platform/groups/{gid}/leave", headers=m["h"])
        self.assertEqual(left.status_code, 200, left.text)
        r = self.client.post("/api/e2ee/conversation-prefs", headers=m["h"], json={"scope_key": f"group:{gid}", "mute": "always"})
        self.assertEqual(r.status_code, 403, r.text)

    # ------------------------------------------------------------------ 5. admin overview RPC health
    def test_admin_overview_uses_cached_rpc_health(self):
        _, _, admin_h, _ = self._make_admin()
        self.client.cookies.clear()
        with patch("eth_rpc.get_cached_rpc_health_status", return_value={"mainnet": {"configured": True, "connected": True}}) as cached, \
             patch("eth_rpc.get_rpc_health_status", side_effect=AssertionError("live probe must not run per request")):
            r = self.client.get("/api/platform/admin/overview", headers=admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        cached.assert_called_once()
        self.assertTrue(r.json()["networks"]["mainnet"]["connected"])


class TestRpcHealthCache(unittest.TestCase):
    """The cache never blocks a request once it has a value, and refreshes stale data in the background."""

    def setUp(self):
        eth_rpc._rpc_health_cache.update({"at": 0.0, "value": None})
        eth_rpc._rpc_health_refreshing.clear()

    def test_stale_value_returned_immediately_and_refreshed_in_background(self):
        stale = {"mainnet": {"configured": True, "connected": False}}
        fresh = {"mainnet": {"configured": True, "connected": True}}
        eth_rpc._rpc_health_cache.update({"at": 0.0, "value": stale})  # long expired
        gate = threading.Event()

        def slow_probe():
            gate.wait(2)
            return fresh

        with patch("eth_rpc.is_test_environment", return_value=False), \
             patch("eth_rpc.get_rpc_health_status", side_effect=slow_probe):
            got = eth_rpc.get_cached_rpc_health_status()
            self.assertIs(got, stale)  # answered without waiting for the slow probe
            gate.set()
            for _ in range(100):
                if eth_rpc._rpc_health_cache["value"] is fresh:
                    break
                threading.Event().wait(0.02)
        self.assertIs(eth_rpc._rpc_health_cache["value"], fresh)

    def test_simultaneous_callers_start_only_one_probe(self):
        calls = []
        gate = threading.Event()

        def probe():
            calls.append(1)
            gate.wait(2)
            return {"mainnet": {"configured": True, "connected": True}}

        with patch("eth_rpc.is_test_environment", return_value=False), \
             patch("eth_rpc.get_rpc_health_status", side_effect=probe):
            start = threading.Barrier(16)

            def caller():
                start.wait()
                eth_rpc.get_cached_rpc_health_status()

            threads = [threading.Thread(target=caller) for _ in range(16)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            gate.set()
            for _ in range(100):
                if not eth_rpc._rpc_health_refreshing.is_set():
                    break
                threading.Event().wait(0.02)
        self.assertEqual(len(calls), 1)

    def test_empty_cache_non_blocking_returns_placeholder(self):
        with patch("eth_rpc.is_test_environment", return_value=False), \
             patch("eth_rpc.get_rpc_health_status", side_effect=lambda: threading.Event().wait(1) or {}):
            got = eth_rpc.get_cached_rpc_health_status()
        self.assertIn("mainnet", got)
        self.assertTrue(got["mainnet"].get("checking"))


# ---------------------------------------------------------------------- 6. pending contract creation
class TestPendingContractCreation(unittest.TestCase):
    DEST = "0x000000000000000000000000000000000000dEaD"

    def _w3(self, tx):
        w3 = MagicMock()
        w3.eth.get_transaction_receipt.side_effect = Exception("not mined")
        w3.eth.get_transaction.return_value = tx
        return w3

    def test_unmined_contract_creation_fails_immediately(self):
        tx = {"from": Account.create().address, "to": None, "value": 10**16}
        with patch("eth_rpc.get_w3_with_source", return_value=(self._w3(tx), "mainnet_primary")):
            res = eth_rpc.verify_onchain_payment_transaction("0x" + "ab" * 32, 1, expected_recipient=self.DEST)
        self.assertEqual(res["status"], "failed")
        self.assertIn("Recipient mismatch", res["reason"])

    def test_unmined_correct_recipient_is_still_pending(self):
        tx = {"from": Account.create().address, "to": self.DEST, "value": 10**16}
        with patch("eth_rpc.get_w3_with_source", return_value=(self._w3(tx), "mainnet_primary")):
            res = eth_rpc.verify_onchain_payment_transaction("0x" + "cd" * 32, 1, expected_recipient=self.DEST)
        self.assertEqual(res["status"], "pending")


# ---------------------------------------------------------------------- 7. pins, schema cache, emoji
class TestChatFeaturesDbFixes(_Fixtures):
    __test__ = True

    def test_concurrent_pins_never_exceed_limit(self):
        scope = "group:grp_" + secrets.token_hex(6)
        errors = []

        def pin(i):
            try:
                chat_features_db.set_pin(scope, f"msg_{i:03d}", "usr_tester", True)
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        # Widen the read-then-write window (the timestamp is computed between the pin-count read
        # and the INSERT) so the old non-atomic version reliably overshoots the limit.
        real_now = chat_features_db._now

        def slow_now():
            threading.Event().wait(0.01)
            return real_now()

        with patch("chat_features_db._now", side_effect=slow_now):
            threads = [threading.Thread(target=pin, args=(i,)) for i in range(24)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(errors, [])
        self.assertLessEqual(len(chat_features_db.list_pins(scope)), chat_features_db.PIN_LIMIT)
        self.assertEqual(len(chat_features_db.list_pins(scope)), chat_features_db.PIN_LIMIT)

    def test_fourth_pin_replaces_oldest(self):
        scope = "dm:conv_" + secrets.token_hex(6)
        for i in range(3):
            chat_features_db.set_pin(scope, f"m{i}", "u", True)
        res = chat_features_db.set_pin(scope, "m3", "u", True)
        ids = {p["message_id"] for p in res["pins"]}
        self.assertEqual(len(ids), 3)
        self.assertIn("m3", ids)
        self.assertIsNotNone(res["replaced"])
        # unpin still works
        res = chat_features_db.set_pin(scope, "m3", "u", False)
        self.assertNotIn("m3", {p["message_id"] for p in res["pins"]})

    def test_identical_timestamps_still_evict_the_oldest_pin(self):
        """Windows clocks tick ~1 ms: several pins can get the same time. The oldest must still go."""
        from datetime import datetime, timezone
        frozen = datetime(2026, 11, 28, 12, 0, 0, tzinfo=timezone.utc)
        scope = "group:grp_" + secrets.token_hex(6)
        with patch("chat_features_db._now", return_value=frozen):
            for mid in ("first", "second", "third"):
                chat_features_db.set_pin(scope, mid, "u", True)
            res = chat_features_db.set_pin(scope, "fourth", "u", True)
        self.assertEqual(res["replaced"], "first")
        self.assertEqual([p["message_id"] for p in res["pins"]], ["fourth", "third", "second"])

    def test_schema_cache_keys_on_identity_not_id(self):
        chat_features_db._ensure_schema()
        current = chat_features_db.chat_db._sqlite_conn
        self.assertIs(chat_features_db._ready_for, current)
        self.assertNotIsInstance(chat_features_db._ready_for, int)


class TestReactionEmojiValidation(unittest.TestCase):
    GOOD = ["👍", "👍🏽", "❤️", "❤", "1️⃣", "#️⃣", "*️⃣", "🇺🇬", "👨‍👩‍👧‍👦", "👩🏽‍💻", "🏴󠁧󠁢󠁥󠁮󠁧󠁿", "😂", "🙏", "✅"]
    BAD = ["abc", "1", "#", "Привет", "ж", "中文", "αβ", "👍👍", "<b>", "", "👍a", "🇺", "1️", "👍‍", "x" * 40]

    def test_accepts_real_emoji_including_keycaps(self):
        for e in self.GOOD:
            self.assertEqual(chat_features_db.clean_reaction_emoji(e), e, e)

    def test_rejects_text_in_any_script(self):
        for e in self.BAD:
            with self.assertRaises(ValueError, msg=repr(e)):
                chat_features_db.clean_reaction_emoji(e)


class TestTestEnvironmentDetection(unittest.TestCase):
    def test_pytest_or_unittest_or_flag_all_count(self):
        with patch.dict(os.environ, {"TESTING": "0"}):
            # unittest is always imported here
            self.assertTrue(eth_rpc.is_test_environment())
        with patch.dict(os.environ, {"TESTING": "1"}):
            self.assertTrue(eth_rpc.is_test_environment())


if __name__ == "__main__":
    unittest.main()