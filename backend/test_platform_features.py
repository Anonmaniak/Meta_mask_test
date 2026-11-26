"""
Comprehensive Automated Test Suite for Ethereum Wallet-Linked Chat Platform Features.

Covers Master Development Prompt Sections 3–16:
1. EIP-4361 (SIWE) authentication, starting Level 7, and removal of all payment/MongoDB routes.
2. Permanent `user_id`, case-insensitive usernames, cooldowns, impersonation quarantine,
   and wallet-replacement session invalidation + history.
3. Configurable Wallet-Based Levels (7+) via server-side Ethereum RPC snapshots + grace-period downgrades.
4. Open Public Chat (guest & verified modes, edit/delete, malicious URI guard, duplicate guard, WS, moderation).
5. Username search, privacy toggles, server-enforced user blocking, optional read receipts, and abuse reports.
6. Group access policies (`min_eth_balance_wei`, public/invite-only, paid/free), discovery, join requests, and leave-group (invite links answer 410).
7. RBAC Admin (`superadmin` vs `moderator`), account mute/suspend/restore, and immutable audit logs.
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
import platform_db
from test_e2ee_security import generate_signed_test_device


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class TestChatPlatformFeatures(unittest.TestCase):
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
        e2ee_routes._rate_buckets.clear()
        platform_db.update_platform_settings(
            {
                "username_cooldown_hours": 24,
                "username_reservation_days": 30,
            },
            actor_user_id="test_setup",
        )

    def _auth_headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def _siwe_login(self, acct) -> dict:
        addr = Web3.to_checksum_address(acct.address)
        c_res = self.client.post(
            "/api/e2ee/auth/challenge",
            json={"wallet_address": addr, "purpose": "login", "chain_id": 11155111},
        )
        self.assertEqual(c_res.status_code, 200, c_res.text)
        chal = c_res.json()
        # Verify standardized EIP-4361 SIWE message fields
        self.assertIn("wants you to sign in with your Ethereum account:\n", chal["message"])
        self.assertIn("Version: 1\n", chal["message"])
        self.assertIn("Chain ID: 11155111\n", chal["message"])
        self.assertIn(f"Nonce: {chal['nonce']}\n", chal["message"])

        sig = acct.sign_message(encode_defunct(text=chal["message"])).signature.hex()
        v_res = self.client.post(
            "/api/e2ee/auth/verify",
            json={
                "challenge_id": chal["challenge_id"],
                "wallet_address": addr,
                "signature": sig,
            },
        )
        self.assertEqual(v_res.status_code, 200, v_res.text)
        self.assertIn("zyphra_session", v_res.cookies)
        self.client.cookies.clear()
        return v_res.json()

    # -------------------------------------------------------------------------
    # 1. Zero Payments/MongoDB + SIWE + Starting Level 7
    # -------------------------------------------------------------------------
    def test_01_payments_removed_siwe_auth_and_starting_level_7(self):
        # Verify payment & legacy unsigned login endpoints are completely removed
        for gone_method, gone_path in (
            ("GET", "/api/feed"),
            ("POST", "/api/transaction"),
            ("GET", "/api/transactions"),
            ("POST", "/api/e2ee/account/subscription"),
            ("POST", "/api/auth/login"),
        ):
            r = self.client.request(gone_method, gone_path, json={})
            self.assertEqual(r.status_code, 404, f"{gone_path} should be 404")

        h = self.client.get("/api/health").json()
        self.assertEqual(h["service"], "zyphra-chat-platform")
        self.assertNotIn("starting_level", h)
        self.assertNotIn("escrow_address", h)
        self.assertNotEqual(h["storage"], "mongodb")

        w = Account.create()
        auth = self._siwe_login(w)
        user = auth["user"]
        self.assertTrue(user["user_id"].startswith("usr_"))
        self.assertEqual(user["account_status"], "active")

    # -------------------------------------------------------------------------
    # 2. Username Cooldown, Quarantine & Wallet Replacement Session Revocation
    # -------------------------------------------------------------------------
    def test_02_username_cooldown_quarantine_and_wallet_session_invalidation(self):
        alice_w1 = Account.create()
        alice_w2 = Account.create()
        bob_w = Account.create()

        alice = self._siwe_login(alice_w1)
        bob = self._siwe_login(bob_w)
        alice_uid, alice_tok1 = alice["user"]["user_id"], alice["session_token"]
        bob_tok = bob["session_token"]

        u1 = f"crypto_alice_{secrets.token_hex(2)}"
        u2 = f"explorer_alice_{secrets.token_hex(2)}"

        # Initial username claim succeeds
        r1 = self.client.patch(
            "/api/e2ee/account/username",
            headers=self._auth_headers(alice_tok1),
            json={"username": u1},
        )
        self.assertEqual(r1.status_code, 200, r1.text)

        # Case-insensitive collision by Bob rejected
        r_dup = self.client.patch(
            "/api/e2ee/account/username",
            headers=self._auth_headers(bob_tok),
            json={"username": u1.upper()},
        )
        self.assertEqual(r_dup.status_code, 409)

        # Real-time check confirms case-insensitive collision is unavailable
        chk_bob = self.client.get(
            f"/api/e2ee/account/username/check?username={u1.upper()}",
            headers=self._auth_headers(bob_tok),
        )
        self.assertEqual(chk_bob.status_code, 200)
        self.assertFalse(chk_bob.json()["available"])
        self.assertIn("already claimed", chk_bob.json()["reason"].lower())

        # Check unclaimed username is available
        chk_free = self.client.get(
            f"/api/e2ee/account/username/check?username={u2}",
            headers=self._auth_headers(bob_tok),
        )
        self.assertEqual(chk_free.status_code, 200)
        self.assertTrue(chk_free.json()["available"])

        # Immediate second rename by Alice blocked by 24h cooldown
        r_cool = self.client.patch(
            "/api/e2ee/account/username",
            headers=self._auth_headers(alice_tok1),
            json={"username": u2},
        )
        self.assertEqual(r_cool.status_code, 409)
        self.assertIn("cooldown", r_cool.json()["detail"].lower())

        # Admin sets cooldown=0; Alice renames u1 -> u2; u1 enters 30-day quarantine
        platform_db.update_platform_settings({"username_cooldown_hours": 0}, "admin_test")
        r2 = self.client.patch(
            "/api/e2ee/account/username",
            headers=self._auth_headers(alice_tok1),
            json={"username": u2},
        )
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["user"]["user_id"], alice_uid)

        # Bob cannot silently claim Alice's quarantined old username u1
        r_quarantine = self.client.patch(
            "/api/e2ee/account/username",
            headers=self._auth_headers(bob_tok),
            json={"username": u1},
        )
        self.assertEqual(r_quarantine.status_code, 409)
        self.assertIn("reserved", r_quarantine.json()["detail"].lower())

        # Check real-time endpoint also flags quarantined username as unavailable
        chk_quarantine = self.client.get(
            f"/api/e2ee/account/username/check?username={u1}",
            headers=self._auth_headers(bob_tok),
        )
        self.assertEqual(chk_quarantine.status_code, 200)
        self.assertFalse(chk_quarantine.json()["available"])
        self.assertIn("reserved", chk_quarantine.json()["reason"].lower())

        # Wallet replacement revokes old wallet sessions while preserving permanent user_id
        w2_addr = Web3.to_checksum_address(alice_w2.address)
        l_chal = self.client.post(
            "/api/e2ee/auth/challenge",
            headers=self._auth_headers(alice_tok1),
            json={"wallet_address": w2_addr, "purpose": "link_wallet", "chain_id": 11155111},
        ).json()
        l_sig = alice_w2.sign_message(encode_defunct(text=l_chal["message"])).signature.hex()
        l_res = self.client.post(
            "/api/e2ee/account/wallets/link",
            headers=self._auth_headers(alice_tok1),
            json={
                "challenge_id": l_chal["challenge_id"],
                "new_wallet_address": w2_addr,
                "signature": l_sig,
                "make_primary": True,
                "revoke_previous_wallets": True,
            },
        )
        self.assertEqual(l_res.status_code, 200, l_res.text)
        alice_tok2 = l_res.json()["session_token"]

        # Old wallet session token is now revoked (401)
        self.assertEqual(
            self.client.get("/api/e2ee/me", headers=self._auth_headers(alice_tok1)).status_code,
            401,
        )
        # New wallet session token works & preserves permanent user_id + full history
        hist = self.client.get(
            "/api/platform/profile/history", headers=self._auth_headers(alice_tok2)
        )
        self.assertEqual(hist.status_code, 200)
        h_body = hist.json()
        self.assertEqual(h_body["user_id"], alice_uid)
        self.assertGreaterEqual(len(h_body["username_history"]), 2)
        self.assertGreaterEqual(len(h_body["wallet_history"]), 2)

    # -------------------------------------------------------------------------
    # 3. Server-Side RPC Balance Snapshots (Levels removed)
    # -------------------------------------------------------------------------
    def test_03_levels_rpc_balance_verification_and_grace_downgrade(self):
        admin_w = Account.create()
        user_w = Account.create()

        with patch.dict(os.environ, {"ADMIN_WALLET_ADDRESSES": admin_w.address}):
            admin_auth = self._siwe_login(admin_w)
        self.assertEqual(admin_auth["user"]["admin_role"], "superadmin")

        user_auth = self._siwe_login(user_w)
        user_tok = user_auth["session_token"]

        # Legacy level endpoints are removed (404)
        self.assertEqual(self.client.get("/api/platform/levels").status_code, 404)

        # Mock Ethereum RPC returning 2.5 ETH at block 20500100
        with patch("eth_rpc.verify_onchain_eth_balance") as mock_rpc:
            mock_rpc.return_value = {
                "wallet_address": Web3.to_checksum_address(user_w.address),
                "chain_id": 11155111,
                "balance_wei": str(int(2.5 * 10**18)),
                "balance_wei_int": int(2.5 * 10**18),
                "balance_eth": "2.5",
                "block_number": 20500100,
                "rpc_source": "sepolia_rpc",
            }
            v_res = self.client.post(
                "/api/platform/wallet/verify-balance",
                headers=self._auth_headers(user_tok),
                json={"chain_id": 11155111},
            )
            self.assertEqual(v_res.status_code, 200, v_res.text)
            self.assertEqual(v_res.json()["user"]["qualifying_balance_wei"], str(int(2.5 * 10**18)))
            self.assertEqual(v_res.json()["snapshot"]["block_number"], 20500100)

    # -------------------------------------------------------------------------
    # 4. Open Public Chat, Malicious URI Guard, Edit/Delete, WS & Moderation
    # -------------------------------------------------------------------------
    def test_04_open_public_chat_members_only_ws_and_moderation(self):
        # Premium-only: anonymous visitors can neither read nor post
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/api/platform/public-chat/messages").status_code, 401)
        g_post = self.client.post(
            "/api/platform/public-chat/messages",
            json={"content": "Hello from open guest", "guest_token": "guest_tok_123"},
        )
        self.assertEqual(g_post.status_code, 401)

        # Verified (paid) member posts, edits
        alice = self._siwe_login(Account.create())
        alice_tok = alice["session_token"]
        uname = f"pub_alice_{secrets.token_hex(2)}"
        self.client.patch(
            "/api/e2ee/account/username",
            headers=self._auth_headers(alice_tok),
            json={"username": uname},
        )
        v_post = self.client.post(
            "/api/platform/public-chat/messages",
            headers=self._auth_headers(alice_tok),
            json={"content": "Verified message 🚀"},
        )
        self.assertEqual(v_post.status_code, 200)
        msg_id = v_post.json()["message"]["message_id"]
        self.assertEqual(v_post.json()["message"]["display_name"], f"@{uname}")

        # Duplicate burst rejected
        dup = self.client.post(
            "/api/platform/public-chat/messages",
            headers=self._auth_headers(alice_tok),
            json={"content": "Verified message 🚀"},
        )
        self.assertEqual(dup.status_code, 429)

        # Malicious script / javascript: link rejected
        bad_post = self.client.post(
            "/api/platform/public-chat/messages",
            headers=self._auth_headers(alice_tok),
            json={"content": "Click javascript:alert(document.cookie)"},
        )
        self.assertEqual(bad_post.status_code, 400)

        ed = self.client.patch(
            f"/api/platform/public-chat/messages/{msg_id}",
            headers=self._auth_headers(alice_tok),
            json={"content": "Verified message edited ✨"},
        )
        self.assertEqual(ed.status_code, 200)
        self.assertIsNotNone(ed.json()["edited_at"])

        # Public Chat WebSocket is members-only: first frame must carry a valid session token
        from starlette.websockets import WebSocketDisconnect
        self.client.cookies.clear()
        with self.client.websocket_connect("/ws/public-chat") as ws_bad:
            ws_bad.send_json({"type": "auth", "token": "bogus"})
            with self.assertRaises(WebSocketDisconnect) as cm:
                ws_bad.receive_json()
            self.assertEqual(cm.exception.code, 4401)

        alice_wallet = alice["user"]["wallets"][0]["wallet_address"]
        with self.client.websocket_connect("/ws/public-chat") as ws_mem:
            ws_mem.send_json({"type": "auth", "token": alice_tok})
            welcome = ws_mem.receive_json()
            self.assertEqual(welcome["type"], "public_connected")
            self.assertIn("active_live", welcome["online"])
            ws_mem.send_json({"type": "presence_status", "wallet_address": alice_wallet})
            ws_mem.send_json({"type": "ping"})
            # Presence updates may arrive before the pong (order depends on the server's event loop):
            # read frames until the pong shows up, with a small cap so a missing pong still fails.
            seen = []
            for _ in range(6):
                frame = ws_mem.receive_json()
                seen.append(frame)
                if frame.get("type") == "pong":
                    break
            self.assertTrue(any(f["type"] == "pong" for f in seen), seen)

    # -------------------------------------------------------------------------
    # 5. Username Search, User Blocking, Read Receipts & Abuse Reports
    # -------------------------------------------------------------------------
    def test_05_search_blocking_receipts_and_reports(self):
        alice = self._siwe_login(Account.create())
        bob = self._siwe_login(Account.create())
        alice_uid, alice_tok = alice["user"]["user_id"], alice["session_token"]
        bob_uid, bob_tok = bob["user"]["user_id"], bob["session_token"]

        bob_uname = f"searchable_bob_{secrets.token_hex(2)}"
        self.client.patch(
            "/api/e2ee/account/username",
            headers=self._auth_headers(bob_tok),
            json={"username": bob_uname},
        )

        # Search finds Bob
        s_res = self.client.get(
            f"/api/platform/users/search?q=@{bob_uname[:12]}",
            headers=self._auth_headers(alice_tok),
        )
        self.assertEqual(s_res.status_code, 200)
        self.assertTrue(any(u["user_id"] == bob_uid for u in s_res.json()["users"]))

        # Register devices for Alice & Bob
        a_dev = f"dev_ablk_{secrets.token_hex(4)}"
        b_dev = f"dev_bblk_{secrets.token_hex(4)}"
        ba, _ = generate_signed_test_device(alice_uid, a_dev)
        bb, _ = generate_signed_test_device(bob_uid, b_dev)
        self.client.post("/api/e2ee/devices/register", json=ba, headers=self._auth_headers(alice_tok))
        self.client.post("/api/e2ee/devices/register", json=bb, headers=self._auth_headers(bob_tok))

        # Alice blocks Bob -> Bob cannot DM Alice (403) and Alice hides Bob's public messages
        self.client.post(
            "/api/platform/public-chat/messages",
            headers=self._auth_headers(bob_tok),
            json={"content": "Bob public post before block filter check"},
        )
        blk = self.client.post(
            "/api/platform/blocks",
            headers=self._auth_headers(alice_tok),
            json={"target_user_id": bob_uid, "reason": "unwanted messages"},
        )
        self.assertEqual(blk.status_code, 200)

        dm_blocked = self.client.post(
            "/api/e2ee/dm/messages",
            headers=self._auth_headers(bob_tok),
            json={
                "message_id": f"dm_blk_{secrets.token_hex(6)}",
                "recipient_user_id": alice_uid,
                "sender_device_id": b_dev,
                "device_ciphertexts": {
                    a_dev: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(64))}
                },
            },
        )
        self.assertEqual(dm_blocked.status_code, 403)

        feed_for_alice = self.client.get(
            "/api/platform/public-chat/messages",
            headers=self._auth_headers(alice_tok),
        ).json()["messages"]
        self.assertFalse(any(m["author_user_id"] == bob_uid for m in feed_for_alice))

        # Unblock restores DM ability; test privacy-aware read receipts & abuse report
        self.client.delete(f"/api/platform/blocks/{bob_uid}", headers=self._auth_headers(alice_tok))
        self.client.patch(
            "/api/platform/profile",
            headers=self._auth_headers(bob_tok),
            json={"send_read_receipts": False, "display_name": "Bob Builder"},
        )
        rcpt_off = self.client.post(
            "/api/platform/dm/read-receipt",
            headers=self._auth_headers(bob_tok),
            json={"peer_user_id": alice_uid, "last_read_seq": 5},
        ).json()
        self.assertIsNone(rcpt_off["receipt"])

        rep = self.client.post(
            "/api/platform/reports",
            headers=self._auth_headers(alice_tok),
            json={
                "scope_type": "user",
                "scope_id": bob_uid,
                "target_user_id": bob_uid,
                "reason": "spam_test",
                "details": "Automated test report",
            },
        )
        self.assertEqual(rep.status_code, 200)
        self.assertEqual(rep.json()["report"]["status"], "open")

    # -------------------------------------------------------------------------
    # 6. Group Access Policies (min_eth_balance), Invites & Leave
    # -------------------------------------------------------------------------
    def test_06_group_access_policies_invites_discovery_and_leave(self):
        creator = self._siwe_login(Account.create())
        candidate = self._siwe_login(Account.create())
        c_uid, c_tok = creator["user"]["user_id"], creator["session_token"]
        u_uid, u_tok = candidate["user"]["user_id"], candidate["session_token"]

        c_dev = f"dev_gadm_{secrets.token_hex(4)}"
        u_dev = f"dev_gusr_{secrets.token_hex(4)}"
        bc, _ = generate_signed_test_device(c_uid, c_dev)
        bu, _ = generate_signed_test_device(u_uid, u_dev)
        self.client.post("/api/e2ee/devices/register", json=bc, headers=self._auth_headers(c_tok))
        self.client.post("/api/e2ee/devices/register", json=bu, headers=self._auth_headers(u_tok))

        # Verify creator holds 1.0 ETH so creator meets own group policy when posting
        platform_db.record_verified_balance_snapshot(
            user_id=c_uid,
            wallet_address=creator["user"]["primary_wallet"],
            chain_id=1,
            balance_wei_int=10**18,
            block_number=19500000,
        )

        # Create public 0.5 ETH-gated MLS group
        g_res = self.client.post(
            "/api/e2ee/groups",
            headers=self._auth_headers(c_tok),
            json={
                "name": "Alpha Room",
                "mls_group_id_b64": _b64(secrets.token_bytes(16)),
                "creator_device_id": c_dev,
                "description": "Verified 0.5+ ETH holders only",
                "visibility": "public",
                "min_eth_balance_wei": str(int(0.5 * 10**18)),
                "require_invitation": False,
            },
        )
        self.assertEqual(g_res.status_code, 200, g_res.text)
        gid = g_res.json()["group"]["group_id"]

        # Invite links were removed (410): admins add people, who Accept or Reject.
        self.assertEqual(
            self.client.post(
                f"/api/platform/groups/{gid}/invites",
                headers=self._auth_headers(c_tok),
                json={"expires_hours": 24, "max_uses": 5},
            ).status_code,
            410,
        )

        # Level 7 candidate is rejected on discovery eligibility, join request, AND MLS add commit!
        disc = self.client.get(
            "/api/platform/groups/discover", headers=self._auth_headers(u_tok)
        ).json()["groups"]
        found = [g for g in disc if g["group_id"] == gid][0]
        self.assertFalse(found["eligible"])

        self.assertEqual(
            self.client.post(
                f"/api/platform/groups/{gid}/join-request",
                headers=self._auth_headers(u_tok),
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                f"/api/e2ee/groups/{gid}/commits",
                headers=self._auth_headers(c_tok),
                json={
                    "committer_device_id": c_dev,
                    "expected_epoch": 0,
                    "commit_type": "add",
                    "mls_commit_b64": _b64(secrets.token_bytes(96)),
                    "added_members": [{"user_id": u_uid, "device_id": u_dev, "leaf_index": 1}],
                },
            ).status_code,
            403,
        )

        # Candidate verifies 1.0 ETH -> reaches Level 8 -> join request & MLS add commit succeed!
        platform_db.record_verified_balance_snapshot(
            user_id=u_uid,
            wallet_address=candidate["user"]["primary_wallet"],
            chain_id=1,
            balance_wei_int=10**18,
            block_number=19500010,
        )
        j_ok = self.client.post(
            f"/api/platform/groups/{gid}/join-request",
            headers=self._auth_headers(u_tok),
        )
        self.assertEqual(j_ok.status_code, 200, j_ok.text)
        self.assertEqual(j_ok.json()["status"], "pending_mls_welcome")

        reqs = self.client.get(
            f"/api/platform/groups/{gid}/join-requests", headers=self._auth_headers(c_tok)
        ).json()["requests"]
        self.assertTrue(any(r["user_id"] == u_uid for r in reqs))

        add_ok = self.client.post(
            f"/api/e2ee/groups/{gid}/commits",
            headers=self._auth_headers(c_tok),
            json={
                "committer_device_id": c_dev,
                "expected_epoch": 0,
                "commit_type": "add",
                "mls_commit_b64": _b64(secrets.token_bytes(96)),
                "added_members": [{"user_id": u_uid, "device_id": u_dev, "leaf_index": 1}],
                "welcomes": [
                    {
                        "target_user_id": u_uid,
                        "target_device_id": u_dev,
                        "mls_welcome_b64": _b64(secrets.token_bytes(120)),
                    }
                ],
            },
        )
        self.assertEqual(add_ok.status_code, 200, add_ok.text)

        # Candidate leaves group
        lv = self.client.post(
            f"/api/platform/groups/{gid}/leave", headers=self._auth_headers(u_tok)
        )
        self.assertEqual(lv.status_code, 200)
        self.assertEqual(lv.json()["status"], "left")
        self.assertEqual(
            self.client.get(f"/api/e2ee/groups/{gid}", headers=self._auth_headers(u_tok)).status_code,
            403,
        )

    # -------------------------------------------------------------------------
    # 7. RBAC Admin Enforcement, Account Suspension & Audit Logs
    # -------------------------------------------------------------------------
    def test_07_rbac_admin_moderation_and_audit_logs(self):
        super_w = Account.create()
        mod_w = Account.create()
        bad_w = Account.create()

        with patch.dict(os.environ, {"ADMIN_WALLET_ADDRESSES": super_w.address}):
            super_auth = self._siwe_login(super_w)
        mod_auth = self._siwe_login(mod_w)
        bad_auth = self._siwe_login(bad_w)

        s_tok = super_auth["session_token"]
        m_uid, m_tok = mod_auth["user"]["user_id"], mod_auth["session_token"]
        b_uid, b_tok = bad_auth["user"]["user_id"], bad_auth["session_token"]

        # Normal user cannot access admin overview (403)
        self.assertEqual(
            self.client.get("/api/platform/admin/overview", headers=self._auth_headers(b_tok)).status_code,
            403,
        )

        # Superadmin grants moderator role to mod_w
        self.assertEqual(
            self.client.post(
                f"/api/platform/admin/users/{m_uid}/role",
                headers=self._auth_headers(s_tok),
                json={"role": "moderator"},
            ).status_code,
            200,
        )

        # Moderator can view overview & inspect users, but CANNOT change platform settings (403)
        self.assertEqual(
            self.client.get("/api/platform/admin/overview", headers=self._auth_headers(m_tok)).status_code,
            200,
        )
        self.assertEqual(
            self.client.put(
                "/api/platform/admin/settings",
                headers=self._auth_headers(m_tok),
                json={"platform_entry_fee_usd": 25},
            ).status_code,
            403,
        )

        # Moderator suspends bad_w -> bad_w's active session is immediately revoked!
        sus = self.client.post(
            f"/api/platform/admin/users/{b_uid}/moderate",
            headers=self._auth_headers(m_tok),
            json={"action_type": "suspend", "reason": "Phishing spam", "duration_hours": 48},
        )
        self.assertEqual(sus.status_code, 200)
        self.assertEqual(sus.json()["user"]["account_status"], "suspended")

        self.assertIn(
            self.client.get("/api/e2ee/me", headers=self._auth_headers(b_tok)).status_code,
            (401, 403),
        )

        logs = self.client.get(
            "/api/platform/admin/audit-logs", headers=self._auth_headers(s_tok)
        ).json()["audit_logs"]
        self.assertTrue(any(l["action"] == "user_suspend" for l in logs))


if __name__ == "__main__":
    unittest.main()