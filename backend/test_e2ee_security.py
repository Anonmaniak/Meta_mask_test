"""
Comprehensive Security Verification Suite for Section 17 High-Security E2EE.

Covers Section K Release & Security Verification Requirements:
- K.1: Server receives & stores ciphertext only; rejects plaintext/secret fields.
- K.2: Database administrators cannot decrypt private/group messages or read raw session tokens.
- K.3: Auth failures, signature forgery, key substitution, challenge/message replay, and
       unauthorized DM/group/public-channel retrieval all fail closed.
- K.4: RFC 9420 MLS group member addition (pre-join secrecy), removal (post-removal block),
       and optimistic epoch concurrency (`409 Conflict` with `missing_commits`).
- K.5: Permanent `user_id` stability across username changes, authenticated wallet rotation,
       device revocation, subscription downgrade/expiry independence, and lost-key reset.
- K.6: Application logs and 422/500 error responses never leak plaintexts, private keys,
       seed phrases, bearer tokens, or client IP addresses.
- K.7: Strict Content-Security-Policy & browser security headers + authenticated `/ws/e2ee`
       WebSocket without query-string token leakage.
- Section I: Encrypted attachment SHA-256 integrity check, scope authorization, and revocation.
"""

import io
import os
import sys
import base64
import hashlib
import secrets
import unittest
from contextlib import redirect_stdout
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from app import app
import chat_db
import e2ee_db
import e2ee_routes


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def generate_signed_test_device(user_id: str, device_id: str, otk_count: int = 2):
    """Generates real Ed25519 + X25519 device keys and signs the canonical bundle."""
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub_b64 = _b64(
        ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    curve_priv = X25519PrivateKey.generate()
    curve_pub_b64 = _b64(
        curve_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    fb_priv = X25519PrivateKey.generate()
    fb_id = "fb_01"
    fb_pub_b64 = _b64(
        fb_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )

    otks = {}
    for i in range(otk_count):
        otk_priv = X25519PrivateKey.generate()
        otks[f"otk_{i:02d}"] = _b64(
            otk_priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    canonical = e2ee_routes.build_canonical_device_bundle_payload(
        user_id=user_id,
        device_id=device_id,
        ed25519_identity_key=ed_pub_b64,
        curve25519_identity_key=curve_pub_b64,
        fallback_key_id=fb_id,
        fallback_public_key=fb_pub_b64,
    )
    sig_b64 = _b64(ed_priv.sign(canonical.encode("utf-8")))

    kp_bytes = secrets.token_bytes(96)
    kp_ref = hashlib.sha256(kp_bytes).hexdigest()

    payload = {
        "device_id": device_id,
        "device_label": f"Device {device_id[-6:]}",
        "ed25519_identity_key": ed_pub_b64,
        "curve25519_identity_key": curve_pub_b64,
        "fallback_key_id": fb_id,
        "fallback_public_key": fb_pub_b64,
        "bundle_signature": sig_b64,
        "one_time_keys": otks,
        "mls_key_packages": [
            {
                "package_id": f"mkp_{kp_ref[:20]}",
                "ciphersuite": e2ee_routes.MLS_CIPHERSUITE_ID,
                "key_package_b64": _b64(kp_bytes),
                "key_package_ref": kp_ref,
            }
        ],
    }
    return payload, ed_priv


class TestE2EESecurityArchitecture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Isolate security tests in an in-memory SQLite engine so live Neon DB stays clean
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

    def _authenticate_wallet(self, acct) -> dict:
        addr = Web3.to_checksum_address(acct.address)
        c_res = self.client.post(
            "/api/e2ee/auth/challenge",
            json={"wallet_address": addr, "purpose": "login", "chain_id": 1},
        )
        self.assertEqual(c_res.status_code, 200, c_res.text)
        chal = c_res.json()

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
        data = v_res.json()
        # Clear TestClient cookie jar so each request uses explicit Authorization headers
        self.client.cookies.clear()
        return data

    def _auth_headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    # -------------------------------------------------------------------------
    # K.1 & K.2: Ciphertext-Only Storage & DBA Non-Decryptability
    # -------------------------------------------------------------------------
    def test_01_ciphertext_only_and_dba_inspection(self):
        alice_wallet = Account.create()
        bob_wallet = Account.create()

        alice_auth = self._authenticate_wallet(alice_wallet)
        bob_auth = self._authenticate_wallet(bob_wallet)

        alice_uid = alice_auth["user"]["user_id"]
        bob_uid = bob_auth["user"]["user_id"]
        alice_tok = alice_auth["session_token"]
        bob_tok = bob_auth["session_token"]

        alice_dev_id = f"dev_alice_{secrets.token_hex(6)}"
        bob_dev_id = f"dev_bob_{secrets.token_hex(6)}"
        alice_bundle, _ = generate_signed_test_device(alice_uid, alice_dev_id)
        bob_bundle, _ = generate_signed_test_device(bob_uid, bob_dev_id)

        self.assertEqual(
            self.client.post(
                "/api/e2ee/devices/register",
                json=alice_bundle,
                headers=self._auth_headers(alice_tok),
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/api/e2ee/devices/register",
                json=bob_bundle,
                headers=self._auth_headers(bob_tok),
            ).status_code,
            200,
        )

        # Attempting to submit plaintext or private keys MUST be rejected (HTTP 422)
        for forbidden_field in ("plaintext", "message", "text", "private_key", "seed_phrase"):
            bad_res = self.client.post(
                "/api/e2ee/dm/messages",
                headers=self._auth_headers(alice_tok),
                json={
                    "message_id": f"dm_bad_{secrets.token_hex(6)}",
                    "recipient_user_id": bob_uid,
                    "sender_device_id": alice_dev_id,
                    "device_ciphertexts": {
                        bob_dev_id: {
                            "message_type": 0,
                            "ciphertext_b64": _b64(secrets.token_bytes(64)),
                        }
                    },
                    forbidden_field: "DO_NOT_ACCEPT_PLAINTEXT_OR_KEYS",
                },
            )
            self.assertEqual(bad_res.status_code, 422, f"Field {forbidden_field} must fail closed")

        # Valid opaque Olm v2 ciphertext submission succeeds
        opaque_ct = _b64(secrets.token_bytes(96))
        msg_id = f"dm_ok_{secrets.token_hex(8)}"
        send_res = self.client.post(
            "/api/e2ee/dm/messages",
            headers=self._auth_headers(alice_tok),
            json={
                "message_id": msg_id,
                "recipient_user_id": bob_uid,
                "sender_device_id": alice_dev_id,
                "device_ciphertexts": {
                    bob_dev_id: {"message_type": 0, "ciphertext_b64": opaque_ct},
                    alice_dev_id: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(96))},
                },
            },
        )
        self.assertEqual(send_res.status_code, 200, send_res.text)
        sent_data = send_res.json()
        # Verify metadata minimization: coarse 1-minute UTC timestamp bucketing
        self.assertTrue(
            sent_data["timestamp"].endswith(":00+00:00"),
            f"Expected 1-minute bucketed UTC timestamp, got {sent_data['timestamp']}",
        )

        # Simulate DBA reading raw SQL tables directly
        cur = chat_db._sqlite_conn.cursor()
        cur.execute("SELECT * FROM chat_dm_messages WHERE message_id = ?", (msg_id,))
        raw_dm_row = dict(cur.fetchone())
        self.assertIn(opaque_ct, raw_dm_row["ciphertexts_json"])
        for col_name in raw_dm_row.keys():
            self.assertNotIn(col_name, ("plaintext", "message", "text", "private_key"))

        # Verify raw session tokens are SHA-256 hashed at rest (DBA cannot steal bearer token)
        cur.execute("SELECT * FROM chat_auth_sessions")
        session_rows = [dict(r) for r in cur.fetchall()]
        self.assertGreaterEqual(len(session_rows), 2)
        serialized_sessions = str(session_rows)
        self.assertNotIn(alice_tok, serialized_sessions)
        self.assertNotIn(bob_tok, serialized_sessions)

    # -------------------------------------------------------------------------
    # K.3: Auth Failures, Key Substitution, Replay & Unauthorized Retrieval
    # -------------------------------------------------------------------------
    def test_02_auth_forgery_key_substitution_replay_and_unauthorized_access(self):
        alice_wallet = Account.create()
        bob_wallet = Account.create()
        eve_wallet = Account.create()

        # 1. Signer mismatch on challenge verification -> 401
        alice_addr = Web3.to_checksum_address(alice_wallet.address)
        c_res = self.client.post(
            "/api/e2ee/auth/challenge",
            json={"wallet_address": alice_addr, "purpose": "login", "chain_id": 1},
        ).json()
        wrong_sig = eve_wallet.sign_message(encode_defunct(text=c_res["message"])).signature.hex()
        bad_verify = self.client.post(
            "/api/e2ee/auth/verify",
            json={
                "challenge_id": c_res["challenge_id"],
                "wallet_address": alice_addr,
                "signature": wrong_sig,
            },
        )
        self.assertEqual(bad_verify.status_code, 401)

        # 2. Replay of already-consumed challenge_id -> 401
        c_res2 = self.client.post(
            "/api/e2ee/auth/challenge",
            json={"wallet_address": alice_addr, "purpose": "login", "chain_id": 1},
        ).json()
        good_sig = alice_wallet.sign_message(encode_defunct(text=c_res2["message"])).signature.hex()
        ok_verify = self.client.post(
            "/api/e2ee/auth/verify",
            json={
                "challenge_id": c_res2["challenge_id"],
                "wallet_address": alice_addr,
                "signature": good_sig,
            },
        )
        self.assertEqual(ok_verify.status_code, 200)
        self.client.cookies.clear()

        replay_verify = self.client.post(
            "/api/e2ee/auth/verify",
            json={
                "challenge_id": c_res2["challenge_id"],
                "wallet_address": alice_addr,
                "signature": good_sig,
            },
        )
        self.assertEqual(replay_verify.status_code, 401)

        alice_auth = ok_verify.json()
        bob_auth = self._authenticate_wallet(bob_wallet)
        eve_auth = self._authenticate_wallet(eve_wallet)

        alice_uid = alice_auth["user"]["user_id"]
        bob_uid = bob_auth["user"]["user_id"]
        alice_tok = alice_auth["session_token"]
        bob_tok = bob_auth["session_token"]
        eve_tok = eve_auth["session_token"]

        # 3. Forged Ed25519 device bundle signature -> 400
        alice_dev_id = f"dev_alice_{secrets.token_hex(6)}"
        forged_bundle, _ = generate_signed_test_device(alice_uid, alice_dev_id)
        forged_bundle["bundle_signature"] = _b64(secrets.token_bytes(64))
        forged_res = self.client.post(
            "/api/e2ee/devices/register",
            json=forged_bundle,
            headers=self._auth_headers(alice_tok),
        )
        self.assertEqual(forged_res.status_code, 400)

        # 4. Low-order all-zero Curve25519 point -> 400
        zero_bundle, ed_priv = generate_signed_test_device(alice_uid, alice_dev_id)
        zero_bundle["curve25519_identity_key"] = _b64(b"\x00" * 32)
        self.assertEqual(
            self.client.post(
                "/api/e2ee/devices/register",
                json=zero_bundle,
                headers=self._auth_headers(alice_tok),
            ).status_code,
            400,
        )

        # 5. Register valid devices for Alice and Bob (with 1 OTK on Bob to test fallback!)
        valid_alice_bundle, _ = generate_signed_test_device(alice_uid, alice_dev_id, otk_count=2)
        bob_dev_id = f"dev_bob_{secrets.token_hex(6)}"
        valid_bob_bundle, _ = generate_signed_test_device(bob_uid, bob_dev_id, otk_count=1)
        self.assertEqual(
            self.client.post(
                "/api/e2ee/devices/register",
                json=valid_alice_bundle,
                headers=self._auth_headers(alice_tok),
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/api/e2ee/devices/register",
                json=valid_bob_bundle,
                headers=self._auth_headers(bob_tok),
            ).status_code,
            200,
        )

        # 6. Key substitution on existing active device_id -> 409 Conflict
        substituted_bundle, _ = generate_signed_test_device(alice_uid, alice_dev_id)
        sub_res = self.client.post(
            "/api/e2ee/devices/register",
            json=substituted_bundle,
            headers=self._auth_headers(alice_tok),
        )
        self.assertEqual(sub_res.status_code, 409)

        # 7. Atomic single-use OTK consumption followed by signed Fallback Key
        claim1 = self.client.post(
            "/api/e2ee/prekeys/claim",
            json={"target_user_id": bob_uid},
            headers=self._auth_headers(alice_tok),
        ).json()
        self.assertEqual(claim1["bundles"][0]["is_fallback"], False)

        claim2 = self.client.post(
            "/api/e2ee/prekeys/claim",
            json={"target_user_id": bob_uid},
            headers=self._auth_headers(alice_tok),
        ).json()
        self.assertEqual(claim2["bundles"][0]["is_fallback"], True)

        # 8. Send DM & verify duplicate message_id replay rejection (409)
        dm_id = f"dm_replay_{secrets.token_hex(6)}"
        dm_payload = {
            "message_id": dm_id,
            "recipient_user_id": bob_uid,
            "sender_device_id": alice_dev_id,
            "device_ciphertexts": {
                bob_dev_id: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(64))}
            },
        }
        first_send = self.client.post(
            "/api/e2ee/dm/messages", json=dm_payload, headers=self._auth_headers(alice_tok)
        )
        self.assertEqual(first_send.status_code, 200)
        conv_id = first_send.json()["conversation_id"]

        replay_send = self.client.post(
            "/api/e2ee/dm/messages", json=dm_payload, headers=self._auth_headers(alice_tok)
        )
        self.assertEqual(replay_send.status_code, 409)

        # 9. Unauthorized third-party Eve cannot retrieve Alice<->Bob conversation
        eve_steal = self.client.get(
            f"/api/e2ee/dm/messages?peer_user_id={bob_uid}&conversation_id={conv_id}",
            headers=self._auth_headers(eve_tok),
        )
        self.assertEqual(eve_steal.status_code, 403)

        # Bob cannot query using Alice's device_id
        wrong_dev_fetch = self.client.get(
            f"/api/e2ee/dm/messages?peer_user_id={alice_uid}&device_id={alice_dev_id}",
            headers=self._auth_headers(bob_tok),
        )
        self.assertEqual(wrong_dev_fetch.status_code, 403)

    # (Removed: the legacy unauthenticated /api/chat/* public-room endpoints no longer exist.)
    def test_03_legacy_public_chat_endpoints_are_gone(self):
        for path in ("/api/chat/messages?channel=global", "/api/chat/public-security-model", "/api/chat/keys/challenge"):
            self.assertIn(self.client.get(path).status_code, (404, 405))

    # -------------------------------------------------------------------------
    # E & K.4: MLS Group Add, Remove, Pre-Join/Post-Removal Boundaries & Concurrency
    # -------------------------------------------------------------------------
    def test_04_mls_group_membership_epochs_and_concurrency(self):
        alice = self._authenticate_wallet(Account.create())
        bob = self._authenticate_wallet(Account.create())
        eve = self._authenticate_wallet(Account.create())

        alice_uid, alice_tok = alice["user"]["user_id"], alice["session_token"]
        bob_uid, bob_tok = bob["user"]["user_id"], bob["session_token"]
        eve_tok = eve["session_token"]

        alice_dev = f"dev_alice_{secrets.token_hex(6)}"
        bob_dev = f"dev_bob_{secrets.token_hex(6)}"
        b_alice, _ = generate_signed_test_device(alice_uid, alice_dev)
        b_bob, _ = generate_signed_test_device(bob_uid, bob_dev)

        self.client.post("/api/e2ee/devices/register", json=b_alice, headers=self._auth_headers(alice_tok))
        self.client.post("/api/e2ee/devices/register", json=b_bob, headers=self._auth_headers(bob_tok))

        # 1. Create MLS group at epoch 0 (`history_sharing_mode="none"`)
        g_res = self.client.post(
            "/api/e2ee/groups",
            headers=self._auth_headers(alice_tok),
            json={
                "name": "Core Protocol Vault",
                "mls_group_id_b64": _b64(secrets.token_bytes(24)),
                "creator_device_id": alice_dev,
                "history_sharing_mode": "none",
            },
        )
        self.assertEqual(g_res.status_code, 200, g_res.text)
        group_id = g_res.json()["group"]["group_id"]

        # Non-member Eve blocked from reading or sending
        self.assertEqual(
            self.client.get(f"/api/e2ee/groups/{group_id}", headers=self._auth_headers(eve_tok)).status_code,
            403,
        )
        self.assertEqual(
            self.client.get(
                f"/api/e2ee/groups/{group_id}/messages", headers=self._auth_headers(eve_tok)
            ).status_code,
            403,
        )

        # 2. Alice sends Epoch-0 message BEFORE Bob joins
        m0_res = self.client.post(
            f"/api/e2ee/groups/{group_id}/messages",
            headers=self._auth_headers(alice_tok),
            json={
                "message_id": f"gmsg_ep0_{secrets.token_hex(6)}",
                "sender_device_id": alice_dev,
                "epoch": 0,
                "mls_ciphertext_b64": _b64(secrets.token_bytes(80)),
            },
        )
        self.assertEqual(m0_res.status_code, 200)

        # 3. Claim Bob's single-use MLS KeyPackage & submit Add Commit (epoch 0 -> 1)
        kp_claim = self.client.post(
            "/api/e2ee/mls/key-packages/claim",
            headers=self._auth_headers(alice_tok),
            json={"target_user_id": bob_uid},
        )
        self.assertEqual(kp_claim.status_code, 200)
        self.assertEqual(len(kp_claim.json()["key_packages"]), 1)

        # Second claim when Bob has 0 remaining KeyPackages -> 404 (proves single-use consumption!)
        self.assertEqual(
            self.client.post(
                "/api/e2ee/mls/key-packages/claim",
                headers=self._auth_headers(alice_tok),
                json={"target_user_id": bob_uid},
            ).status_code,
            404,
        )

        add_commit = self.client.post(
            f"/api/e2ee/groups/{group_id}/commits",
            headers=self._auth_headers(alice_tok),
            json={
                "committer_device_id": alice_dev,
                "expected_epoch": 0,
                "commit_type": "add",
                "mls_commit_b64": _b64(secrets.token_bytes(120)),
                "added_members": [{"user_id": bob_uid, "device_id": bob_dev, "role": "member"}],
                "welcomes": [
                    {
                        "target_user_id": bob_uid,
                        "target_device_id": bob_dev,
                        "mls_welcome_b64": _b64(secrets.token_bytes(160)),
                    }
                ],
            },
        )
        self.assertEqual(add_commit.status_code, 200, add_commit.text)
        self.assertEqual(add_commit.json()["commit"]["epoch"], 1)

        # 4. Concurrent stale Commit targeting expected_epoch=0 MUST fail with 409 + missing_commits
        stale_commit = self.client.post(
            f"/api/e2ee/groups/{group_id}/commits",
            headers=self._auth_headers(alice_tok),
            json={
                "committer_device_id": alice_dev,
                "expected_epoch": 0,
                "commit_type": "update",
                "mls_commit_b64": _b64(secrets.token_bytes(100)),
            },
        )
        self.assertEqual(stale_commit.status_code, 409)
        conflict_detail = stale_commit.json()["detail"]
        self.assertEqual(conflict_detail["current_epoch"], 1)
        self.assertEqual(len(conflict_detail["missing_commits"]), 1)

        # 4b. Bob was added directly by the admin, so he must Accept first (Instagram-style invitation):
        #     no Welcome, no group access and the group is not in his list until he accepts.
        self.assertEqual(
            len(
                self.client.get(
                    f"/api/e2ee/groups/welcomes?device_id={bob_dev}&consume=false",
                    headers=self._auth_headers(bob_tok),
                ).json()["welcomes"]
            ),
            0,
        )
        self.assertEqual(
            self.client.get(f"/api/e2ee/groups/{group_id}", headers=self._auth_headers(bob_tok)).status_code,
            403,
        )
        invs = self.client.get("/api/e2ee/groups/invitations", headers=self._auth_headers(bob_tok)).json()["invitations"]
        self.assertEqual([i["group_id"] for i in invs], [group_id])
        acc = self.client.post(
            f"/api/e2ee/groups/{group_id}/invitation/accept", headers=self._auth_headers(bob_tok)
        )
        self.assertEqual(acc.status_code, 200, acc.text)
        self.assertEqual(
            self.client.get("/api/e2ee/groups/invitations", headers=self._auth_headers(bob_tok)).json()["invitations"],
            [],
        )

        # 5. Bob peeks Welcome (consume=false), ACKs after durable import, and verifies non-admin commit guard
        welcomes_peek = self.client.get(
            f"/api/e2ee/groups/welcomes?device_id={bob_dev}&consume=false",
            headers=self._auth_headers(bob_tok),
        ).json()["welcomes"]
        self.assertEqual(len(welcomes_peek), 1)
        # Still available prior to ACK
        welcomes_peek2 = self.client.get(
            f"/api/e2ee/groups/welcomes?device_id={bob_dev}&consume=false",
            headers=self._auth_headers(bob_tok),
        ).json()["welcomes"]
        self.assertEqual(len(welcomes_peek2), 1)
        ack_res = self.client.post(
            f"/api/e2ee/groups/welcomes/{welcomes_peek[0]['welcome_id']}/ack?device_id={bob_dev}",
            headers=self._auth_headers(bob_tok),
        )
        self.assertEqual(ack_res.status_code, 200)
        self.assertTrue(ack_res.json()["consumed"])
        self.assertEqual(
            len(
                self.client.get(
                    f"/api/e2ee/groups/welcomes?device_id={bob_dev}&consume=false",
                    headers=self._auth_headers(bob_tok),
                ).json()["welcomes"]
            ),
            0,
        )

        # Group details include member username fields
        grp_detail = self.client.get(
            f"/api/e2ee/groups/{group_id}",
            headers=self._auth_headers(bob_tok),
        ).json()["group"]
        self.assertTrue(all("username" in m for m in grp_detail["members"]))

        # Non-admin member MUST NOT submit add/remove commits (403)
        non_admin_remove = self.client.post(
            f"/api/e2ee/groups/{group_id}/commits",
            headers=self._auth_headers(bob_tok),
            json={
                "committer_device_id": bob_dev,
                "expected_epoch": 1,
                "commit_type": "remove",
                "mls_commit_b64": _b64(secrets.token_bytes(120)),
                "removed_members": [{"user_id": alice_uid}],
            },
        )
        self.assertEqual(non_admin_remove.status_code, 403)

        m1_id = f"gmsg_ep1_{secrets.token_hex(6)}"
        self.assertEqual(
            self.client.post(
                f"/api/e2ee/groups/{group_id}/messages",
                headers=self._auth_headers(bob_tok),
                json={
                    "message_id": m1_id,
                    "sender_device_id": bob_dev,
                    "epoch": 1,
                    "mls_ciphertext_b64": _b64(secrets.token_bytes(80)),
                },
            ).status_code,
            200,
        )

        bob_msgs = self.client.get(
            f"/api/e2ee/groups/{group_id}/messages", headers=self._auth_headers(bob_tok)
        ).json()["messages"]
        self.assertEqual(len(bob_msgs), 1, "New member MUST NOT receive pre-join epoch 0 messages")
        self.assertEqual(bob_msgs[0]["message_id"], m1_id)

        # 6. Remove Bob at Epoch 2 -> Bob immediately loses read/write/commit authorization
        rem_commit = self.client.post(
            f"/api/e2ee/groups/{group_id}/commits",
            headers=self._auth_headers(alice_tok),
            json={
                "committer_device_id": alice_dev,
                "expected_epoch": 1,
                "commit_type": "remove",
                "mls_commit_b64": _b64(secrets.token_bytes(120)),
                "removed_members": [{"user_id": bob_uid}],
            },
        )
        self.assertEqual(rem_commit.status_code, 200)
        self.assertEqual(rem_commit.json()["commit"]["epoch"], 2)

        self.assertEqual(
            self.client.post(
                f"/api/e2ee/groups/{group_id}/messages",
                headers=self._auth_headers(bob_tok),
                json={
                    "message_id": f"gmsg_ep2_bob_{secrets.token_hex(6)}",
                    "sender_device_id": bob_dev,
                    "epoch": 2,
                    "mls_ciphertext_b64": _b64(secrets.token_bytes(80)),
                },
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.get(
                f"/api/e2ee/groups/{group_id}/messages", headers=self._auth_headers(bob_tok)
            ).status_code,
            403,
        )

    # -------------------------------------------------------------------------
    # D, J & K.5: Permanent user_id, Wallet Changes, Subscriptions & Lost Keys
    # -------------------------------------------------------------------------
    def test_05_permanent_identity_wallet_rotation_subscriptions_and_lost_keys(self):
        alice_w1 = Account.create()
        alice_w2 = Account.create()
        bob_w = Account.create()

        alice_auth = self._authenticate_wallet(alice_w1)
        bob_auth = self._authenticate_wallet(bob_w)

        permanent_uid = alice_auth["user"]["user_id"]
        alice_tok = alice_auth["session_token"]
        bob_uid, bob_tok = bob_auth["user"]["user_id"], bob_auth["session_token"]

        dev1_id = f"dev_alice1_{secrets.token_hex(5)}"
        bob_dev_id = f"dev_bob1_{secrets.token_hex(5)}"
        b_alice1, _ = generate_signed_test_device(permanent_uid, dev1_id)
        b_bob, _ = generate_signed_test_device(bob_uid, bob_dev_id)

        self.client.post("/api/e2ee/devices/register", json=b_alice1, headers=self._auth_headers(alice_tok))
        self.client.post("/api/e2ee/devices/register", json=b_bob, headers=self._auth_headers(bob_tok))

        # Send initial DM before username/wallet/subscription changes
        self.client.post(
            "/api/e2ee/dm/messages",
            headers=self._auth_headers(alice_tok),
            json={
                "message_id": f"dm_persist_{secrets.token_hex(6)}",
                "recipient_user_id": bob_uid,
                "sender_device_id": dev1_id,
                "device_ciphertexts": {
                    bob_dev_id: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(64))},
                    dev1_id: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(64))},
                },
            },
        )

        # 1. Username update preserves permanent user_id & encryption keys
        uname_res = self.client.patch(
            "/api/e2ee/account/username",
            headers=self._auth_headers(alice_tok),
            json={"username": f"alice_{secrets.token_hex(3)}"},
        )
        self.assertEqual(uname_res.status_code, 200)
        self.assertEqual(uname_res.json()["user"]["user_id"], permanent_uid)
        self.assertTrue(uname_res.json()["encryption_identity_unchanged"])

        # 2. Unauthenticated attacker cannot request link_wallet challenge
        w2_addr = Web3.to_checksum_address(alice_w2.address)
        self.assertEqual(
            self.client.post(
                "/api/e2ee/auth/challenge",
                json={"wallet_address": w2_addr, "purpose": "link_wallet", "chain_id": 1},
            ).status_code,
            401,
        )

        # 3. Authenticated wallet replacement preserves permanent user_id, device keys & history
        link_chal = self.client.post(
            "/api/e2ee/auth/challenge",
            headers=self._auth_headers(alice_tok),
            json={"wallet_address": w2_addr, "purpose": "link_wallet", "chain_id": 1},
        ).json()
        link_sig = alice_w2.sign_message(encode_defunct(text=link_chal["message"])).signature.hex()
        link_res = self.client.post(
            "/api/e2ee/account/wallets/link",
            headers=self._auth_headers(alice_tok),
            json={
                "challenge_id": link_chal["challenge_id"],
                "new_wallet_address": w2_addr,
                "signature": link_sig,
                "make_primary": True,
                "revoke_previous_wallets": True,
            },
        )
        self.assertEqual(link_res.status_code, 200, link_res.text)
        self.assertEqual(link_res.json()["user"]["user_id"], permanent_uid)
        self.assertTrue(link_res.json()["encryption_identity_unchanged"])

        # Logging in with replacement wallet resolves to the EXACT SAME permanent user_id!
        w2_login = self._authenticate_wallet(alice_w2)
        self.assertEqual(w2_login["user"]["user_id"], permanent_uid)
        alice_tok = w2_login["session_token"]

        # 4. Wallet-based balance snapshot updates preserve keys & historical ciphertexts
        import platform_db
        up_snap = platform_db.record_verified_balance_snapshot(
            user_id=permanent_uid,
            wallet_address=w2_addr,
            chain_id=1,
            balance_wei_int=2 * 10**18,
            block_number=19000001,
        )
        self.assertEqual(up_snap["balance_wei"], str(2 * 10**18))
        down_snap = platform_db.record_verified_balance_snapshot(
            user_id=permanent_uid,
            wallet_address=w2_addr,
            chain_id=1,
            balance_wei_int=0,
            block_number=19000005,
        )
        self.assertEqual(down_snap["balance_wei"], "0")

        dm_hist = self.client.get(
            f"/api/e2ee/dm/messages?peer_user_id={bob_uid}&device_id={dev1_id}",
            headers=self._auth_headers(alice_tok),
        )
        self.assertEqual(dm_hist.status_code, 200)
        self.assertEqual(len(dm_hist.json()["messages"]), 1)

        # 5. Lost-all-devices explicit reset requires confirm_irrecoverable_history=True
        reset_chal = self.client.post(
            "/api/e2ee/auth/challenge",
            headers=self._auth_headers(alice_tok),
            json={"wallet_address": w2_addr, "purpose": "reset_lost_identity", "chain_id": 1},
        ).json()
        reset_sig = alice_w2.sign_message(encode_defunct(text=reset_chal["message"])).signature.hex()
        recovery_dev_id = f"dev_recovery_{secrets.token_hex(5)}"
        b_recovery, _ = generate_signed_test_device(permanent_uid, recovery_dev_id)

        # Rejects confirm_irrecoverable_history=False before consuming challenge
        bad_reset = self.client.post(
            "/api/e2ee/identity/reset",
            headers=self._auth_headers(alice_tok),
            json={
                "challenge_id": reset_chal["challenge_id"],
                "wallet_address": w2_addr,
                "signature": reset_sig,
                "confirm_irrecoverable_history": False,
                "new_device": b_recovery,
            },
        )
        self.assertEqual(bad_reset.status_code, 400)

        ok_reset = self.client.post(
            "/api/e2ee/identity/reset",
            headers=self._auth_headers(alice_tok),
            json={
                "challenge_id": reset_chal["challenge_id"],
                "wallet_address": w2_addr,
                "signature": reset_sig,
                "confirm_irrecoverable_history": True,
                "new_device": b_recovery,
            },
        )
        self.assertEqual(ok_reset.status_code, 200, ok_reset.text)
        reset_body = ok_reset.json()
        self.assertEqual(reset_body["user_id"], permanent_uid)
        self.assertEqual(reset_body["identity_version"], 2)
        self.assertIn("cannot be decrypted", reset_body["irrecoverable_history_notice"])

        # Old revoked device can no longer send DMs
        revoked_send = self.client.post(
            "/api/e2ee/dm/messages",
            headers=self._auth_headers(alice_tok),
            json={
                "message_id": f"dm_revoked_{secrets.token_hex(6)}",
                "recipient_user_id": bob_uid,
                "sender_device_id": dev1_id,
                "device_ciphertexts": {
                    bob_dev_id: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(64))}
                },
            },
        )
        self.assertEqual(revoked_send.status_code, 403)

        # Peer Bob receives explicit `identity_reset_lost_keys` security event
        ev_res = self.client.get(
            f"/api/e2ee/identity/events?user_ids={permanent_uid}",
            headers=self._auth_headers(bob_tok),
        )
        self.assertEqual(ev_res.status_code, 200)
        event_types = [e["event_type"] for e in ev_res.json()["events"]]
        self.assertIn("identity_reset_lost_keys", event_types)

    # -------------------------------------------------------------------------
    # Section I: Encrypted Attachments Integrity, Authorization & Revocation
    # -------------------------------------------------------------------------
    def test_06_encrypted_attachments_integrity_and_revocation(self):
        alice = self._authenticate_wallet(Account.create())
        bob = self._authenticate_wallet(Account.create())
        eve = self._authenticate_wallet(Account.create())

        alice_uid, alice_tok = alice["user"]["user_id"], alice["session_token"]
        bob_uid, bob_tok = bob["user"]["user_id"], bob["session_token"]
        eve_tok = eve["session_token"]

        a_dev = f"dev_att_a_{secrets.token_hex(5)}"
        b_dev = f"dev_att_b_{secrets.token_hex(5)}"
        ba, _ = generate_signed_test_device(alice_uid, a_dev)
        bb, _ = generate_signed_test_device(bob_uid, b_dev)
        self.client.post("/api/e2ee/devices/register", json=ba, headers=self._auth_headers(alice_tok))
        self.client.post("/api/e2ee/devices/register", json=bb, headers=self._auth_headers(bob_tok))

        ct_bytes = secrets.token_bytes(256)
        ct_b64 = _b64(ct_bytes)
        good_sha = hashlib.sha256(ct_bytes).hexdigest()

        # Tampered SHA-256 rejected (400)
        self.assertEqual(
            self.client.post(
                "/api/e2ee/attachments",
                headers=self._auth_headers(alice_tok),
                json={
                    "scope_type": "dm",
                    "scope_id": bob_uid,
                    "uploader_device_id": a_dev,
                    "ciphertext_b64": ct_b64,
                    "ciphertext_sha256": "0" * 64,
                },
            ).status_code,
            400,
        )

        # Valid upload succeeds
        up_res = self.client.post(
            "/api/e2ee/attachments",
            headers=self._auth_headers(alice_tok),
            json={
                "scope_type": "dm",
                "scope_id": bob_uid,
                "uploader_device_id": a_dev,
                "ciphertext_b64": ct_b64,
                "ciphertext_sha256": good_sha,
            },
        )
        self.assertEqual(up_res.status_code, 200, up_res.text)
        att_id = up_res.json()["attachment"]["attachment_id"]

        # Send DM referencing attachment so conversation is established
        self.client.post(
            "/api/e2ee/dm/messages",
            headers=self._auth_headers(alice_tok),
            json={
                "message_id": f"dm_att_{secrets.token_hex(6)}",
                "recipient_user_id": bob_uid,
                "sender_device_id": a_dev,
                "device_ciphertexts": {
                    b_dev: {"message_type": 0, "ciphertext_b64": _b64(secrets.token_bytes(64))}
                },
                "attachment_ids": [att_id],
            },
        )

        # Authorized recipient Bob downloads ciphertext (200)
        dl_bob = self.client.get(
            f"/api/e2ee/attachments/{att_id}", headers=self._auth_headers(bob_tok)
        )
        self.assertEqual(dl_bob.status_code, 200)
        self.assertEqual(dl_bob.json()["attachment"]["ciphertext_b64"], ct_b64)

        # Unauthorized Eve blocked (403)
        self.assertEqual(
            self.client.get(
                f"/api/e2ee/attachments/{att_id}", headers=self._auth_headers(eve_tok)
            ).status_code,
            403,
        )

        # Revocation by uploader returns 410 Gone thereafter
        self.assertEqual(
            self.client.post(
                f"/api/e2ee/attachments/{att_id}/revoke",
                headers=self._auth_headers(alice_tok),
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(
                f"/api/e2ee/attachments/{att_id}", headers=self._auth_headers(bob_tok)
            ).status_code,
            410,
        )

    # -------------------------------------------------------------------------
    # G, H, K.6 & K.7: CSP Headers, Authenticated WebSocket & Zero Log Leakage
    # -------------------------------------------------------------------------
    def test_07_security_headers_websocket_auth_and_zero_log_leakage(self):
        alice = self._authenticate_wallet(Account.create())
        alice_uid, alice_tok = alice["user"]["user_id"], alice["session_token"]

        # 1. Verify strict CSP & browser security headers
        me_res = self.client.get("/api/e2ee/me", headers=self._auth_headers(alice_tok))
        self.assertEqual(me_res.status_code, 200)
        self.assertIn("default-src 'self'", me_res.headers.get("Content-Security-Policy", ""))
        self.assertIn("frame-ancestors 'none'", me_res.headers.get("Content-Security-Policy", ""))
        self.assertEqual(me_res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(me_res.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(me_res.headers.get("Referrer-Policy"), "no-referrer")

        # 2. WebSocket rejects invalid token with close code 4401
        with self.client.websocket_connect("/ws/e2ee") as ws_bad:
            ws_bad.send_json({"type": "auth", "token": "zys_invalid_token_value"})
            with self.assertRaises(WebSocketDisconnect) as ctx:
                ws_bad.receive_json()
            self.assertEqual(ctx.exception.code, 4401)

        # 3. WebSocket authenticates valid session frame without query-string token
        with self.client.websocket_connect("/ws/e2ee") as ws_ok:
            ws_ok.send_json({"type": "auth", "token": alice_tok})
            ack = ws_ok.receive_json()
            self.assertEqual(ack["type"], "authenticated")
            self.assertEqual(ack["user_id"], alice_uid)
            ws_ok.send_json({"type": "ping"})
            self.assertEqual(ws_ok.receive_json()["type"], "pong")

        # 4. Verify zero secrets, plaintexts, seed phrases, or client IPs leak in logs or 422 errors
        canary_seed = "witch collapse practice feed shame open despair creek road again ice least"
        canary_privkey = "0x9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff"
        canary_plaintext = "TOP_SECRET_DECRYPTED_BODY_CANARY_4242"

        buf = io.StringIO()
        with redirect_stdout(buf):
            err_res = self.client.post(
                "/api/e2ee/dm/messages?secret_query_token=SHOULD_NOT_LOG",
                headers=self._auth_headers(alice_tok),
                json={
                    "plaintext": canary_plaintext,
                    "seed_phrase": canary_seed,
                    "private_key": canary_privkey,
                },
            )

        self.assertEqual(err_res.status_code, 422)
        err_body_str = err_res.text
        logged_output = buf.getvalue()

        for secret_val in (
            canary_seed,
            canary_privkey,
            canary_plaintext,
            alice_tok,
            "SHOULD_NOT_LOG",
            "testclient",
        ):
            self.assertNotIn(
                secret_val,
                err_body_str,
                f"422 response MUST NOT echo raw input value: {secret_val}",
            )
            self.assertNotIn(
                secret_val,
                logged_output,
                f"Application stdout logs MUST NOT leak value: {secret_val}",
            )


if __name__ == "__main__":
    unittest.main()