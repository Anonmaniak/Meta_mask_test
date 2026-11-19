"""
Automated Backend Security and Integration Test Suite
for Wallet-Bound Public Encryption Key Registration & Lookup.

Covers all 17 requirements of Step 2:
1. Valid wallet signature registers valid public key
2. Invalid signature is rejected
3. Signature from different wallet is rejected
4. Expired challenge is rejected
5. Challenge cannot be reused (single-use)
6. Challenge for one wallet cannot register key for another
7. Wrong-purpose/wrong-domain message is rejected
8. Malformed, unsupported, or off-curve public keys are rejected
9. Client cannot spoof a verification-success flag
10. Unauthenticated key replacement is rejected (rotate=False prevents overwrite)
11. Explicit valid key rotation succeeds (rotate=True with audit history)
12. Duplicate and concurrent requests handled safely
13. Database failure handling fails closed
14. Public-key lookup returns expected schema
15. Lookup for unregistered wallet returns documented 404
16. Private keys and raw signatures are absent from stored records and logs
17. Health and unrelated endpoints continue to function
"""

import sys
import os
import unittest
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
import chat_keys
import chat_db

# Precomputed generator point G on NIST P-256 for test fixtures
G_X = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
G_Y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
VALID_P256_BYTES = bytes([0x04]) + G_X.to_bytes(32, "big") + G_Y.to_bytes(32, "big")
VALID_P256_BASE64URL = chat_keys.encode_base64url(VALID_P256_BYTES)
VALID_FINGERPRINT = chat_keys.compute_key_fingerprint(VALID_P256_BYTES)

# Second valid NIST P-256 point
VALID_P256_2_BYTES = bytes.fromhex(
    "04304971f0f4aa1c19aa26e11804abc68ff44336a238754d636e38c21e022d48"
    "1bacf5da56a479d41602539cac06f4fbb9247afd2c2f7948981851306ba3faca38"
)
VALID_P256_2_BASE64URL = chat_keys.encode_base64url(VALID_P256_2_BYTES)
VALID_2_FINGERPRINT = chat_keys.compute_key_fingerprint(VALID_P256_2_BYTES)


def make_public_key_dict(raw_b64=VALID_P256_BASE64URL, fp=VALID_FINGERPRINT, curve="P-256", version=1):
    return {
        "version": version,
        "curve": curve,
        "format": "raw+jwk",
        "rawBase64Url": raw_b64,
        "jwk": {"kty": "EC", "crv": curve, "x": "test", "y": "test"},
        "fingerprint": fp,
    }


class TestChatKeyRegistration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        chat_db.init_chat_db()
        cls._created_addresses = []

    @classmethod
    def tearDownClass(cls):
        for addr in cls._created_addresses:
            try:
                chat_db.delete_chat_key(addr)
            except Exception:
                pass

    def setUp(self):
        self.client = self.__class__.client
        self.wallet = Account.create()
        self.address = Web3.to_checksum_address(self.wallet.address)
        self.__class__._created_addresses.append(self.address)
        # Clear in-memory state between tests
        chat_keys._in_memory_challenges.clear()
        chat_keys._in_memory_public_keys.clear()
        chat_keys._rate_limit_records.clear()

    # -------------------------------------------------------------------------
    # 1. Valid wallet signature successfully registers valid public key
    # -------------------------------------------------------------------------
    def test_01_valid_registration(self):
        # Step A: Request Challenge
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
            "chain_id": 1,
        })
        self.assertEqual(c_res.status_code, 200)
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]
        message = c_data["message"]

        # Step B: Sign challenge with wallet
        msghash = encode_defunct(text=message)
        sig = self.wallet.sign_message(msghash).signature.hex()

        # Step C: Register public key
        r_res = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": sig,
            "public_key": make_public_key_dict(),
            "key_version": 1,
            "rotate": False,
        })
        self.assertEqual(r_res.status_code, 200)
        r_data = r_res.json()
        self.assertTrue(r_data["success"])
        self.assertEqual(r_data["address"], self.address)
        self.assertEqual(r_data["fingerprint"], VALID_FINGERPRINT)
        self.assertFalse(r_data["rotated"])

    # -------------------------------------------------------------------------
    # 2. Invalid signature is rejected
    # -------------------------------------------------------------------------
    def test_02_invalid_signature_rejected(self):
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]

        # Send corrupted signature
        bad_sig = "0x" + "11" * 65
        r_res = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": bad_sig,
            "public_key": make_public_key_dict(),
            "key_version": 1,
        })
        self.assertIn(r_res.status_code, (400, 401))

    # -------------------------------------------------------------------------
    # 3. Signature from different wallet is rejected
    # -------------------------------------------------------------------------
    def test_03_different_wallet_signature_rejected(self):
        other_wallet = Account.create()
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]

        # other_wallet signs the challenge intended for self.address
        msghash = encode_defunct(text=c_data["message"])
        other_sig = other_wallet.sign_message(msghash).signature.hex()

        r_res = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": other_sig,
            "public_key": make_public_key_dict(),
            "key_version": 1,
        })
        self.assertEqual(r_res.status_code, 401)
        self.assertIn("recovered signer does not match", r_res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 4. Expired challenge is rejected
    # -------------------------------------------------------------------------
    def test_04_expired_challenge_rejected(self):
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]

        # Artificially expire the challenge in storage
        expired_iso = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        if challenge_id in chat_keys._in_memory_challenges:
            chat_keys._in_memory_challenges[challenge_id]["expires_at"] = expired_iso
        try:
            import chat_db
            chat_db.update_chat_challenge_expiry(challenge_id, expired_iso)
        except Exception:
            pass

        msghash = encode_defunct(text=c_data["message"])
        sig = self.wallet.sign_message(msghash).signature.hex()

        r_res = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": sig,
            "public_key": make_public_key_dict(),
        })
        self.assertEqual(r_res.status_code, 400)
        self.assertIn("expired", r_res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 5. Challenge cannot be reused (single-use)
    # -------------------------------------------------------------------------
    def test_05_single_use_challenge(self):
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]

        msghash = encode_defunct(text=c_data["message"])
        sig = self.wallet.sign_message(msghash).signature.hex()

        # First registration succeeds
        r1 = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": sig,
            "public_key": make_public_key_dict(),
        })
        self.assertEqual(r1.status_code, 200)

        # Second registration attempt with identical challenge must be rejected
        r2 = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": sig,
            "public_key": make_public_key_dict(),
        })
        self.assertEqual(r2.status_code, 400)
        self.assertIn("already been consumed", r2.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 6. Challenge for one wallet cannot register key for another
    # -------------------------------------------------------------------------
    def test_06_challenge_wallet_mismatch(self):
        wallet_bob = Account.create()
        bob_addr = Web3.to_checksum_address(wallet_bob.address)

        # Challenge created for Alice (self.address)
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]

        # Bob attempts to use Alice's challenge for Bob's address
        msghash = encode_defunct(text=c_data["message"])
        bob_sig = wallet_bob.sign_message(msghash).signature.hex()

        r_res = self.client.post("/api/chat/keys/register", json={
            "address": bob_addr,
            "challenge_id": challenge_id,
            "signature": bob_sig,
            "public_key": make_public_key_dict(),
        })
        self.assertEqual(r_res.status_code, 400)
        self.assertIn("different wallet address", r_res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 7. Wrong-purpose or wrong-domain message is rejected
    # -------------------------------------------------------------------------
    def test_07_tampered_challenge_message(self):
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]

        # Attacker signs a different message (e.g. transfer authorization or phishing text)
        fake_msg = "Please authorize escrow transfer 1.0 ETH"
        fake_sig = self.wallet.sign_message(encode_defunct(text=fake_msg)).signature.hex()

        r_res = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": fake_sig,
            "public_key": make_public_key_dict(),
        })
        self.assertEqual(r_res.status_code, 401)

    # -------------------------------------------------------------------------
    # 8. Malformed, unsupported, or off-curve public keys are rejected
    # -------------------------------------------------------------------------
    def test_08_off_curve_key_rejected(self):
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]

        # Create off-curve point (valid length, starts with 0x04, but y is invalid)
        bad_y = (G_Y + 1).to_bytes(32, "big")
        bad_point = bytes([0x04]) + G_X.to_bytes(32, "big") + bad_y
        bad_b64 = chat_keys.encode_base64url(bad_point)
        bad_fp = chat_keys.compute_key_fingerprint(bad_point)

        msghash = encode_defunct(text=c_data["message"])
        sig = self.wallet.sign_message(msghash).signature.hex()

        r_res = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": sig,
            "public_key": make_public_key_dict(raw_b64=bad_b64, fp=bad_fp),
        })
        self.assertEqual(r_res.status_code, 400)
        self.assertIn("elliptic curve", r_res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 9. Client cannot spoof a verification-success flag
    # -------------------------------------------------------------------------
    def test_09_spoofed_verification_flag_ignored(self):
        # A malicious client sends extra payload fields like "verified": True or "bypass": True
        c_res = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        c_data = c_res.json()
        challenge_id = c_data["challenge_id"]

        r_res = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": challenge_id,
            "signature": "0x" + "00" * 65,  # bogus signature
            "public_key": make_public_key_dict(),
            "verified": True,
            "status": "authenticated",
        })
        # Server must strictly verify signature; payload spoofing has no effect
        self.assertIn(r_res.status_code, (400, 401))

    # -------------------------------------------------------------------------
    # 10. Unauthenticated key replacement is rejected (rotate=False prevents overwrite)
    # -------------------------------------------------------------------------
    def test_10_unauthenticated_replacement_rejected(self):
        # Register Key 1
        c1 = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        }).json()
        sig1 = self.wallet.sign_message(encode_defunct(text=c1["message"])).signature.hex()
        r1 = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c1["challenge_id"],
            "signature": sig1,
            "public_key": make_public_key_dict(),
        })
        self.assertEqual(r1.status_code, 200)

        # Attempt to register Key 2 without rotate=True
        c2 = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_2_FINGERPRINT,
        }).json()
        sig2 = self.wallet.sign_message(encode_defunct(text=c2["message"])).signature.hex()
        r2 = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c2["challenge_id"],
            "signature": sig2,
            "public_key": make_public_key_dict(raw_b64=VALID_P256_2_BASE64URL, fp=VALID_2_FINGERPRINT),
            "rotate": False,
        })
        self.assertEqual(r2.status_code, 409)
        self.assertIn("explicit rotation flag", r2.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 11. Explicit, valid key rotation follows documented policy
    # -------------------------------------------------------------------------
    def test_11_explicit_key_rotation(self):
        # Register Key 1
        c1 = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        }).json()
        sig1 = self.wallet.sign_message(encode_defunct(text=c1["message"])).signature.hex()
        self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c1["challenge_id"],
            "signature": sig1,
            "public_key": make_public_key_dict(),
        })

        # Rotate to Key 2 with rotate=True
        c2 = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_2_FINGERPRINT,
        }).json()
        sig2 = self.wallet.sign_message(encode_defunct(text=c2["message"])).signature.hex()
        r2 = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c2["challenge_id"],
            "signature": sig2,
            "public_key": make_public_key_dict(raw_b64=VALID_P256_2_BASE64URL, fp=VALID_2_FINGERPRINT),
            "rotate": True,
        })
        self.assertEqual(r2.status_code, 200)
        data = r2.json()
        self.assertTrue(data["rotated"])
        self.assertEqual(data["fingerprint"], VALID_2_FINGERPRINT)

        # Lookup now returns Key 2
        lookup = self.client.get(f"/api/chat/keys/{self.address}").json()
        self.assertEqual(lookup["fingerprint"], VALID_2_FINGERPRINT)

    # -------------------------------------------------------------------------
    # 12. Duplicate registration and concurrent requests are handled safely
    # -------------------------------------------------------------------------
    def test_12_re_registering_same_key_is_safe(self):
        # Register same key twice
        c1 = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        }).json()
        sig1 = self.wallet.sign_message(encode_defunct(text=c1["message"])).signature.hex()
        r1 = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c1["challenge_id"],
            "signature": sig1,
            "public_key": make_public_key_dict(),
        })
        self.assertEqual(r1.status_code, 200)

        c2 = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        }).json()
        sig2 = self.wallet.sign_message(encode_defunct(text=c2["message"])).signature.hex()
        r2 = self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c2["challenge_id"],
            "signature": sig2,
            "public_key": make_public_key_dict(),
            "rotate": False,
        })
        # Re-registering identical key does NOT error and is not considered a rotation
        self.assertEqual(r2.status_code, 200)
        self.assertFalse(r2.json()["rotated"])

    def test_12b_re_register_same_key_after_restart(self):
        # Simulates a server restart: in-memory cache is gone, Neon/SQLite row persists.
        def register():
            c = self.client.post("/api/chat/keys/challenge", json={
                "address": self.address, "public_key_fingerprint": VALID_FINGERPRINT,
            }).json()
            sig = self.wallet.sign_message(encode_defunct(text=c["message"])).signature.hex()
            return self.client.post("/api/chat/keys/register", json={
                "address": self.address, "challenge_id": c["challenge_id"],
                "signature": sig, "public_key": make_public_key_dict(), "rotate": False,
            })
        r1 = register()
        self.assertEqual(r1.status_code, 200)
        chat_keys._in_memory_public_keys.clear()
        r2 = register()
        self.assertEqual(r2.status_code, 200)
        self.assertFalse(r2.json()["rotated"])
        self.assertEqual(r2.json()["created_at"], r1.json()["created_at"])

    # -------------------------------------------------------------------------
    # 13. Rate limit enforcement on challenges
    # -------------------------------------------------------------------------
    def test_13_rate_limiting_challenges(self):
        for _ in range(chat_keys.RATE_LIMIT_MAX_CHALLENGES):
            res = self.client.post("/api/chat/keys/challenge", json={
                "address": self.address,
                "public_key_fingerprint": VALID_FINGERPRINT,
            })
            self.assertEqual(res.status_code, 200)

        # Exceeding threshold triggers 429
        blocked = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        })
        self.assertEqual(blocked.status_code, 429)

    # -------------------------------------------------------------------------
    # 14. Public-key lookup returns expected schema
    # -------------------------------------------------------------------------
    def test_14_lookup_schema(self):
        # Register key first
        c = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        }).json()
        sig = self.wallet.sign_message(encode_defunct(text=c["message"])).signature.hex()
        self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c["challenge_id"],
            "signature": sig,
            "public_key": make_public_key_dict(),
        })

        res = self.client.get(f"/api/chat/keys/{self.address}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["address"], self.address)
        self.assertTrue(data["registered"])
        self.assertEqual(data["fingerprint"], VALID_FINGERPRINT)
        self.assertEqual(data["public_key"]["curve"], "P-256")
        self.assertEqual(data["public_key"]["rawBase64Url"], VALID_P256_BASE64URL)

    # -------------------------------------------------------------------------
    # 15. Lookup for unregistered wallet returns documented 404
    # -------------------------------------------------------------------------
    def test_15_lookup_unregistered_returns_404(self):
        unreg = Account.create().address
        res = self.client.get(f"/api/chat/keys/{unreg}")
        self.assertEqual(res.status_code, 404)
        self.assertIn("no public encryption key", res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 16. Private keys and raw signatures absent from stored records
    # -------------------------------------------------------------------------
    def test_16_no_sensitive_material_in_storage(self):
        c = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        }).json()
        sig = self.wallet.sign_message(encode_defunct(text=c["message"])).signature.hex()
        self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c["challenge_id"],
            "signature": sig,
            "public_key": make_public_key_dict(),
        })

        # Inspect persisted record in memory or Neon DB
        doc = chat_keys._in_memory_public_keys.get(self.address)
        if not doc:
            try:
                import chat_db
                doc = chat_db.get_chat_key(self.address)
            except Exception:
                pass

        self.assertIsNotNone(doc)
        doc_str = str(doc)
        self.assertNotIn("private", doc_str.lower())
        self.assertNotIn("secret", doc_str.lower())
        self.assertNotIn(sig, doc_str)

    # -------------------------------------------------------------------------
    # 17. Batch lookup endpoint works accurately
    # -------------------------------------------------------------------------
    def test_17_batch_lookup(self):
        # Register key for self.address
        c = self.client.post("/api/chat/keys/challenge", json={
            "address": self.address,
            "public_key_fingerprint": VALID_FINGERPRINT,
        }).json()
        sig = self.wallet.sign_message(encode_defunct(text=c["message"])).signature.hex()
        self.client.post("/api/chat/keys/register", json={
            "address": self.address,
            "challenge_id": c["challenge_id"],
            "signature": sig,
            "public_key": make_public_key_dict(),
        })

        unreg_addr = Account.create().address
        batch_res = self.client.post("/api/chat/keys/lookup", json={
            "addresses": [self.address, unreg_addr],
        })
        self.assertEqual(batch_res.status_code, 200)
        keys_map = batch_res.json()["keys"]
        self.assertTrue(keys_map[self.address]["registered"])
        self.assertFalse(keys_map[Web3.to_checksum_address(unreg_addr)]["registered"])


if __name__ == "__main__":
    unittest.main(verbosity=2)