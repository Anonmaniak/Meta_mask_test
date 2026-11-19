"""
Automated Backend Security and Integration Test Suite
for End-to-End Encrypted (E2EE) Global Chat with Neon PostgreSQL.

Verifies:
1. Encrypted envelope submission succeeds with verified sender wallet signature.
2. Plaintext message submissions are strictly rejected (HTTP 400/422).
3. Sender spoofing (signature from a different wallet) is rejected (HTTP 401).
4. Tampered metadata fails signature verification (HTTP 401).
5. Stale / expired timestamps outside the 5-minute window are rejected (HTTP 400).
6. Envelopes that omit the sender from the recipient list are rejected (HTTP 400).
7. Anonymous visitors can view encrypted feed without keys or authentication.
8. Database documents contain zero plaintext fields.
9. Authoritative room recipient listing returns registered public keys.
10. Unsupported envelope versions and malformed fields fail closed.
"""

import sys
import os
import time
import sqlite3
import unittest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

# Ensure backend directory is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
import chat_db
from chat_routes import (
    build_canonical_envelope_dict,
    compute_canonical_envelope_hash,
    build_envelope_signing_text,
)


def make_dummy_key_wrapper(recipient_addr: str, fingerprint: str = "fp_abc123"):
    return {
        "recipient": recipient_addr,
        "keyFingerprint": fingerprint,
        "iv": "dGVzdF9pdl8xMmJ5",  # exactly 12 bytes base64url
        "wrappedKey": "dGVzdF93cmFwcGVkX2tleV9hZXNfZ2NtXzI1NmJpdHNfc2FmZQ",
    }


class TestChatE2EE(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        chat_db.init_chat_db()
        cls._created_msg_ids = []

    @classmethod
    def tearDownClass(cls):
        for mid in cls._created_msg_ids:
            try:
                chat_db.delete_chat_message(mid)
            except Exception:
                pass

    def setUp(self):
        self.client = self.__class__.client
        self.sender_wallet = Account.create()
        self.sender_address = Web3.to_checksum_address(self.sender_wallet.address)

        self.peer_wallet = Account.create()
        self.peer_address = Web3.to_checksum_address(self.peer_wallet.address)

        # Register active public keys with fingerprint fp_abc123 for sender and peer
        for addr in (self.sender_address, self.peer_address):
            chat_db.insert_or_update_chat_key({
                "address": addr,
                "public_key": {"kty": "EC", "crv": "P-256", "x": "test_x", "y": "test_y"},
                "public_key_raw_b64": "dGVzdF9wdWJsaWNfa2V5",
                "public_key_fingerprint": "fp_abc123",
                "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
                "curve": "P-256",
                "key_format_version": 1,
                "status": "active",
            })

    def _sign_envelope(
        self,
        wallet,
        sender,
        message_id,
        room,
        timestamp,
        version=1,
        algorithm="ECDH-P256-HKDF-AES-GCM-256",
        key_version=1,
        content_iv="dGVzdF9pdl8xMmJ5",
        content_ciphertext="dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
        recipients=None,
    ):
        if recipients is None:
            recipients = [make_dummy_key_wrapper(sender)]
        recipients_dicts = [
            {
                "iv": r["iv"],
                "keyFingerprint": r["keyFingerprint"],
                "recipient": r["recipient"],
                "wrappedKey": r["wrappedKey"],
            }
            for r in recipients
        ]
        canonical_dict = build_canonical_envelope_dict(
            message_id=message_id,
            sender=sender,
            channel=room,
            timestamp=timestamp,
            version=version,
            algorithm=algorithm,
            key_version=key_version,
            content_iv=content_iv,
            content_ciphertext=content_ciphertext,
            recipients=recipients_dicts,
        )
        envelope_hash = compute_canonical_envelope_hash(canonical_dict)
        expected_text = build_envelope_signing_text(
            sender=sender,
            message_id=message_id,
            room=room,
            timestamp=timestamp,
            envelope_hash=envelope_hash,
        )
        msghash = encode_defunct(text=expected_text)
        return wallet.sign_message(msghash).signature.hex()

    def _sign_legacy_envelope(self, wallet, sender, message_id, room, timestamp):
        legacy_text = (
            f"zyphra.in Chat Message\n"
            f"Sender: {sender}\n"
            f"Message ID: {message_id}\n"
            f"Room: {room}\n"
            f"Timestamp: {timestamp}"
        )
        msghash = encode_defunct(text=legacy_text)
        return wallet.sign_message(msghash).signature.hex()

    # -------------------------------------------------------------------------
    # 1. Valid encrypted message submission succeeds
    # -------------------------------------------------------------------------
    def test_01_valid_encrypted_message_submission(self):
        msg_id = f"msg_{datetime.now(timezone.utc).timestamp()}"
        self.__class__._created_msg_ids.append(msg_id)
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [
            make_dummy_key_wrapper(self.sender_address),
            make_dummy_key_wrapper(self.peer_address),
        ]
        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256", "format": "raw+jwk"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["message_id"], msg_id)
        self.assertEqual(data["status"], "encrypted_delivered")

    # -------------------------------------------------------------------------
    # 2. Plaintext message submissions are strictly rejected
    # -------------------------------------------------------------------------
    def test_02_plaintext_message_rejected(self):
        # Attempting to post plaintext "message" field
        res = self.client.post("/api/chat/messages", json={
            "sender": self.sender_address,
            "message": "Hello plaintext world!",
            "channel": "global",
        })
        # Fails validation / schema check (extra fields forbidden or missing encrypted fields)
        self.assertIn(res.status_code, [400, 422])

    # -------------------------------------------------------------------------
    # 3. Sender spoofing (signature from different wallet) is rejected
    # -------------------------------------------------------------------------
    def test_03_sender_spoofing_rejected(self):
        msg_id = f"msg_spoof_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        # Attacker signs claiming to be sender_address
        attacker_wallet = Account.create()
        sig = self._sign_envelope(
            attacker_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Sender authentication failed", res.json()["detail"])

    # -------------------------------------------------------------------------
    # 4. Tampered message metadata fails signature verification
    # -------------------------------------------------------------------------
    def test_04_tampered_metadata_fails_verification(self):
        msg_id = f"msg_tamper_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]
        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=recipients,
        )

        # Tamper with the channel / room after signing
        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "dm",  # Tampered!
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Sender authentication failed", res.json()["detail"])

    # -------------------------------------------------------------------------
    # 5. Stale / expired timestamp rejected (replay protection)
    # -------------------------------------------------------------------------
    def test_05_stale_timestamp_rejected(self):
        msg_id = "msg_old_123"
        # 10 minutes in the past
        old_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]
        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            old_ts,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": old_ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("timestamp is outside the valid window", res.json()["detail"])

    # -------------------------------------------------------------------------
    # 6. Sender must be included in recipients (self-decryption requirement)
    # -------------------------------------------------------------------------
    def test_06_sender_omitted_from_recipients_rejected(self):
        msg_id = f"msg_no_self_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        peer_recipients = [make_dummy_key_wrapper(self.peer_address)]
        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=peer_recipients,
        )

        # Only peer in recipients, sender omitted!
        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": peer_recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Sender must be included in the recipients list", res.json()["detail"])

    # -------------------------------------------------------------------------
    # 7. Anonymous feed retrieval returns ciphertext only (no plaintext)
    # -------------------------------------------------------------------------
    def test_07_anonymous_feed_returns_ciphertext_only(self):
        res = self.client.get("/api/chat/messages?channel=global&limit=10")
        self.assertEqual(res.status_code, 200)
        msgs = res.json()
        self.assertIsInstance(msgs, list)
        for m in msgs:
            # Verify no plaintext keys exist
            self.assertNotIn("plaintext", m)
            self.assertNotIn("message", m)
            self.assertNotIn("text", m)
            # Verify ciphertext and IV exist
            self.assertIn("content_ciphertext", m)
            self.assertIn("content_iv", m)
            self.assertIn("recipients", m)

    # -------------------------------------------------------------------------
    # 8. Database records strictly exclude plaintext
    # -------------------------------------------------------------------------
    def test_08_database_records_zero_plaintext(self):
        stored = chat_db.get_chat_messages("global", limit=20)
        for doc in stored:
            self.assertNotIn("plaintext", doc)
            self.assertNotIn("message", doc)
            self.assertNotIn("text", doc)

    # -------------------------------------------------------------------------
    # 9. Authoritative room recipient directory lookup
    # -------------------------------------------------------------------------
    def test_09_authoritative_room_recipients(self):
        res = self.client.get("/api/chat/rooms/global/recipients")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["room_id"], "global")
        self.assertIn("recipients", data)
        self.assertIsInstance(data["recipients"], list)

    # -------------------------------------------------------------------------
    # 10. Ciphertext tampering fails signature integrity verification
    # -------------------------------------------------------------------------
    def test_10_ciphertext_tampering_fails_verification(self):
        msg_id = f"msg_tamper_ct_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        orig_ct = "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw"
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            content_ciphertext=orig_ct,
            recipients=recipients,
        )

        # Attacker tampers with the ciphertext after signing
        tampered_ct = orig_ct + "_tampered_content"
        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": tampered_ct,
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Sender authentication failed", res.json()["detail"])

        # Verify not stored in database
        feed = self.client.get("/api/chat/messages?channel=global&limit=20").json()
        self.assertFalse(any(m.get("id") == msg_id for m in feed))

    # -------------------------------------------------------------------------
    # 11. IV tampering fails signature integrity verification
    # -------------------------------------------------------------------------
    def test_11_iv_tampering_fails_verification(self):
        msg_id = f"msg_tamper_iv_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        orig_iv = "dGVzdF9pdl8xMmJ5"
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            content_iv=orig_iv,
            recipients=recipients,
        )

        # Attacker tampers with content IV (valid 12-byte base64url, but different from signed IV)
        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ6",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Sender authentication failed", res.json()["detail"])

        # Verify not stored
        feed = self.client.get("/api/chat/messages?channel=global&limit=20").json()
        self.assertFalse(any(m.get("id") == msg_id for m in feed))

    # -------------------------------------------------------------------------
    # 12. Recipient wrapper tampering fails signature verification
    # -------------------------------------------------------------------------
    def test_12_recipient_wrapper_tampering_fails_verification(self):
        msg_id = f"msg_tamper_wrap_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [
            make_dummy_key_wrapper(self.sender_address),
            make_dummy_key_wrapper(self.peer_address),
        ]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=recipients,
        )

        # Tamper with peer's wrappedKey
        tampered_recipients = [
            make_dummy_key_wrapper(self.sender_address),
            {
                "recipient": self.peer_address,
                "keyFingerprint": "fp_abc123",
                "iv": "dGVzdF9pdl8xMmJ5",
                "wrappedKey": "dGFtcGVyZWRfd3JhcHBlZF9rZXlfYWVzX2djbV8yNTZiaXRz",
            },
        ]

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": tampered_recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Sender authentication failed", res.json()["detail"])

        # Verify not stored
        feed = self.client.get("/api/chat/messages?channel=global&limit=20").json()
        self.assertFalse(any(m.get("id") == msg_id for m in feed))

    # -------------------------------------------------------------------------
    # 13. Recipient list tampering (adding unauthorized recipient) fails verification
    # -------------------------------------------------------------------------
    def test_13_recipient_list_tampering_fails_verification(self):
        msg_id = f"msg_tamper_rlist_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=recipients,
        )

        # Attacker injects another recipient into the envelope after signing
        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": [
                make_dummy_key_wrapper(self.sender_address),
                make_dummy_key_wrapper(self.peer_address),
            ],
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Sender authentication failed", res.json()["detail"])

        # Verify not stored
        feed = self.client.get("/api/chat/messages?channel=global&limit=20").json()
        self.assertFalse(any(m.get("id") == msg_id for m in feed))

    # -------------------------------------------------------------------------
    # 14. Duplicate recipients in envelope are strictly rejected
    # -------------------------------------------------------------------------
    def test_14_duplicate_recipients_rejected(self):
        msg_id = f"msg_dup_recip_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        duplicate_recipients = [
            make_dummy_key_wrapper(self.sender_address),
            make_dummy_key_wrapper(self.sender_address.lower()),
        ]

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": duplicate_recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": "0x" + "aa" * 65,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        # Rejection should occur with HTTP 400 or 422 indicating duplicate recipient
        self.assertIn(res.status_code, [400, 422])
        self.assertIn("Duplicate recipient", str(res.json()))

        # Verify not stored
        feed = self.client.get("/api/chat/messages?channel=global&limit=20").json()
        self.assertFalse(any(m.get("id") == msg_id for m in feed))

    # -------------------------------------------------------------------------
    # 15. Legacy unhashed envelopes are rejected with client upgrade error
    # -------------------------------------------------------------------------
    def test_15_legacy_envelope_rejected_with_upgrade_error(self):
        msg_id = f"msg_legacy_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        # Signed using old format (no envelope hash)
        legacy_sig = self._sign_legacy_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": legacy_sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("upgrade your client", res.json()["detail"].lower())

        # Verify not stored
        feed = self.client.get("/api/chat/messages?channel=global&limit=20").json()
        self.assertFalse(any(m.get("id") == msg_id for m in feed))

    # -------------------------------------------------------------------------
    # 16. Valid message delivery and database persistence
    # -------------------------------------------------------------------------
    def test_16_valid_message_delivery_and_persistence(self):
        msg_id = f"msg_delivery_{datetime.now(timezone.utc).timestamp()}"
        self.__class__._created_msg_ids.append(msg_id)
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [
            make_dummy_key_wrapper(self.sender_address),
            make_dummy_key_wrapper(self.peer_address),
        ]
        ct = "dGVzdF9kZWxpdmVyeV9jaXBoZXJ0ZXh0XzEyOGJpdA"
        iv = "dGVzdF9pdl8xMmJ5"

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            content_ciphertext=ct,
            content_iv=iv,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": iv,
            "content_ciphertext": ct,
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256", "format": "raw+jwk"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["success"])

        # Fetch feed and verify exact persistence
        feed_res = self.client.get("/api/chat/messages?channel=global&limit=20")
        self.assertEqual(feed_res.status_code, 200)
        feed = feed_res.json()
        saved = next((m for m in feed if m.get("id") == msg_id), None)
        self.assertIsNotNone(saved)
        self.assertEqual(saved["content_ciphertext"], ct)
        self.assertEqual(saved["content_iv"], iv)
        self.assertEqual(len(saved["recipients"]), 2)

    # -------------------------------------------------------------------------
    # 17. Successful insertion detects row creation and persists record
    # -------------------------------------------------------------------------
    def test_17_successful_message_insertion(self):
        msg_id = f"msg_succ_{datetime.now(timezone.utc).timestamp()}"
        self.__class__._created_msg_ids.append(msg_id)
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]
        ct = "dGVzdF9zdWNjZXNzX2N0XzEyOGJpdF9nY21fdGFn"
        iv = "MTJieXRlc19zdWNj"

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            content_ciphertext=ct,
            content_iv=iv,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": iv,
            "content_ciphertext": ct,
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["message_id"], msg_id)
        self.assertEqual(data["status"], "encrypted_delivered")

        # Directly verify database layer created the row
        stored = chat_db.get_chat_message_by_id(msg_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["id"], msg_id)
        self.assertEqual(stored["content_ciphertext"], ct)
        self.assertEqual(stored["content_iv"], iv)

    # -------------------------------------------------------------------------
    # 18. Duplicate insertion returns 409 Conflict and never overwrites
    # -------------------------------------------------------------------------
    def test_18_duplicate_insertion_returns_409_conflict(self):
        msg_id = f"msg_dup_conf_{datetime.now(timezone.utc).timestamp()}"
        self.__class__._created_msg_ids.append(msg_id)
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]
        orig_ct = "dGVzdF9vcmlnaW5hbF9jaXBoZXJ0ZXh0XzEyOA"
        orig_iv = "MTJieXRlc19vcmln"

        sig1 = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            content_ciphertext=orig_ct,
            content_iv=orig_iv,
            recipients=recipients,
        )

        payload1 = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": orig_iv,
            "content_ciphertext": orig_ct,
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig1,
            "timestamp": ts,
        }

        # 1. First insert succeeds
        res1 = self.client.post("/api/chat/messages", json=payload1)
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res1.json()["status"], "encrypted_delivered")

        # 2. Resubmission of duplicate message_id fails with 409 Conflict
        res2 = self.client.post("/api/chat/messages", json=payload1)
        self.assertEqual(res2.status_code, 409)
        self.assertIn("Duplicate message ID conflict", res2.json()["detail"])
        self.assertIn(msg_id, res2.json()["detail"])

        # 3. Attempting to overwrite existing message_id with different ciphertext also fails with 409
        diff_ct = "dGVzdF9kaWZmZXJlbnRfY2lwaGVydGV4dF8xMjg"
        diff_iv = "MTJieXRlc19kaWZm"
        sig_diff = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            content_ciphertext=diff_ct,
            content_iv=diff_iv,
            recipients=recipients,
        )
        payload_diff = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": diff_iv,
            "content_ciphertext": diff_ct,
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig_diff,
            "timestamp": ts,
        }

        res3 = self.client.post("/api/chat/messages", json=payload_diff)
        self.assertEqual(res3.status_code, 409)
        self.assertIn("Duplicate message ID conflict", res3.json()["detail"])

        # 4. Verify existing message in database was NOT overwritten
        stored = chat_db.get_chat_message_by_id(msg_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["content_ciphertext"], orig_ct)
        self.assertEqual(stored["content_iv"], orig_iv)

    # -------------------------------------------------------------------------
    # 19. Duplicate insertion with idempotent=true safely returns original message
    # -------------------------------------------------------------------------
    def test_19_duplicate_insertion_idempotent_safe_return(self):
        msg_id = f"msg_idem_{datetime.now(timezone.utc).timestamp()}"
        self.__class__._created_msg_ids.append(msg_id)
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]
        ct = "dGVzdF9pZGVtcG90ZW50X2NpcGhlcnRleHRfMTI4"
        iv = "MTJieXRlc19pZGVt"

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            content_ciphertext=ct,
            content_iv=iv,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": iv,
            "content_ciphertext": ct,
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        # First insert succeeds
        res1 = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res1.status_code, 200)

        # Idempotent resubmission of exactly identical message returns original record
        res2 = self.client.post("/api/chat/messages?idempotent=true", json=payload)
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        self.assertTrue(data2["success"])
        self.assertTrue(data2["duplicate"])
        self.assertEqual(data2["status"], "already_exists")
        self.assertEqual(data2["original_message"]["content_ciphertext"], ct)

        # Idempotent resubmission with DIFFERENT ciphertext fails with 409
        diff_ct = "dGVzdF9hbHRlcmVkX2NpcGhlcnRleHRfMTI4Yml0"
        sig_diff = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            content_ciphertext=diff_ct,
            content_iv=iv,
            recipients=recipients,
        )
        payload_diff = dict(payload)
        payload_diff["content_ciphertext"] = diff_ct
        payload_diff["signature"] = sig_diff

        res3 = self.client.post("/api/chat/messages?idempotent=true", json=payload_diff)
        self.assertEqual(res3.status_code, 409)

    # -------------------------------------------------------------------------
    # 20. Database failure returns generic safe error without leaking details
    # -------------------------------------------------------------------------
    def test_20_database_failure_returns_safe_generic_error(self):
        msg_id = f"msg_dbfail_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        # Simulate unexpected database operational failure
        internal_error_message = "FATAL: Connection pool exhausted to postgres://admin:secret@neon.tech/db"
        with patch("chat_db.insert_chat_message", side_effect=sqlite3.OperationalError(internal_error_message)):
            res = self.client.post("/api/chat/messages", json=payload)
            self.assertEqual(res.status_code, 500)
            data = res.json()
            # Generic safe error returned to client
            self.assertEqual(data["detail"], "Unable to save encrypted message")
            # Internal connection string / password must NEVER be exposed
            self.assertNotIn("postgres://", str(data))
            self.assertNotIn("secret", str(data))
            self.assertNotIn("FATAL", str(data))

    # -------------------------------------------------------------------------
    # 21. Database layer detects row creation and returns clear duplicate result
    # -------------------------------------------------------------------------
    def test_21_database_layer_row_creation_detection(self):
        msg_id = f"msg_dblayer_{datetime.now(timezone.utc).timestamp()}"
        self.__class__._created_msg_ids.append(msg_id)
        doc = {
            "id": msg_id,
            "room_id": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9kYmxheWVyX2NpcGhlcnRleHRfMTI4Yml0",
            "recipients": [make_dummy_key_wrapper(self.sender_address)],
            "sender_public_key": {"curve": "P-256"},
            "signature": "0x" + "cc" * 65,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # 1. First insert creates row
        res1 = chat_db.insert_chat_message(doc)
        self.assertTrue(res1.created)
        self.assertFalse(res1.duplicate)
        self.assertIsNone(res1.existing)
        self.assertTrue(bool(res1))

        # 2. Second insert with same id detects duplicate and does not create row
        res2 = chat_db.insert_chat_message(doc)
        self.assertFalse(res2.created)
        self.assertTrue(res2.duplicate)
        self.assertFalse(bool(res2))
        self.assertIsNotNone(res2.existing)
        self.assertEqual(res2.existing["id"], msg_id)
        self.assertEqual(res2.existing["content_ciphertext"], doc["content_ciphertext"])

        # 3. Third insert with different ciphertext also detects duplicate and does not overwrite
        doc_diff = dict(doc)
        doc_diff["content_ciphertext"] = "dGVzdF90YW1wZXJlZF9vdmVyd3JpdGVfYXR0ZW1wdA"
        res3 = chat_db.insert_chat_message(doc_diff)
        self.assertFalse(res3.created)
        self.assertTrue(res3.duplicate)
        # Verify original in database is still intact
        stored = chat_db.get_chat_message_by_id(msg_id)
        self.assertEqual(stored["content_ciphertext"], doc["content_ciphertext"])

    # -------------------------------------------------------------------------
    # 22. Malformed base64url inputs are strictly rejected
    # -------------------------------------------------------------------------
    def test_22_malformed_base64url_rejected(self):
        msg_id = f"msg_malformed_b64_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        # Case A: Content IV contains illegal base64 characters (+, / or !)
        payload_bad_iv = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "bad+iv/with+chars!",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": "0x" + "aa" * 65,
            "timestamp": ts,
        }
        res_iv = self.client.post("/api/chat/messages", json=payload_bad_iv)
        self.assertIn(res_iv.status_code, [400, 422])
        self.assertIn("base64url", res_iv.text.lower())

        # Case B: Ciphertext contains illegal base64url characters
        payload_bad_ct = dict(payload_bad_iv)
        payload_bad_ct["content_iv"] = "dGVzdF9pdl8xMmJ5"
        payload_bad_ct["content_ciphertext"] = "bad+ciphertext/with!illegal"
        res_ct = self.client.post("/api/chat/messages", json=payload_bad_ct)
        self.assertIn(res_ct.status_code, [400, 422])
        self.assertIn("base64url", res_ct.text.lower())

        # Case C: Recipient wrapper wrappedKey is malformed base64url
        bad_recip = [dict(recipients[0])]
        bad_recip[0]["wrappedKey"] = "malformed+key/wrapped!with+symbols"
        payload_bad_wrap = dict(payload_bad_iv)
        payload_bad_wrap["content_iv"] = "dGVzdF9pdl8xMmJ5"
        payload_bad_wrap["recipients"] = bad_recip
        res_wrap = self.client.post("/api/chat/messages", json=payload_bad_wrap)
        self.assertIn(res_wrap.status_code, [400, 422])
        self.assertIn("base64url", res_wrap.text.lower())

    # -------------------------------------------------------------------------
    # 23. Invalid IV length is strictly rejected (AES-GCM requires 12 bytes)
    # -------------------------------------------------------------------------
    def test_23_invalid_iv_length_rejected(self):
        msg_id = f"msg_bad_iv_len_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        # 8 bytes IV (too short)
        iv_8bytes = "MTIzNDU2Nzg"
        payload_short = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": iv_8bytes,
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": "0x" + "aa" * 65,
            "timestamp": ts,
        }
        res_short = self.client.post("/api/chat/messages", json=payload_short)
        self.assertIn(res_short.status_code, [400, 422])
        self.assertIn("12 bytes", res_short.text.lower())

        # 16 bytes IV (too long)
        iv_16bytes = "MTIzNDU2Nzg5MDEyMzQ1Ng"
        payload_long = dict(payload_short)
        payload_long["content_iv"] = iv_16bytes
        res_long = self.client.post("/api/chat/messages", json=payload_long)
        self.assertIn(res_long.status_code, [400, 422])
        self.assertIn("12 bytes", res_long.text.lower())

        # Recipient wrapper IV with 16 bytes instead of 12
        bad_recip_iv = [dict(recipients[0])]
        bad_recip_iv[0]["iv"] = iv_16bytes
        payload_bad_recip_iv = dict(payload_short)
        payload_bad_recip_iv["content_iv"] = "dGVzdF9pdl8xMmJ5"
        payload_bad_recip_iv["recipients"] = bad_recip_iv
        res_recip_iv = self.client.post("/api/chat/messages", json=payload_bad_recip_iv)
        self.assertIn(res_recip_iv.status_code, [400, 422])
        self.assertIn("12 bytes", res_recip_iv.text.lower())

    # -------------------------------------------------------------------------
    # 24. Unsupported protocol version rejected with client update required
    # -------------------------------------------------------------------------
    def test_24_unsupported_protocol_version_rejected(self):
        msg_id = f"msg_bad_version_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        payload = {
            "version": 2,  # unsupported future version
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": "0x" + "aa" * 65,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertIn(res.status_code, [400, 422])
        self.assertIn("client update required", res.text.lower())

    # -------------------------------------------------------------------------
    # 25. Unsupported algorithm rejected
    # -------------------------------------------------------------------------
    def test_25_unsupported_algorithm_rejected(self):
        msg_id = f"msg_bad_algo_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "AES-256-CBC",  # unsupported algorithm
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": "0x" + "aa" * 65,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertIn(res.status_code, [400, 422])
        self.assertIn("unsupported algorithm", res.text.lower())

    # -------------------------------------------------------------------------
    # 26. Recipient key fingerprint mismatch is strictly rejected
    # -------------------------------------------------------------------------
    def test_26_recipient_fingerprint_mismatch_rejected(self):
        msg_id = f"msg_fp_mismatch_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        # Sender is registered with fingerprint 'fp_abc123', but wrapper submits 'fp_mismatch_xyz'
        mismatched_recipients = [
            make_dummy_key_wrapper(self.sender_address, fingerprint="fp_mismatch_xyz")
        ]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=mismatched_recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": mismatched_recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("key fingerprint mismatch", res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 27. Recipient without registered public key is strictly rejected
    # -------------------------------------------------------------------------
    def test_27_unregistered_recipient_rejected(self):
        msg_id = f"msg_unreg_recip_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        unregistered_wallet = Account.create()
        unregistered_addr = Web3.to_checksum_address(unregistered_wallet.address)

        recipients = [
            make_dummy_key_wrapper(self.sender_address),
            make_dummy_key_wrapper(unregistered_addr, fingerprint="fp_unknown_123"),
        ]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("has no registered encryption key", res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 28. Inactive / revoked recipient key is strictly rejected
    # -------------------------------------------------------------------------
    def test_28_inactive_recipient_key_rejected(self):
        msg_id = f"msg_inactive_recip_{datetime.now(timezone.utc).timestamp()}"
        ts = datetime.now(timezone.utc).isoformat()
        revoked_wallet = Account.create()
        revoked_addr = Web3.to_checksum_address(revoked_wallet.address)

        # Register inactive/revoked key for this wallet
        chat_db.insert_or_update_chat_key({
            "address": revoked_addr,
            "public_key": {"kty": "EC", "crv": "P-256", "x": "rev_x", "y": "rev_y"},
            "public_key_raw_b64": "dGVzdF9wdWJsaWNfa2V5",
            "public_key_fingerprint": "fp_revoked_123",
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "curve": "P-256",
            "key_format_version": 1,
            "status": "revoked",
        })

        recipients = [
            make_dummy_key_wrapper(self.sender_address),
            make_dummy_key_wrapper(revoked_addr, fingerprint="fp_revoked_123"),
        ]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            ts,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("inactive or revoked", res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 29. Manipulated and malformed timestamps are strictly rejected
    # -------------------------------------------------------------------------
    def test_29_manipulated_timestamps_rejected(self):
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        # 1. Future clock skew outside allowed window (10 minutes in future)
        future_ts = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        msg_id_future = f"msg_ts_future_{datetime.now(timezone.utc).timestamp()}"
        sig_future = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id_future,
            "global",
            future_ts,
            recipients=recipients,
        )
        payload_future = {
            "version": 1,
            "message_id": msg_id_future,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig_future,
            "timestamp": future_ts,
        }
        res_future = self.client.post("/api/chat/messages", json=payload_future)
        self.assertEqual(res_future.status_code, 400)
        self.assertIn("timestamp is outside the valid window", res_future.json()["detail"].lower())

        # 2. Past clock skew outside allowed window (10 minutes in past)
        past_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        msg_id_past = f"msg_ts_past_{datetime.now(timezone.utc).timestamp()}"
        sig_past = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id_past,
            "global",
            past_ts,
            recipients=recipients,
        )
        payload_past = dict(payload_future)
        payload_past["message_id"] = msg_id_past
        payload_past["signature"] = sig_past
        payload_past["timestamp"] = past_ts
        res_past = self.client.post("/api/chat/messages", json=payload_past)
        self.assertEqual(res_past.status_code, 400)
        self.assertIn("timestamp is outside the valid window", res_past.json()["detail"].lower())

        # 3. Malformed timestamp string
        msg_id_malformed = f"msg_ts_malformed_{datetime.now(timezone.utc).timestamp()}"
        payload_malformed = dict(payload_future)
        payload_malformed["message_id"] = msg_id_malformed
        payload_malformed["timestamp"] = "not-an-iso-8601-date"
        res_malformed = self.client.post("/api/chat/messages", json=payload_malformed)
        self.assertIn(res_malformed.status_code, [400, 422])
        self.assertIn("timestamp", res_malformed.text.lower())

        # 4. Naive timestamp lacking timezone offset
        msg_id_naive = f"msg_ts_naive_{datetime.now(timezone.utc).timestamp()}"
        payload_naive = dict(payload_future)
        payload_naive["message_id"] = msg_id_naive
        payload_naive["timestamp"] = "2026-11-10T14:30:00"
        res_naive = self.client.post("/api/chat/messages", json=payload_naive)
        self.assertIn(res_naive.status_code, [400, 422])

        # 5. Timestamp manipulation post-signing fails signature verification
        now_ts = datetime.now(timezone.utc).isoformat()
        other_ts = (datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat()
        msg_id_tamper_ts = f"msg_ts_tamper_{datetime.now(timezone.utc).timestamp()}"
        sig_orig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id_tamper_ts,
            "global",
            now_ts,
            recipients=recipients,
        )
        payload_tamper_ts = dict(payload_future)
        payload_tamper_ts["message_id"] = msg_id_tamper_ts
        payload_tamper_ts["signature"] = sig_orig
        payload_tamper_ts["timestamp"] = other_ts  # altered after signing
        res_tamper_ts = self.client.post("/api/chat/messages", json=payload_tamper_ts)
        self.assertEqual(res_tamper_ts.status_code, 401)
        self.assertIn("Sender authentication failed", res_tamper_ts.json()["detail"])

    # -------------------------------------------------------------------------
    # 30. Valid timestamp separates client signed time from server creation time
    # -------------------------------------------------------------------------
    def test_30_valid_timestamp_and_server_separation(self):
        msg_id = f"msg_ts_valid_{datetime.now(timezone.utc).timestamp()}"
        self.__class__._created_msg_ids.append(msg_id)
        client_ts = datetime.now(timezone.utc).isoformat()
        recipients = [make_dummy_key_wrapper(self.sender_address)]

        sig = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id,
            "global",
            client_ts,
            recipients=recipients,
        )

        payload = {
            "version": 1,
            "message_id": msg_id,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig,
            "timestamp": client_ts,
        }

        res = self.client.post("/api/chat/messages", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["client_timestamp"], client_ts)
        self.assertIn("server_timestamp", data)
        self.assertIn("created_at", data)
        self.assertEqual(data["timestamp"], client_ts)

        # Directly inspect stored record in database
        stored = chat_db.get_chat_message_by_id(msg_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["client_timestamp"], client_ts)
        self.assertEqual(stored["timestamp"], client_ts)
        self.assertIn("server_timestamp", stored)
        self.assertIn("created_at", stored)

        # Confirm cryptographic verification works on stored message using client_timestamp
        canonical_dict = build_canonical_envelope_dict(
            message_id=stored["id"],
            sender=stored["sender"],
            channel=stored["room_id"],
            timestamp=stored["client_timestamp"],
            version=1,
            algorithm=stored["algorithm"],
            key_version=1,
            content_iv=stored["content_iv"],
            content_ciphertext=stored["content_ciphertext"],
            recipients=stored["recipients"],
        )
        reconstructed_hash = compute_canonical_envelope_hash(canonical_dict)
        signing_text = build_envelope_signing_text(
            sender=stored["sender"],
            message_id=stored["id"],
            room=stored["room_id"],
            timestamp=stored["client_timestamp"],
            envelope_hash=reconstructed_hash,
        )
        msghash = encode_defunct(text=signing_text)
        recovered_addr = Account.recover_message(msghash, signature=stored["signature"])
        self.assertEqual(recovered_addr.lower(), self.sender_address.lower())

    # -------------------------------------------------------------------------
    # 31. Database ordering is strictly controlled by server creation timestamp
    # -------------------------------------------------------------------------
    def test_31_server_side_ordering_immune_to_client_clock_skew(self):
        import time

        msg_id1 = f"msg_ord_1_{datetime.now(timezone.utc).timestamp()}"
        msg_id2 = f"msg_ord_2_{datetime.now(timezone.utc).timestamp()}"
        self.__class__._created_msg_ids.extend([msg_id1, msg_id2])

        recipients = [make_dummy_key_wrapper(self.sender_address)]

        # Message 1 has a client timestamp 2 minutes in the FUTURE (+120s)
        client_ts1 = (datetime.now(timezone.utc) + timedelta(seconds=120)).isoformat()
        sig1 = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id1,
            "global",
            client_ts1,
            recipients=recipients,
        )
        payload1 = {
            "version": 1,
            "message_id": msg_id1,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig1,
            "timestamp": client_ts1,
        }

        # Submit Message 1 first
        res1 = self.client.post("/api/chat/messages", json=payload1)
        self.assertEqual(res1.status_code, 200)

        # Brief pause to ensure distinct monotonic server timestamp
        time.sleep(0.05)

        # Message 2 has a client timestamp 2 minutes in the PAST (-120s)
        client_ts2 = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
        sig2 = self._sign_envelope(
            self.sender_wallet,
            self.sender_address,
            msg_id2,
            "global",
            client_ts2,
            recipients=recipients,
        )
        payload2 = {
            "version": 1,
            "message_id": msg_id2,
            "channel": "global",
            "sender": self.sender_address,
            "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
            "key_version": 1,
            "content_iv": "dGVzdF9pdl8xMmJ5",
            "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
            "recipients": recipients,
            "sender_public_key": {"curve": "P-256"},
            "signature": sig2,
            "timestamp": client_ts2,
        }

        # Submit Message 2 second
        res2 = self.client.post("/api/chat/messages", json=payload2)
        self.assertEqual(res2.status_code, 200)

        # Verify in database:
        # Message 1's client_ts is AFTER Message 2's client_ts:
        self.assertGreater(client_ts1, client_ts2)

        # But Message 1's server created_at is BEFORE Message 2's server created_at:
        stored1 = chat_db.get_chat_message_by_id(msg_id1)
        stored2 = chat_db.get_chat_message_by_id(msg_id2)
        self.assertLessEqual(stored1["created_at"], stored2["created_at"])

        # Fetch messages via the public feed API
        feed_res = self.client.get("/api/chat/messages?channel=global&limit=50")
        self.assertEqual(feed_res.status_code, 200)
        messages = feed_res.json()

        # Locate the two test messages in the feed
        idx1 = next((i for i, m in enumerate(messages) if m["id"] == msg_id1), None)
        idx2 = next((i for i, m in enumerate(messages) if m["id"] == msg_id2), None)
        self.assertIsNotNone(idx1)
        self.assertIsNotNone(idx2)

        # Chronological order must place Message 1 before Message 2 based on server creation time,
        # completely ignoring the client's manipulated timestamp!
        self.assertLess(idx1, idx2)

    def test_32_database_failure_on_feed_and_recipients(self):
        """Verifies that database exceptions return safe generic errors and never leak internal stack traces."""
        with unittest.mock.patch("chat_db.get_chat_messages", side_effect=RuntimeError("psycopg2.OperationalError: connection terminated")):
            res = self.client.get("/api/chat/messages?channel=global")
            self.assertEqual(res.status_code, 500)
            data = res.json()
            self.assertIn("Failed to fetch chat messages", data.get("detail", ""))
            self.assertNotIn("psycopg2", data.get("detail", ""))
            self.assertNotIn("OperationalError", str(data))

        with unittest.mock.patch("chat_db.get_active_room_public_keys", side_effect=Exception("Neon DB connection timeout")):
            res = self.client.get("/api/chat/rooms/global/recipients")
            self.assertEqual(res.status_code, 500)
            data = res.json()
            self.assertIn("Unable to fetch room recipients", data.get("detail", ""))
            self.assertNotIn("Neon DB", data.get("detail", ""))

        with unittest.mock.patch("chat_db.get_chat_message_by_id", side_effect=Exception("SELECT * FROM internal_chat_error")):
            res = self.client.get("/api/chat/messages/msg_test_err_123")
            self.assertEqual(res.status_code, 500)
            data = res.json()
            self.assertIn("Unable to retrieve chat message", data.get("detail", ""))
            self.assertNotIn("internal_chat_error", str(data))

    def test_33_recipient_query_param_validation_and_filtering(self):
        """Verifies validation and filtering behavior of the recipient query parameter on GET /api/chat/messages."""
        # Invalid recipient EVM address should return HTTP 400
        res_bad = self.client.get("/api/chat/messages?channel=global&recipient=invalid_eth_address")
        self.assertEqual(res_bad.status_code, 400)
        self.assertIn("Invalid recipient address parameter", res_bad.json().get("detail", ""))

        # Valid recipient EVM address should return HTTP 200 with filtered results
        test_recipient = "0x" + "1" * 40
        res_good = self.client.get(f"/api/chat/messages?channel=global&recipient={test_recipient}")
        self.assertEqual(res_good.status_code, 200)
        self.assertIsInstance(res_good.json(), list)

    def test_34_oversized_payload_rejected_with_413(self):
        """Verifies that oversized encrypted payloads exceeding request limits are rejected with HTTP 413."""
        large_body = b"{" + b'"padding":"' + b"A" * 140000 + b'"}'
        res = self.client.post(
            "/api/chat/messages",
            content=large_body,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(res.status_code, 413)
        self.assertIn("exceeds maximum size limit", res.json().get("detail", ""))

    def test_35_failed_storage_prevents_broadcast_and_fails_closed(self):
        """Verifies that storage failures fail closed, preventing WebSocket broadcast and success responses."""
        broadcast_called = []
        # Open Public Chat is members-only now: anonymous posting is refused outright
        anon = self.client.post(
            "/api/platform/public-chat/messages",
            json={"content": "anonymous post", "guest_token": "test_gst_123"},
        )
        self.assertEqual(anon.status_code, 401)

        import e2ee_db
        member, _ = e2ee_db.get_or_create_user_for_wallet("0x" + "c3" * 20)
        exp = (e2ee_db.now_utc() + timedelta(hours=1)).isoformat()
        member_token, _ = e2ee_db.create_auth_session(member["user_id"], "0x" + "c3" * 20, exp)
        with unittest.mock.patch("platform_routes.schedule_public_ws_broadcast", side_effect=lambda evt: broadcast_called.append(evt)):
            with unittest.mock.patch("platform_db.insert_public_chat_message", side_effect=Exception("Database disk full")):
                res = self.client.post(
                    "/api/platform/public-chat/messages",
                    json={"content": "This message should never be broadcast"},
                    headers={"Authorization": f"Bearer {member_token}"},
                )
                self.assertEqual(res.status_code, 500)
                self.assertIn("Unable to save chat message", res.json().get("detail", ""))
                # Broadcast MUST NOT be called!
                self.assertEqual(len(broadcast_called), 0)

        # Encrypted chat: malformed envelope fails closed without database insertion
        bad_msg_id = f"msg_malformed_{time.time()}"
        res_malformed = self.client.post(
            "/api/chat/messages",
            json={
                "version": 1,
                "message_id": bad_msg_id,
                "channel": "global",
                "sender": self.sender_address,
                "algorithm": "ECDH-P256-HKDF-AES-GCM-256",
                "key_version": 1,
                "content_iv": "invalid_iv_too_short",
                "content_ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2Flc19nY21fMTI4Yml0X3RhZw",
                "recipients": [{"recipient": self.sender_address, "keyFingerprint": "fp_test", "iv": "dGVzdF9pdl8xMmJ5", "wrappedKey": "dGVzdF93cmFwcGVkX2tleV9kYXRhXzMyYnl0ZXM"}],
                "sender_public_key": {"curve": "P-256"},
                "signature": "0x" + "1" * 130,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        self.assertEqual(res_malformed.status_code, 422)
        # Message was never partially stored
        stored = chat_db.get_chat_message_by_id(bad_msg_id)
        self.assertIsNone(stored)



if __name__ == "__main__":
    unittest.main()