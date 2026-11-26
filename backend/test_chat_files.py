"""Files and images in chats: Members' room uploads (stored as-is) and encrypted-file daily limits."""
import base64
import hashlib
import os
import secrets
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from eth_account import Account

import e2ee_routes
import public_attachments_db as pad
from test_e2ee_security import generate_signed_test_device
from test_paid_membership_and_groups import TestPaidMembershipAndGroups as _Base

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class TestChatFiles(_Base):
    def _member(self):
        acc = Account.create()
        d = self._siwe_login(acc)
        return d["user"]["user_id"], {"Authorization": f"Bearer {d['session_token']}"}

    def _upload(self, h, name, data, mime="application/octet-stream"):
        return self.client.post("/api/platform/public-chat/attachments", headers=h,
                                json={"file_name": name, "mime_type": mime, "data_b64": _b64(data)})

    def test_room_image_and_file_round_trip(self):
        uid, h = self._member()
        img = self._upload(h, "photo.png", PNG, "image/png")
        self.assertEqual(img.status_code, 200, img.text)
        self.assertEqual(img.json()["attachment"]["kind"], "image")
        doc = self._upload(h, "../../etc/report<1>.pdf", b"%PDF-1.7 hello", "application/pdf")
        self.assertEqual(doc.status_code, 200, doc.text)
        self.assertEqual(doc.json()["attachment"]["file_name"], "report_1_.pdf")  # path + unsafe chars removed
        ids = [img.json()["attachment"]["attachment_id"], doc.json()["attachment"]["attachment_id"]]

        # Files-only message (no text) is allowed
        post = self.client.post("/api/platform/public-chat/messages", headers=h, json={"content": "", "attachment_ids": ids})
        self.assertEqual(post.status_code, 200, post.text)
        msg = post.json()["message"]
        self.assertEqual([a["attachment_id"] for a in msg["attachments"]], ids)

        # The feed carries them; another member can download
        _, h2 = self._member()
        feed = self.client.get("/api/platform/public-chat/messages", headers=h2).json()
        mine = next(m for m in feed["messages"] if m["message_id"] == msg["message_id"])
        self.assertEqual(len(mine["attachments"]), 2)
        self.assertEqual(feed["policy"]["max_files_per_message"], 5)

        r = self.client.get(f"/api/platform/public-chat/attachments/{ids[0]}", headers=h2)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, PNG)
        self.assertEqual(r.headers["content-type"], "image/png")
        self.assertTrue(r.headers["content-disposition"].startswith("inline"))
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")

        r = self.client.get(f"/api/platform/public-chat/attachments/{ids[1]}", headers=h2)
        self.assertEqual(r.headers["content-type"], "application/octet-stream")  # never rendered by the browser
        self.assertTrue(r.headers["content-disposition"].startswith("attachment"))
        self.assertIn("sandbox", r.headers["content-security-policy"])

        # Cannot attach the same file twice
        again = self.client.post("/api/platform/public-chat/messages", headers=h, json={"content": "x", "attachment_ids": ids[:1]})
        self.assertEqual(again.status_code, 400)

    def test_room_file_rules(self):
        uid, h = self._member()
        # A file that claims to be an image but is not -> stored as a plain file, never shown inline
        fake = self._upload(h, "evil.png", b"<svg onload=alert(1)>", "image/png")
        self.assertEqual(fake.json()["attachment"]["kind"], "file")
        self.assertEqual(fake.json()["attachment"]["mime_type"], "application/octet-stream")
        # SVG is a file, not an image
        svg = self._upload(h, "logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>", "image/svg+xml")
        self.assertEqual(svg.json()["attachment"]["kind"], "file")
        # Empty and too-large files are refused
        self.assertEqual(self._upload(h, "empty.txt", b"").status_code, 422)
        with patch.object(pad, "MAX_FILE_BYTES", 10):
            self.assertEqual(self._upload(h, "big.bin", b"x" * 11).status_code, 413)
        # Pending uploads are private to the uploader
        pid = self._upload(h, "draft.txt", b"draft").json()["attachment"]["attachment_id"]
        _, h2 = self._member()
        self.assertEqual(self.client.get(f"/api/platform/public-chat/attachments/{pid}", headers=h2).status_code, 404)
        self.assertEqual(self.client.get(f"/api/platform/public-chat/attachments/{pid}", headers=h).status_code, 200)
        # Someone else cannot attach my upload
        self.assertEqual(self.client.post("/api/platform/public-chat/messages", headers=h2,
                                          json={"content": "hi", "attachment_ids": [pid]}).status_code, 400)
        # Not more than 5 files per message
        many = [self._upload(h, f"f{i}.txt", b"x").json()["attachment"]["attachment_id"] for i in range(6)]
        self.assertEqual(self.client.post("/api/platform/public-chat/messages", headers=h,
                                          json={"content": "", "attachment_ids": many}).status_code, 422)
        # Daily limit
        with patch.object(pad, "DAILY_MAX_FILES", 1):
            _, h3 = self._member()
            self.assertEqual(self._upload(h3, "a.txt", b"a").status_code, 200)
            self.assertEqual(self._upload(h3, "b.txt", b"b").status_code, 429)
        # Empty message without files is still refused
        self.assertEqual(self.client.post("/api/platform/public-chat/messages", headers=h, json={"content": " "}).status_code, 400)

    def test_deleting_a_message_removes_its_files(self):
        uid, h = self._member()
        aid = self._upload(h, "a.jpg", JPEG, "image/jpeg").json()["attachment"]["attachment_id"]
        mid = self.client.post("/api/platform/public-chat/messages", headers=h,
                               json={"content": "pic", "attachment_ids": [aid]}).json()["message"]["message_id"]
        self.assertEqual(self.client.delete(f"/api/platform/public-chat/messages/{mid}", headers=h).status_code, 200)
        self.assertEqual(self.client.get(f"/api/platform/public-chat/attachments/{aid}", headers=h).status_code, 410)

    def test_encrypted_files_daily_limit(self):
        uid, h = self._member()
        dev = f"dev_f_{secrets.token_hex(5)}"
        b, _ = generate_signed_test_device(uid, dev)
        self.client.post("/api/e2ee/devices/register", json=b, headers=h)
        peer_uid, _ = self._member()

        def up():
            ct = secrets.token_bytes(64)
            return self.client.post("/api/e2ee/attachments", headers=h, json={
                "scope_type": "dm", "scope_id": peer_uid, "uploader_device_id": dev,
                "ciphertext_b64": _b64(ct), "ciphertext_sha256": hashlib.sha256(ct).hexdigest()})

        with patch.object(e2ee_routes, "E2EE_DAILY_MAX_FILES", 2):
            self.assertEqual(up().status_code, 200)
            self.assertEqual(up().status_code, 200)
            r = up()
            self.assertEqual(r.status_code, 429, r.text)
            self.assertIn("Daily file limit", r.json()["detail"])


if __name__ == "__main__":
    unittest.main()
