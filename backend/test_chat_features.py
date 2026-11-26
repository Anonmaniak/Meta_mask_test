"""
Chat features: delete for everyone, encrypted control events (reactions / edits / votes), disappearing
messages, pinned messages, announcement-only groups, @mentions, typing, mute / archive, Members' room
reactions / mentions / typing / pins, the admin banner, and renewal reminders.

The server never sees message text; these tests check what it stores, removes, allows and notifies.
"""
import base64
import os
import secrets
import sys
import unittest
from datetime import timedelta
from unittest.mock import patch

os.environ["TESTING"] = "1"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eth_account import Account

import chat_features_db
import e2ee_db
import e2ee_routes
import platform_db
import platform_routes
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


class TestChatFeatures(_Fixtures):
    __test__ = True

    def setUp(self):
        super().setUp()
        e2ee_routes._rate_buckets.clear()
        platform_db.auth_cache.invalidate_all()

    # ------------------------------------------------------------------ helpers
    def _member(self, admin=False):
        if admin:
            _, data, h, dev = self._make_admin()
            self.client.cookies.clear()
            return {"uid": data["user"]["user_id"], "h": h, "dev": dev, "name": data["user"].get("username")}
        data = self._siwe_login(Account.create())
        self.client.cookies.clear()
        uid, h = data["user"]["user_id"], {"Authorization": f"Bearer {data['session_token']}"}
        dev = f"dev_m_{secrets.token_hex(5)}"
        bundle, _ = generate_signed_test_device(uid, dev)
        self.assertEqual(self.client.post("/api/e2ee/devices/register", json=bundle, headers=h).status_code, 200)
        return {"uid": uid, "h": h, "dev": dev, "name": data["user"].get("username")}

    def _group(self, admin, *members):
        gid = self._create_group(admin["h"], admin["dev"], visibility="public").json()["group"]["group_id"]
        for m in members:
            # they ask to join first, so the admin's add makes them active straight away
            self.assertEqual(self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"]).status_code, 200)
            epoch = e2ee_db.get_mls_group(gid)["current_epoch"]
            r = self.client.post(f"/api/e2ee/groups/{gid}/commits", headers=admin["h"], json={
                "committer_device_id": admin["dev"], "expected_epoch": epoch, "commit_type": "add",
                "mls_commit_b64": _b64(secrets.token_bytes(96)),
                "added_members": [{"user_id": m["uid"], "device_id": m["dev"], "role": "member"}],
                "welcomes": [{"target_user_id": m["uid"], "target_device_id": m["dev"],
                              "mls_welcome_b64": _b64(secrets.token_bytes(120))}]})
            self.assertEqual(r.status_code, 200, r.text)
        return gid

    def _gsend(self, gid, m, kind="message", mentions=None):
        epoch = e2ee_db.get_mls_group(gid)["current_epoch"]
        return self.client.post(f"/api/e2ee/groups/{gid}/messages", headers=m["h"], json={
            "message_id": "msg_" + secrets.token_hex(8), "epoch": epoch, "sender_device_id": m["dev"],
            "mls_ciphertext_b64": _b64(secrets.token_bytes(40)), "event_kind": kind,
            "mention_user_ids": mentions or []})

    def _dsend(self, sender, recipient, kind="message", types=(1, 1)):
        cts = {sender["dev"]: {"message_type": types[0], "ciphertext_b64": _b64(secrets.token_bytes(40))},
               recipient["dev"]: {"message_type": types[1], "ciphertext_b64": _b64(secrets.token_bytes(40))}}
        return self.client.post("/api/e2ee/dm/messages", headers=sender["h"], json={
            "message_id": "dm_" + secrets.token_hex(8), "recipient_user_id": recipient["uid"],
            "sender_device_id": sender["dev"], "device_ciphertexts": cts, "event_kind": kind})

    def _dlist(self, viewer, peer):
        r = self.client.get(f"/api/e2ee/dm/messages?peer_user_id={peer['uid']}&device_id={viewer['dev']}", headers=viewer["h"])
        self.assertEqual(r.status_code, 200, r.text)
        return {m["message_id"]: m for m in r.json()["messages"]}

    def _glist(self, gid, viewer):
        r = self.client.get(f"/api/e2ee/groups/{gid}/messages", headers=viewer["h"])
        self.assertEqual(r.status_code, 200, r.text)
        return {m["message_id"]: m for m in r.json()["messages"]}

    def _unread(self, m):
        return self.client.get("/api/e2ee/unread", headers=m["h"]).json()

    def _scalar(self, q, params=()):
        with platform_db.chat_db._sqlite_lock:
            return platform_db.chat_db._sqlite_conn.execute(q, params).fetchone()[0]

    def _sql(self, q, params=()):
        with platform_db.chat_db._sqlite_lock:
            platform_db.chat_db._sqlite_conn.execute(q, params)
            platform_db.chat_db._sqlite_conn.commit()

    # ------------------------------------------------------------------ delete for everyone
    def test_dm_delete_for_everyone_removes_the_stored_copy(self):
        a, b = self._member(), self._member()
        # b's copy is a session-setup (pre-key) copy, a's own copy is a normal one
        mid = self._dsend(a, b, types=(1, 0)).json()["message_id"]
        self.assertEqual(self.client.post(f"/api/e2ee/dm/messages/{mid}/delete", headers=b["h"]).status_code, 403)  # not the sender
        self.assertEqual(self.client.post(f"/api/e2ee/dm/messages/{mid}/delete", headers=a["h"]).status_code, 200)
        self.assertEqual(self.client.post(f"/api/e2ee/dm/messages/{mid}/delete", headers=a["h"]).status_code, 200)  # idempotent
        seen_by_a = self._dlist(a, b)[mid]
        seen_by_b = self._dlist(b, a)[mid]
        self.assertTrue(seen_by_a["deleted"] and seen_by_b["deleted"])
        self.assertEqual(seen_by_a["device_ciphertexts"], {})  # normal copy: gone
        self.assertEqual(list(seen_by_b["device_ciphertexts"]), [b["dev"]])  # setup copy kept for b's session only
        self.assertEqual(self.client.post("/api/e2ee/dm/messages/dm_nope_nope/delete", headers=a["h"]).status_code, 404)

    def test_dm_delete_window_is_48_hours(self):
        a, b = self._member(), self._member()
        mid = self._dsend(a, b).json()["message_id"]
        old = (e2ee_db.now_utc() - timedelta(hours=49)).isoformat()
        self._sql("UPDATE chat_dm_messages SET created_bucket = ? WHERE message_id = ?", (old, mid))
        r = self.client.post(f"/api/e2ee/dm/messages/{mid}/delete", headers=a["h"])
        self.assertEqual(r.status_code, 403)
        self.assertIn("48 hours", r.json()["detail"])

    def test_group_delete_sender_or_admin(self):
        admin, a, b = self._member(admin=True), self._member(), self._member()
        gid = self._group(admin, a, b)
        mid = self._gsend(gid, a).json()["message"]["message_id"]
        self.assertEqual(self.client.post(f"/api/e2ee/groups/{gid}/messages/{mid}/delete", headers=b["h"]).status_code, 403)
        self.assertEqual(self.client.post(f"/api/e2ee/groups/{gid}/messages/{mid}/delete", headers=a["h"]).status_code, 200)
        row = self._glist(gid, b)[mid]
        self.assertTrue(row["deleted"])
        self.assertEqual(row["mls_ciphertext_b64"], "")
        # a group admin may delete anyone's message, even an old one
        mid2 = self._gsend(gid, a).json()["message"]["message_id"]
        old = (e2ee_db.now_utc() - timedelta(days=10)).isoformat()
        self._sql("UPDATE chat_group_messages SET created_bucket = ? WHERE message_id = ?", (old, mid2))
        self.assertEqual(self.client.post(f"/api/e2ee/groups/{gid}/messages/{mid2}/delete", headers=a["h"]).status_code, 403)
        self.assertEqual(self.client.post(f"/api/e2ee/groups/{gid}/messages/{mid2}/delete", headers=admin["h"]).status_code, 200)
        # control events (reactions, votes) are not "messages" and cannot be deleted this way
        cid = self._gsend(gid, a, kind="control").json()["message"]["message_id"]
        self.assertEqual(self.client.post(f"/api/e2ee/groups/{gid}/messages/{cid}/delete", headers=a["h"]).status_code, 400)

    # ------------------------------------------------------------------ control events & unread
    def test_control_events_and_deleted_messages_are_never_unread(self):
        a, b = self._member(), self._member()
        self._unread(b)  # first call sets the baseline
        self.assertEqual(self._dsend(a, b, kind="control").status_code, 200)  # e.g. an encrypted reaction
        self.assertEqual(self._unread(b)["total"], 0)
        mid = self._dsend(a, b).json()["message_id"]
        self.assertEqual(self._unread(b)["total"], 1)
        self.client.post(f"/api/e2ee/dm/messages/{mid}/delete", headers=a["h"])
        self.assertEqual(self._unread(b)["total"], 0)
        self.assertEqual(self._dsend(a, b, kind="bogus").status_code, 422)

    # ------------------------------------------------------------------ disappearing messages
    def test_disappearing_messages_dm(self):
        a, b = self._member(), self._member()
        url = "/api/e2ee/disappearing"
        self.assertEqual(self.client.post(url, headers=a["h"], json={"scope_type": "dm", "peer_user_id": b["uid"], "ttl_seconds": 3600}).status_code, 400)
        self.assertEqual(self.client.post(url, headers=b["h"], json={"scope_type": "dm", "peer_user_id": a["uid"], "ttl_seconds": 86400}).status_code, 200)
        st = self.client.get(f"/api/e2ee/conversations/state?scope_type=dm&peer_user_id={b['uid']}", headers=a["h"]).json()
        self.assertEqual(st["disappearing_ttl"], 86400)  # set by b, seen by a (shared chat setting)
        self._unread(b)
        sent = self._dsend(a, b, types=(1, 0)).json()
        self.assertIsNotNone(sent["expires_at"])
        mid = sent["message_id"]
        self.assertEqual(self._unread(b)["total"], 1)
        past = (e2ee_db.now_utc() - timedelta(minutes=1)).isoformat()
        self._sql("UPDATE chat_dm_messages SET expires_at = ? WHERE message_id = ?", (past, mid))
        self.assertEqual(self._unread(b)["total"], 0)
        self.assertNotIn(mid, self._dlist(a, b))  # a had only a normal copy: gone
        row = self._dlist(b, a)[mid]  # b's undelivered setup copy is still delivered, flagged expired
        self.assertTrue(row["expired"])
        e2ee_db.purge_expired_messages()
        self.assertEqual(list(self._dlist(b, a)[mid]["device_ciphertexts"]), [b["dev"]])
        # timer off: new messages keep
        self.client.post(url, headers=a["h"], json={"scope_type": "dm", "peer_user_id": b["uid"], "ttl_seconds": 0})
        self.assertIsNone(self._dsend(a, b).json()["expires_at"])

    def test_disappearing_messages_group_admin_only_and_purged(self):
        admin, a = self._member(admin=True), self._member()
        gid = self._group(admin, a)
        url = "/api/e2ee/disappearing"
        self.assertEqual(self.client.post(url, headers=a["h"], json={"scope_type": "group", "group_id": gid, "ttl_seconds": 604800}).status_code, 403)
        self.assertEqual(self.client.post(url, headers=admin["h"], json={"scope_type": "group", "group_id": gid, "ttl_seconds": 604800}).status_code, 200)
        msg = self._gsend(gid, a).json()["message"]
        self.assertIsNotNone(msg["expires_at"])
        self._sql("UPDATE chat_group_messages SET expires_at = ? WHERE message_id = ?",
                  ((e2ee_db.now_utc() - timedelta(seconds=5)).isoformat(), msg["message_id"]))
        self.assertNotIn(msg["message_id"], self._glist(gid, admin))
        e2ee_db.purge_expired_messages()
        n = self._scalar("SELECT COUNT(*) FROM chat_group_messages WHERE message_id = ?", (msg["message_id"],))
        self.assertEqual(n, 0)  # really removed from the server

    # ------------------------------------------------------------------ pins
    def test_pins_group_admin_three_max_and_deleted_unpins(self):
        admin, a = self._member(admin=True), self._member()
        gid = self._group(admin, a)
        mids = [self._gsend(gid, a).json()["message"]["message_id"] for _ in range(4)]
        url = "/api/e2ee/pins"
        body = {"scope_type": "group", "group_id": gid, "message_id": mids[0], "pinned": True}
        self.assertEqual(self.client.post(url, headers=a["h"], json=body).status_code, 403)  # members cannot pin
        self.assertEqual(self.client.post(url, headers=admin["h"], json={**body, "message_id": "msg_" + "0" * 16}).status_code, 404)
        for mid in mids[:3]:
            self.assertEqual(self.client.post(url, headers=admin["h"], json={**body, "message_id": mid}).status_code, 200)
        r = self.client.post(url, headers=admin["h"], json={**body, "message_id": mids[3]}).json()
        self.assertEqual(r["replaced"], mids[0])  # the oldest made room
        self.assertEqual({p["message_id"] for p in r["pins"]}, set(mids[1:]))
        self.client.post(f"/api/e2ee/groups/{gid}/messages/{mids[3]}/delete", headers=admin["h"])
        st = self.client.get(f"/api/e2ee/conversations/state?scope_type=group&group_id={gid}", headers=a["h"]).json()
        self.assertEqual({p["message_id"] for p in st["pins"]}, set(mids[1:3]))
        self.assertFalse(st["can_manage"])

    def test_pins_dm_either_person(self):
        a, b = self._member(), self._member()
        mid = self._dsend(a, b).json()["message_id"]
        r = self.client.post("/api/e2ee/pins", headers=b["h"], json={"scope_type": "dm", "peer_user_id": a["uid"], "message_id": mid})
        self.assertEqual(r.status_code, 200, r.text)
        st = self.client.get(f"/api/e2ee/conversations/state?scope_type=dm&peer_user_id={b['uid']}", headers=a["h"]).json()
        self.assertEqual([p["message_id"] for p in st["pins"]], [mid])
        # someone outside the chat cannot pin into it (the message is not in THEIR chat with a)
        c = self._member()
        r = self.client.post("/api/e2ee/pins", headers=c["h"], json={"scope_type": "dm", "peer_user_id": a["uid"], "message_id": mid})
        self.assertEqual(r.status_code, 404)

    # ------------------------------------------------------------------ announcement groups
    def test_announcement_group_members_react_but_only_admins_post(self):
        admin, a = self._member(admin=True), self._member()
        gid = self._group(admin, a)
        url = f"/api/e2ee/groups/{gid}/settings"
        self.assertEqual(self.client.post(url, headers=a["h"], json={"admins_only_posting": True}).status_code, 403)
        self.assertEqual(self.client.post(url, headers=admin["h"], json={"admins_only_posting": True}).status_code, 200)
        r = self._gsend(gid, a)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["detail"]["code"], "admins_only")
        self.assertEqual(self._gsend(gid, a, kind="control").status_code, 200)  # reactions / votes still work
        self.assertEqual(self._gsend(gid, admin).status_code, 200)
        self.assertTrue(self.client.get(f"/api/e2ee/conversations/state?scope_type=group&group_id={gid}", headers=a["h"]).json()["admins_only"])
        self.client.post(url, headers=admin["h"], json={"admins_only_posting": False})
        self.assertEqual(self._gsend(gid, a).status_code, 200)

    # ------------------------------------------------------------------ mentions & typing
    def test_group_mentions_notify_only_mentioned_members(self):
        admin, a, b = self._member(admin=True), self._member(), self._member()
        outsider = self._member()
        gid = self._group(admin, a, b)
        with patch.object(e2ee_routes, "_schedule_ws_notify") as notify:
            self.assertEqual(self._gsend(gid, a, mentions=[b["uid"], outsider["uid"], a["uid"]]).status_code, 200)
        mention_calls = [c for c in notify.call_args_list if c.args[1]["type"] == "mention"]
        self.assertEqual(len(mention_calls), 1)
        self.assertEqual(mention_calls[0].args[0], [b["uid"]])  # not the outsider, not the sender
        self.assertNotIn("text", mention_calls[0].args[1])
        with patch.object(e2ee_routes, "_schedule_ws_notify") as notify:
            self._gsend(gid, a, kind="control", mentions=[b["uid"]])  # a reaction never notifies as a mention
        self.assertFalse([c for c in notify.call_args_list if c.args[1]["type"] == "mention"])

    def test_typing_respects_online_status_switch(self):
        a, b = self._member(), self._member()
        url = "/api/e2ee/typing"
        with patch.object(e2ee_routes, "_schedule_ws_notify") as notify:
            r = self.client.post(url, headers=a["h"], json={"scope_type": "dm", "peer_user_id": b["uid"]})
        self.assertTrue(r.json()["sent"])
        self.assertEqual(notify.call_args.args[0], [b["uid"]])
        self.assertEqual(notify.call_args.args[1]["type"], "typing")
        platform_db.update_user_profile(a["uid"], show_online_presence=False)
        platform_db.auth_cache.invalidate_all()
        with patch.object(e2ee_routes, "_schedule_ws_notify") as notify:
            r = self.client.post(url, headers=a["h"], json={"scope_type": "dm", "peer_user_id": b["uid"]})
        self.assertFalse(r.json()["sent"])
        notify.assert_not_called()
        admin = self._member(admin=True)
        gid = self._group(admin, b)
        self.assertEqual(self.client.post(url, headers=a["h"], json={"scope_type": "group", "group_id": gid}).status_code, 403)

    # ------------------------------------------------------------------ mute & archive
    def test_mute_and_archive_preferences(self):
        a, b = self._member(), self._member()
        url = "/api/e2ee/conversation-prefs"
        r = self.client.post(url, headers=a["h"], json={"scope_key": f"dm:{b['uid']}", "mute": "8h"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["pref"]["muted"])
        self.assertFalse(r.json()["pref"]["muted_forever"])
        r = self.client.post(url, headers=a["h"], json={"scope_key": "room", "mute": "always", "archived": False})
        self.assertTrue(r.json()["pref"]["muted_forever"])
        r = self.client.post(url, headers=a["h"], json={"scope_key": f"dm:{b['uid']}", "archived": True})
        self.assertTrue(r.json()["pref"]["muted"] and r.json()["pref"]["archived"])  # mute kept
        prefs = self.client.get(url, headers=a["h"]).json()["prefs"]
        self.assertEqual(set(prefs), {f"dm:{b['uid']}", "room"})
        self.client.post(url, headers=a["h"], json={"scope_key": f"dm:{b['uid']}", "mute": "off", "archived": False})
        self.assertEqual(set(self.client.get(url, headers=a["h"]).json()["prefs"]), {"room"})
        self.assertEqual(self.client.get(url, headers=b["h"]).json()["prefs"], {})  # private to each member
        self.assertEqual(self.client.post(url, headers=a["h"], json={"scope_key": "group:grp_notmine1", "mute": "1w"}).status_code, 403)
        self.assertEqual(self.client.post(url, headers=a["h"], json={"scope_key": "bad key!", "mute": "1w"}).status_code, 400)
        self.assertEqual(self.client.post(url, headers=a["h"], json={"scope_key": "room", "mute": "2h"}).status_code, 422)

    # ------------------------------------------------------------------ Members' room
    def _room_post(self, m, content):
        r = self.client.post("/api/platform/public-chat/messages", headers=m["h"], json={"content": content})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["message"]["message_id"]

    def test_room_reactions(self):
        a, b = self._member(), self._member()
        mid = self._room_post(a, "hello room")
        url = f"/api/platform/public-chat/messages/{mid}/reaction"
        self.assertEqual(self.client.post(url, headers=a["h"], json={"emoji": "👍"}).status_code, 200)
        r = self.client.post(url, headers=b["h"], json={"emoji": "👍"})
        self.assertEqual(sorted(r.json()["reactions"]["👍"]), sorted([a["uid"], b["uid"]]))
        r = self.client.post(url, headers=b["h"], json={"emoji": "❤️"})  # one reaction each: replaced
        self.assertEqual(r.json()["reactions"], {"👍": [a["uid"]], "❤️": [b["uid"]]})
        r = self.client.post(url, headers=a["h"], json={"emoji": None})  # removed
        self.assertEqual(r.json()["reactions"], {"❤️": [b["uid"]]})
        for bad in ("abc", "<b>", "👍" * 20, " "):
            self.assertEqual(self.client.post(url, headers=a["h"], json={"emoji": bad}).status_code, 400, bad)
        feed = self.client.get("/api/platform/public-chat/messages", headers=a["h"]).json()
        self.assertEqual(next(m for m in feed["messages"] if m["message_id"] == mid)["reactions"], {"❤️": [b["uid"]]})
        self.client.delete(f"/api/platform/public-chat/messages/{mid}", headers=a["h"])
        self.assertEqual(chat_features_db.reactions_for_messages([mid]), {})
        self.assertEqual(self.client.post(url, headers=a["h"], json={"emoji": "👍"}).status_code, 404)

    def test_room_mentions_and_typing(self):
        a, b = self._member(), self._member()
        self.client.patch("/api/e2ee/account/username", headers=b["h"], json={"username": "bob_" + secrets.token_hex(3)})
        bname = e2ee_db.get_user_by_id(b["uid"])["username"]
        with patch.object(platform_routes, "_schedule_ws_notify") as notify:
            self._room_post(a, f"hey @{bname.upper()} and @nobody_here_xyz and @{bname}")
        calls = [c for c in notify.call_args_list if c.args[1]["type"] == "mention"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args[0], [b["uid"]])  # case-insensitive, once, unknown names ignored
        platform_db.block_user(b["uid"], a["uid"])
        with patch.object(platform_routes, "_schedule_ws_notify") as notify:
            self._room_post(a, f"@{bname} again")
        self.assertFalse([c for c in notify.call_args_list if c.args[1]["type"] == "mention"])  # blocked: no notice
        with patch.object(platform_routes, "schedule_public_ws_broadcast") as bc:
            self.assertTrue(self.client.post("/api/platform/public-chat/typing", headers=a["h"]).json()["sent"])
        self.assertEqual(bc.call_args.args[0]["type"], "public_typing")
        platform_db.update_user_profile(a["uid"], show_online_presence=False)
        platform_db.auth_cache.invalidate_all()
        self.assertFalse(self.client.post("/api/platform/public-chat/typing", headers=a["h"]).json()["sent"])

    def test_room_pins_by_moderators_only(self):
        a, admin = self._member(), self._member(admin=True)
        mid = self._room_post(a, "rules: be kind")
        url = "/api/platform/public-chat/pins"
        self.assertEqual(self.client.post(url, headers=a["h"], json={"message_id": mid}).status_code, 403)
        self.assertEqual(self.client.post(url, headers=admin["h"], json={"message_id": mid}).status_code, 200)
        feed = self.client.get("/api/platform/public-chat/messages", headers=a["h"]).json()
        self.assertEqual([p["message_id"] for p in feed["pins"]], [mid])
        self.client.delete(f"/api/platform/public-chat/messages/{mid}", headers=a["h"])
        self.assertEqual(self.client.get("/api/platform/public-chat/messages", headers=a["h"]).json()["pins"], [])

    # ------------------------------------------------------------------ banner & reminders
    def test_admin_banner(self):
        admin = self._member(admin=True)
        self.assertIsNone(self.client.get("/api/platform/announcement").json()["announcement"])
        r = self.client.put("/api/platform/admin/settings", headers=admin["h"],
                            json={"announcement_text": "  Maintenance\nSunday 10 pm  ", "announcement_level": "warning"})
        self.assertEqual(r.status_code, 200, r.text)
        ann = self.client.get("/api/platform/announcement").json()["announcement"]
        self.assertEqual((ann["text"], ann["level"]), ("Maintenance Sunday 10 pm", "warning"))
        first_id = ann["id"]
        self.client.put("/api/platform/admin/settings", headers=admin["h"], json={"announcement_level": "info"})
        self.assertEqual(self.client.get("/api/platform/announcement").json()["announcement"]["id"], first_id)  # same text
        self.client.put("/api/platform/admin/settings", headers=admin["h"], json={"announcement_text": "New text"})
        self.assertNotEqual(self.client.get("/api/platform/announcement").json()["announcement"]["id"], first_id)
        past = (platform_db._now() - timedelta(hours=1)).isoformat()
        self.client.put("/api/platform/admin/settings", headers=admin["h"], json={"announcement_ends_at": past})
        self.assertIsNone(self.client.get("/api/platform/announcement").json()["announcement"])
        self.assertEqual(self.client.put("/api/platform/admin/settings", headers=admin["h"],
                                         json={"announcement_level": "loud"}).status_code, 422)
        self.client.put("/api/platform/admin/settings", headers=admin["h"], json={"announcement_text": "", "announcement_ends_at": ""})
        self.assertIsNone(self.client.get("/api/platform/announcement").json()["announcement"])
        m = self._member()
        self.assertEqual(self.client.put("/api/platform/admin/settings", headers=m["h"], json={"announcement_text": "x"}).status_code, 403)

    def _set_platform_until(self, uid, delta):
        until = (platform_db._now() + delta).isoformat()
        self._sql("INSERT OR REPLACE INTO member_subscriptions (user_id, scope_type, scope_id, paid_until, last_period, updated_at) "
                  "VALUES (?, 'platform', 'platform', ?, 'monthly', ?)", (uid, until, until))
        platform_db.auth_cache.invalidate_all()

    def test_renewal_reminders(self):
        self._enable_paywall(usd=10)
        m = self._member()
        stages = []
        for delta in (timedelta(days=30), timedelta(days=5), timedelta(hours=10), timedelta(days=-2), timedelta(days=-20)):
            self._set_platform_until(m["uid"], delta)
            rs = self.client.get("/api/platform/reminders", headers=m["h"]).json()["reminders"]
            stages.append(rs[0]["stage"] if rs else None)
        self.assertEqual(stages, [None, "7d", "1d", "expired", None])
        self._set_platform_until(m["uid"], timedelta(days=3))
        r = self.client.get("/api/platform/reminders", headers=m["h"]).json()["reminders"][0]
        self.assertEqual((r["scope_type"], r["name"]), ("platform", "Membership"))
        self.assertTrue(r["key"].startswith("platform:platform:7d:"))
        # a lifetime free-access grant means nothing to renew
        admin = self._member(admin=True)
        self.client.post("/api/platform/admin/access-grants", headers=admin["h"], json={"user_id": m["uid"], "scope_type": "platform"})
        self.assertEqual(self.client.get("/api/platform/reminders", headers=m["h"]).json()["reminders"], [])
        # free membership: no reminders
        self._enable_paywall(usd=0)
        other = self._member()
        self._set_platform_until(other["uid"], timedelta(days=2))
        self.assertEqual(self.client.get("/api/platform/reminders", headers=other["h"]).json()["reminders"], [])

    def test_paid_group_reminder(self):
        self._enable_paywall(usd=0)
        admin, m = self._member(admin=True), self._member()
        gid = self._create_group(admin["h"], admin["dev"], is_paid=True, entry_fee_usd=20, visibility="public").json()["group"]["group_id"]
        until = (platform_db._now() + timedelta(hours=20)).isoformat()
        self._sql("INSERT INTO member_subscriptions (user_id, scope_type, scope_id, paid_until, last_period, updated_at) "
                  "VALUES (?, 'group', ?, ?, 'monthly', ?)", (m["uid"], gid, until, until))
        platform_db.auth_cache.invalidate_all()
        # not in the group yet: nothing to remind about
        self.assertEqual(self.client.get("/api/platform/reminders", headers=m["h"]).json()["reminders"], [])
        self.client.post(f"/api/platform/groups/{gid}/join-request", headers=m["h"])
        epoch = e2ee_db.get_mls_group(gid)["current_epoch"]
        self.client.post(f"/api/e2ee/groups/{gid}/commits", headers=admin["h"], json={
            "committer_device_id": admin["dev"], "expected_epoch": epoch, "commit_type": "add",
            "mls_commit_b64": _b64(secrets.token_bytes(96)),
            "added_members": [{"user_id": m["uid"], "device_id": m["dev"], "role": "member"}],
            "welcomes": [{"target_user_id": m["uid"], "target_device_id": m["dev"], "mls_welcome_b64": _b64(secrets.token_bytes(120))}]})
        rs = self.client.get("/api/platform/reminders", headers=m["h"]).json()["reminders"]
        self.assertEqual([(r["scope_type"], r["scope_id"], r["stage"]) for r in rs], [("group", gid, "1d")])
        self.assertEqual(rs[0]["name"], "VIP Alpha Traders")

    def test_deleting_a_group_clears_its_chat_settings(self):
        admin, a = self._member(admin=True), self._member()
        gid = self._group(admin, a)
        mid = self._gsend(gid, a).json()["message"]["message_id"]
        self.client.post("/api/e2ee/pins", headers=admin["h"], json={"scope_type": "group", "group_id": gid, "message_id": mid})
        self.client.post("/api/e2ee/disappearing", headers=admin["h"], json={"scope_type": "group", "group_id": gid, "ttl_seconds": 86400})
        self.client.post(f"/api/e2ee/groups/{gid}/settings", headers=admin["h"], json={"admins_only_posting": True})
        self.assertEqual(self.client.delete(f"/api/platform/admin/groups/{gid}", headers=admin["h"]).status_code, 200)
        key = chat_features_db.group_scope_key(gid)
        self.assertEqual(chat_features_db.list_pins(key), [])
        self.assertEqual(chat_features_db.get_disappearing_ttl(key), 0)
        self.assertFalse(chat_features_db.is_admins_only(gid))


if __name__ == "__main__":
    unittest.main()
