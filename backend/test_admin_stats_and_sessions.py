"""Admin dashboard numbers, login-session housekeeping, group deletion and 'Online now' (Nov 2026 audit)."""
import base64
import os
import secrets
import sys
import unittest
from datetime import timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["TESTING"] = "1"

from eth_account import Account

import chat_db
import e2ee_db
import platform_db
import public_attachments_db as pad
from e2ee_routes import realtime_hub
from test_e2ee_security import generate_signed_test_device
from test_subscriptions import TestSubscriptions as _Base


class TestAdminStatsAndSessions(_Base):
    # ---- helpers ---------------------------------------------------------------------------
    def _member(self, register_device=False):
        acc = Account.create()
        d = self._siwe_login(acc)
        uid = d["user"]["user_id"]
        h = {"Authorization": f"Bearer {d['session_token']}"}
        dev = None
        if register_device:
            dev = f"dev_s_{secrets.token_hex(4)}"
            b, _ = generate_signed_test_device(uid, dev)
            self.client.post("/api/e2ee/devices/register", json=b, headers=h)
        return acc, uid, h, dev

    def _sql(self, sql, params=()):
        with chat_db._sqlite_lock:
            chat_db._sqlite_conn.execute(sql, params)
            chat_db._sqlite_conn.commit()

    def _sessions_of(self, uid):
        with chat_db._sqlite_lock:
            return chat_db._sqlite_conn.execute(
                "SELECT session_id, revoked, expires_at, created_at FROM chat_auth_sessions WHERE user_id = ? ORDER BY created_at",
                (uid,),
            ).fetchall()

    # ---- login sessions ----------------------------------------------------------------------
    def test_session_cap_signs_out_the_oldest(self):
        acc = Account.create()
        logins = [self._siwe_login(acc) for _ in range(12)]
        uid = logins[0]["user"]["user_id"]
        live = [s for s in self._sessions_of(uid) if not s["revoked"]]
        self.assertEqual(len(live), e2ee_db.MAX_ACTIVE_SESSIONS_PER_USER)
        # the two OLDEST were signed out, the newest still work
        old = {"Authorization": f"Bearer {logins[0]['session_token']}"}
        new = {"Authorization": f"Bearer {logins[-1]['session_token']}"}
        self.assertEqual(self.client.get("/api/e2ee/me", headers=old).status_code, 401)
        self.assertEqual(self.client.get("/api/e2ee/me", headers=new).status_code, 200)
        # and the dashboard still counts this person once
        base = platform_db.admin_get_overview_stats()["active_sessions"]
        self.assertGreaterEqual(base, 1)

    def test_purge_removes_only_stale_sessions(self):
        _, uid, _, _ = self._member()
        now = platform_db._now()
        rows = {
            "expired_long_ago": ((now - timedelta(days=10)).isoformat(), 0, (now - timedelta(days=11)).isoformat()),
            "revoked_long_ago": ((now + timedelta(hours=1)).isoformat(), 1, (now - timedelta(days=9)).isoformat()),
            "expired_recently": ((now - timedelta(hours=1)).isoformat(), 0, (now - timedelta(hours=25)).isoformat()),
            "revoked_recently": ((now + timedelta(hours=1)).isoformat(), 1, (now - timedelta(hours=2)).isoformat()),
            "live": ((now + timedelta(hours=5)).isoformat(), 0, (now - timedelta(hours=1)).isoformat()),
        }
        for name, (exp, rev, created) in rows.items():
            self._sql(
                "INSERT INTO chat_auth_sessions (session_id, token_hash, user_id, wallet_address, expires_at, revoked, created_at) "
                "VALUES (?, ?, ?, '0x0', ?, ?, ?)",
                (f"sess_t_{name}", secrets.token_hex(32), uid, exp, rev, created),
            )
        removed = e2ee_db.purge_stale_auth_sessions()
        self.assertGreaterEqual(removed, 2)
        left = {r["session_id"] for r in self._sessions_of(uid)}
        self.assertNotIn("sess_t_expired_long_ago", left)
        self.assertNotIn("sess_t_revoked_long_ago", left)
        for kept in ("expired_recently", "revoked_recently", "live"):
            self.assertIn(f"sess_t_{kept}", left)

    # ---- dashboard numbers ---------------------------------------------------------------------
    def test_paid_members_vs_registered_and_free_mode(self):
        self._enable_paywall(usd=10, rate=2500.0)
        before = platform_db.admin_get_overview_stats()
        self.assertFalse(before["membership_free"])
        pay_acc, pay_uid, pay_h, _ = self._member()
        self._member()  # connected, never paid
        mid = platform_db.admin_get_overview_stats()
        self.assertEqual(mid["total_users"] - before["total_users"], 2)
        self.assertEqual(mid["paid_members"] - before["paid_members"], 0)
        r = self._pay(pay_h, pay_acc, "0.004", "monthly")
        self.assertTrue(r.json()["success"], r.text)
        after = platform_db.admin_get_overview_stats()
        self.assertEqual(after["paid_members"] - before["paid_members"], 1)
        self._expire(pay_uid)
        self.assertEqual(platform_db.admin_get_overview_stats()["paid_members"] - before["paid_members"], 0)
        platform_db.update_platform_settings({"platform_entry_fee_usd": 0}, actor_user_id="t")
        self.assertTrue(platform_db.admin_get_overview_stats()["membership_free"])
        self.assertIn("generated_at", after)

    def test_room_message_count_matches_what_members_can_see(self):
        _, uid, h, _ = self._member()
        before = platform_db.admin_get_overview_stats()["public_messages"]
        for i in range(3):
            self.client.post("/api/platform/public-chat/messages", headers=h, json={"content": f"count{i}"})
        # one file attached to the message that will become too old
        data = base64.b64encode(b"hello file").decode()
        aid = self.client.post("/api/platform/public-chat/attachments", headers=h,
                               json={"file_name": "a.txt", "mime_type": "text/plain", "data_b64": data}).json()["attachment"]["attachment_id"]
        old_mid = self.client.post("/api/platform/public-chat/messages", headers=h,
                                   json={"content": "old one", "attachment_ids": [aid]}).json()["message"]["message_id"]
        self._sql("UPDATE public_chat_messages SET created_at = ? WHERE message_id = ?",
                  ((platform_db._now() - timedelta(days=200)).isoformat(), old_mid))
        self.assertEqual(platform_db.admin_get_overview_stats()["public_messages"] - before, 3)
        feed = self.client.get("/api/platform/public-chat/messages?limit=100", headers=h).json()["messages"]
        self.assertEqual(len([m for m in feed if m["content"].startswith("count")]), 3)
        self.assertNotIn(old_mid, [m["message_id"] for m in feed])
        # the next upload also frees the file of the message that fell out of retention
        self.client.post("/api/platform/public-chat/attachments", headers=h,
                         json={"file_name": "b.txt", "mime_type": "text/plain", "data_b64": data})
        self.assertEqual(self.client.get(f"/api/platform/public-chat/attachments/{aid}", headers=h).status_code, 410)

    # ---- groups: counted only while they exist and have members; deletable ---------------------
    def test_group_count_delete_and_permissions(self):
        self._enable_paywall(usd=0, rate=2000.0)
        _, _, admin_h, admin_dev = self._make_admin()
        _, owner_uid, owner_h, owner_dev = self._member(register_device=True)
        _, _, other_h, _ = self._member(register_device=True)
        base = platform_db.admin_get_overview_stats()["total_groups"]

        g = self._create_group(owner_h, owner_dev, visibility="public")
        self.assertEqual(g.status_code, 200, g.text)
        gid = g.json()["group"]["group_id"]
        self.assertEqual(platform_db.admin_get_overview_stats()["total_groups"] - base, 1)

        # a group with nobody left in it is not counted, and is flagged empty in the admin list
        self._sql("UPDATE chat_group_members SET status = 'removed' WHERE group_id = ?", (gid,))
        self.assertEqual(platform_db.admin_get_overview_stats()["total_groups"] - base, 0)
        listed = {x["group_id"]: x for x in platform_db.admin_list_all_groups()}
        self.assertTrue(listed[gid]["empty"])
        self.assertEqual(listed[gid]["active_member_count"], 0)
        self._sql("UPDATE chat_group_members SET status = 'active' WHERE group_id = ?", (gid,))
        self.assertEqual(platform_db.admin_get_overview_stats()["total_groups"] - base, 1)
        self.assertEqual({x["group_id"]: x for x in platform_db.admin_list_all_groups()}[gid]["active_member_count"], 1)

        # someone who is not an admin of the group cannot delete it; unknown group -> 404
        self.assertEqual(self.client.delete(f"/api/platform/groups/{gid}", headers=other_h).status_code, 403)
        self.assertEqual(self.client.delete("/api/platform/groups/grp_doesnotexist", headers=owner_h).status_code, 404)

        # the group's own admin deletes it: gone from the count, the lists and discovery
        r = self.client.delete(f"/api/platform/groups/{gid}", headers=owner_h)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(platform_db.admin_get_overview_stats()["total_groups"] - base, 0)
        self.assertNotIn(gid, [x["group_id"] for x in self.client.get("/api/e2ee/groups", headers=owner_h).json()["groups"]])
        self.assertNotIn(gid, [x["group_id"] for x in self.client.get("/api/platform/groups/discover", headers=other_h).json()["groups"]])
        self.assertNotIn(gid, [x["group_id"] for x in platform_db.admin_list_all_groups()])
        with chat_db._sqlite_lock:
            for table in ("chat_group_members", "chat_group_messages", "group_invite_links", "group_access_policies"):
                n = chat_db._sqlite_conn.execute(f"SELECT COUNT(*) FROM {table} WHERE group_id = ?", (gid,)).fetchone()[0]
                self.assertEqual(n, 0, table)
        self.assertEqual(self.client.delete(f"/api/platform/groups/{gid}", headers=owner_h).status_code, 404)

    def test_paid_group_only_deleted_by_platform_admin(self):
        self._enable_paywall(usd=0, rate=2000.0)
        _, _, admin_h, _ = self._make_admin()
        _, _, owner_h, owner_dev = self._member(register_device=True)
        gid = self._create_group(owner_h, owner_dev).json()["group"]["group_id"]
        # the platform admin turns it into a paid group
        r = self.client.put(f"/api/platform/groups/{gid}/policy", headers=admin_h, json={
            "description": "VIP", "visibility": "public", "require_invitation": False, "is_paid": True, "entry_fee_usd": 20})
        self.assertEqual(r.status_code, 200, r.text)
        denied = self.client.delete(f"/api/platform/groups/{gid}", headers=owner_h)
        self.assertEqual(denied.status_code, 403)
        self.assertIn("platform admin", denied.json()["detail"])
        # members cannot use the admin route either
        self.assertEqual(self.client.delete(f"/api/platform/admin/groups/{gid}", headers=owner_h).status_code, 403)
        base = platform_db.admin_get_overview_stats()["total_groups"]
        ok = self.client.delete(f"/api/platform/admin/groups/{gid}", headers=admin_h)
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(base - platform_db.admin_get_overview_stats()["total_groups"], 1)
        logs = platform_db.list_audit_logs(limit=20)
        self.assertTrue(any(l["action"] == "group_deleted" and l["entity_id"] == gid for l in logs))

    # ---- Online now: admin wallets are counted for the admin dashboard only ---------------------
    def test_online_now_counts_admins_only_when_asked(self):
        ws_user, ws_admin = object(), object()
        saved = (realtime_hub._connections, realtime_hub._admin_ids_cache, realtime_hub._admin_ids_at)
        try:
            realtime_hub._connections = {"usr_normal": {ws_user}, "usr_admin": {ws_admin}}
            realtime_hub._admin_ids_cache = {"usr_admin"}
            realtime_hub._admin_ids_at = 10 ** 12  # keep the cached admin list
            members_view = realtime_hub._compute_online_stats(True, False)
            admin_view = realtime_hub._compute_online_stats(True, True)
            self.assertEqual(members_view["authenticated_users"], 1)
            self.assertEqual(admin_view["authenticated_users"], 2)
            self.assertEqual(admin_view["admins_online"], 1)
            self.assertEqual(realtime_hub.get_online_stats(True, True)["authenticated_users"], 2)
            self.assertEqual(realtime_hub.get_online_stats(True)["authenticated_users"], 1)
        finally:
            realtime_hub._connections, realtime_hub._admin_ids_cache, realtime_hub._admin_ids_at = saved


# Run only this class's tests (the fixtures' own tests belong to their own classes).
for _name in [n for n in dir(_Base) if n.startswith("test_")]:
    setattr(TestAdminStatsAndSessions, _name, None)

if __name__ == "__main__":
    unittest.main()