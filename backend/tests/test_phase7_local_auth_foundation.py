import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import arbor.auth as auth_mod
import arbor.local_auth as local_auth
import arbor.main as web_main
import arbor.session as session_mod


class FakeRequest:
    def __init__(self, body=None, *, cookies=None, headers=None, client_host="127.0.0.1"):
        self._body = body
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.client = SimpleNamespace(host=client_host)

    async def body(self):
        if self._body is None:
            return b""
        return json.dumps(self._body).encode("utf-8")


class LocalAuthStoreTests(unittest.TestCase):
    def test_hash_and_verify_password_roundtrip(self):
        hashed = local_auth.hash_password("correct horse battery staple")
        self.assertTrue(local_auth.verify_password("correct horse battery staple", hashed))
        self.assertFalse(local_auth.verify_password("wrong", hashed))

    def test_create_and_find_user_with_temp_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            with patch.dict(os.environ, {"ARBOR_AUTH_DB": str(auth_db)}, clear=False):
                created = local_auth.create_local_user("owner", "secret-password", role="owner")
                fetched = local_auth.find_user_by_username("owner")

        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["user_id"], created["user_id"])
        self.assertEqual(fetched["username"], "owner")
        self.assertEqual(fetched["role"], "owner")


class LocalAuthPermissionHardeningTests(unittest.TestCase):
    def test_fix_permissions_can_be_disabled_by_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "auth.db"
            db_path.write_text("", encoding="utf-8")
            with (
                patch.dict(os.environ, {"ARBOR_AUTH_AUTOHEAL_PERMS": "0"}, clear=False),
                patch.object(local_auth, "_is_system_auth_db", return_value=True),
                patch.object(local_auth.os, "geteuid", return_value=0),
                patch.object(local_auth.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=123)),
                patch.object(local_auth.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=456)),
                patch.object(local_auth.os, "chown") as mocked_chown,
                patch.object(local_auth.os, "chmod") as mocked_chmod,
            ):
                local_auth._fix_system_auth_db_permissions(db_path)
        mocked_chown.assert_not_called()
        mocked_chmod.assert_not_called()

    def test_fix_permissions_skips_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            real_parent = root / "real-parent"
            real_parent.mkdir()
            symlink_parent = root / "link-parent"
            symlink_parent.symlink_to(real_parent, target_is_directory=True)
            db_path = symlink_parent / "auth.db"
            db_path.write_text("", encoding="utf-8")

            with (
                patch.object(local_auth, "_is_system_auth_db", return_value=True),
                patch.object(local_auth.os, "geteuid", return_value=0),
                patch.object(local_auth.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=123)),
                patch.object(local_auth.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=456)),
                patch.object(local_auth.os, "chown") as mocked_chown,
                patch.object(local_auth.os, "chmod") as mocked_chmod,
                patch.object(local_auth.log, "warning") as mocked_warning,
            ):
                local_auth._fix_system_auth_db_permissions(db_path)

        mocked_chown.assert_not_called()
        mocked_chmod.assert_not_called()
        self.assertTrue(mocked_warning.called)

    def test_fix_permissions_logs_owner_transition(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "auth.db"
            db_path.write_text("", encoding="utf-8")

            with (
                patch.object(local_auth, "_is_system_auth_db", return_value=True),
                patch.object(local_auth.os, "geteuid", return_value=0),
                patch.object(local_auth.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=123)),
                patch.object(local_auth.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=456)),
                patch.object(local_auth.os, "chown"),
                patch.object(local_auth.os, "chmod"),
                patch.object(local_auth.log, "warning") as mocked_warning,
            ):
                local_auth._fix_system_auth_db_permissions(db_path)

        transition_logs = [
            call for call in mocked_warning.call_args_list if "ownership transition" in str(call.args[0])
        ]
        self.assertTrue(transition_logs)


class SessionStoreTests(unittest.TestCase):
    def test_create_get_and_revoke_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            with patch.dict(os.environ, {"ARBOR_AUTH_DB": str(auth_db)}, clear=False):
                user = local_auth.create_local_user("owner", "secret-password", role="owner")
                created = session_mod.create_session(user["user_id"])
                active = session_mod.get_session(created["session_id"])
                self.assertIsNotNone(active)
                self.assertEqual(active["user_id"], user["user_id"])
                session_mod.revoke_session(created["session_id"], reason="logout")
                revoked = session_mod.get_session(created["session_id"])
                self.assertIsNone(revoked)


class LocalAuthApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_login_session_logout_flow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            env = {
                "ARBOR_AUTH_DB": str(auth_db),
                "ARBOR_AUTH_BACKEND": "local",
            }
            with patch.dict(os.environ, env, clear=False):
                local_auth.create_local_user("owner", "secret-password", role="owner")

                login_req = FakeRequest(
                    {"username": "owner", "password": "secret-password"},
                    headers={"user-agent": "test-suite"},
                )
                login_resp = await web_main.auth_login(login_req)
                self.assertEqual(login_resp.status_code, 200)

                set_cookie = login_resp.headers.get("set-cookie", "")
                session_id = ""
                prefix = session_mod.session_cookie_name() + "="
                if set_cookie.startswith(prefix):
                    session_id = set_cookie.split(";", 1)[0][len(prefix):]
                self.assertTrue(session_id)

                session_req = FakeRequest(cookies={session_mod.session_cookie_name(): session_id})
                session_payload = await web_main.auth_session(session_req)
                self.assertTrue(session_payload["authenticated"])
                self.assertEqual(session_payload["username"], "owner")

                logout_req = FakeRequest(cookies={session_mod.session_cookie_name(): session_id})
                logout_resp = await web_main.auth_logout(logout_req)
                self.assertEqual(logout_resp.status_code, 200)
                self.assertEqual(json.loads(logout_resp.body), {"ok": True})

                session_payload_after = await web_main.auth_session(session_req)
                self.assertFalse(session_payload_after["authenticated"])

    async def test_require_auth_uses_session_in_local_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            env = {
                "ARBOR_AUTH_DB": str(auth_db),
                "ARBOR_AUTH_BACKEND": "local",
            }
            with patch.dict(os.environ, env, clear=False):
                user = local_auth.create_local_user("owner", "secret-password", role="owner")
                session = session_mod.create_session(user["user_id"])
                req = FakeRequest(cookies={session_mod.session_cookie_name(): session["session_id"]})
                principal = auth_mod.require_auth(req, None)
                self.assertEqual(principal, user["user_id"])


if __name__ == "__main__":
    unittest.main()
