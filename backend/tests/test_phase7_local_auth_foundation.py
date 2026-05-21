import json
import os
import tempfile
import unittest
import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import arbor.auth as auth_mod
import arbor.approval_mode as approval_mode
import arbor.authorization as authz
import arbor.local_auth as local_auth
import arbor.main as web_main
import arbor.session as session_mod
import arbor.totp_admin as totp_admin


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

    def test_create_user_rejects_short_password_in_core_api(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            with patch.dict(os.environ, {"ARBOR_AUTH_DB": str(auth_db)}, clear=False):
                with self.assertRaisesRegex(ValueError, "password too short"):
                    local_auth.create_local_user("owner", "short", role="owner")


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


class TotpAdminTests(unittest.TestCase):
    def test_begin_enrollment_writes_secret_file_and_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / "arbor.env"
            secret_path = Path(tmpdir) / "totp.secret"
            with patch.dict(
                os.environ,
                {"ARBOR_ENV_FILE": str(env_path), "ARBOR_TOTP_SECRET_FILE": str(secret_path)},
                clear=False,
            ):
                result = totp_admin.begin_totp_enrollment()
                self.assertTrue(secret_path.exists())
                self.assertTrue(result["pending_enrollment"])
                self.assertIn("otpauth://totp/", result["otpauth_uri"])
                if "qr_svg" in result:
                    self.assertTrue(result["qr_svg"].startswith("<svg"))
                    self.assertFalse(result["qr_svg"].startswith("<?xml"))
                if "qr_data_url" in result:
                    self.assertTrue(result["qr_data_url"].startswith("data:image/svg+xml;base64,"))
                    raw_svg = base64.b64decode(result["qr_data_url"].split(",", 1)[1]).decode("utf-8")
                    self.assertTrue(raw_svg.startswith("<svg"))
                    self.assertFalse(raw_svg.startswith("<?xml"))
                env_text = env_path.read_text(encoding="utf-8")
                self.assertIn(f"ARBOR_TOTP_SECRET_FILE={secret_path}", env_text)

    def test_disable_totp_removes_secret_and_unsets_env_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = Path(tmpdir) / "arbor.env"
            secret_path = Path(tmpdir) / "totp.secret"
            secret_path.write_text("JBSWY3DPEHPK3PXP\n", encoding="utf-8")
            env_path.write_text(
                f"ARBOR_AUTH_MODE=totp\nARBOR_TOTP_SECRET_FILE={secret_path}\nARBOR_TOTP_SECRET=INLINE\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "ARBOR_ENV_FILE": str(env_path),
                    "ARBOR_TOTP_SECRET_FILE": str(secret_path),
                    "ARBOR_AUTH_MODE": "totp",
                    "ARBOR_TOTP_SECRET": "INLINE",
                },
                clear=False,
            ):
                result = totp_admin.disable_totp_login(secret_path=secret_path)
                self.assertFalse(secret_path.exists())
                self.assertFalse(result["enabled"])
                env_text = env_path.read_text(encoding="utf-8")
                self.assertIn("ARBOR_AUTH_MODE=cli", env_text)
                self.assertNotIn("ARBOR_TOTP_SECRET_FILE", env_text)
                self.assertNotIn("ARBOR_TOTP_SECRET=", env_text)


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

    def test_role_change_revokes_existing_sessions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            with patch.dict(os.environ, {"ARBOR_AUTH_DB": str(auth_db)}, clear=False):
                user = local_auth.create_local_user("owner", "secret-password", role="viewer")
                created = session_mod.create_session(user["user_id"])
                updated = local_auth.set_local_user_role("owner", "operator")
                self.assertIsNotNone(updated)
                self.assertIsNone(session_mod.get_session(created["session_id"]))

    def test_password_change_timestamp_invalidates_existing_sessions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            with patch.dict(os.environ, {"ARBOR_AUTH_DB": str(auth_db)}, clear=False):
                user = local_auth.create_local_user("owner", "secret-password", role="owner")
                created = session_mod.create_session(user["user_id"])
                with session_mod._db_conn() as conn:
                    conn.execute(
                        "UPDATE local_user SET password_changed_at=? WHERE user_id=?",
                        (created["expires_at"], user["user_id"]),
                    )
                self.assertIsNone(session_mod.get_session(created["session_id"]))

    def test_revoke_all_sessions_invalidates_every_active_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            with patch.dict(os.environ, {"ARBOR_AUTH_DB": str(auth_db)}, clear=False):
                owner = local_auth.create_local_user("owner", "secret-password", role="owner")
                operator = local_auth.create_local_user("operator", "secret-password", role="operator")
                owner_session = session_mod.create_session(owner["user_id"])
                operator_session = session_mod.create_session(operator["user_id"])
                session_mod.revoke_all_sessions(reason="policy_changed")

                self.assertIsNone(session_mod.get_session(owner_session["session_id"]))
                self.assertIsNone(session_mod.get_session(operator_session["session_id"]))


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
                principal = await auth_mod.require_auth(req, None)
                self.assertEqual(principal, user["user_id"])

    async def test_login_throttles_repeated_attempts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            env = {
                "ARBOR_AUTH_DB": str(auth_db),
                "ARBOR_LOGIN_IP_FAILURE_THRESHOLD": "1",
                "ARBOR_LOGIN_USER_FAILURE_THRESHOLD": "1",
                "ARBOR_LOGIN_PAIR_FAILURE_THRESHOLD": "1",
                "ARBOR_LOGIN_LOCKOUT_SECONDS": "120",
            }
            with patch.dict(os.environ, env, clear=False):
                local_auth.create_local_user("owner", "secret-password", role="owner")
                failed = FakeRequest(
                    {"username": "owner", "password": "wrong-password"},
                    headers={"user-agent": "test-suite"},
                )
                failed_resp = await web_main.auth_login(failed)
                self.assertEqual(failed_resp.status_code, 401)

                blocked = FakeRequest(
                    {"username": "owner", "password": "secret-password"},
                    headers={"user-agent": "test-suite"},
                )
                blocked_resp = await web_main.auth_login(blocked)
                self.assertEqual(blocked_resp.status_code, 401)
                self.assertEqual(json.loads(blocked_resp.body), {"error": "invalid username or password"})

    async def test_login_requires_totp_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            env = {
                "ARBOR_AUTH_DB": str(auth_db),
                "ARBOR_AUTH_MODE": "totp",
                "ARBOR_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
            }
            with patch.dict(os.environ, env, clear=False):
                local_auth.create_local_user("owner", "secret-password", role="owner")
                missing_code = FakeRequest({"username": "owner", "password": "secret-password"})
                missing_resp = await web_main.auth_login(missing_code)
                self.assertEqual(missing_resp.status_code, 401)

                ok_req = FakeRequest(
                    {
                        "username": "owner",
                        "password": "secret-password",
                        "totp_code": approval_mode.totp_code("JBSWY3DPEHPK3PXP"),
                    }
                )
                ok_resp = await web_main.auth_login(ok_req)
                self.assertEqual(ok_resp.status_code, 200)
                self.assertEqual(json.loads(ok_resp.body)["step_up_method"], "totp")

    async def test_auth_totp_status_owner_endpoint_returns_daemon_status(self):
        authz.set_current_principal({"backend": "local", "subject": "u1", "username": "owner", "role": "owner"})
        try:
            query_one = AsyncMock(return_value={"enabled": False, "pending_enrollment": False})
            with patch.object(web_main, "query_one", query_one):
                data = await web_main.auth_totp_status("u1")
        finally:
            authz.set_current_principal(None)

        self.assertEqual(data["enabled"], False)
        query_one.assert_awaited_once_with("totp_status", {})

    async def test_auth_totp_status_prefers_active_login_totp_state(self):
        authz.set_current_principal({"backend": "local", "subject": "u1", "username": "owner", "role": "owner"})
        try:
            query_one = AsyncMock(return_value={"enabled": False, "pending_enrollment": True})
            with (
                patch.dict(os.environ, {"ARBOR_AUTH_MODE": "totp", "ARBOR_TOTP_SECRET": "JBSWY3DPEHPK3PXP"}, clear=False),
                patch.object(web_main, "query_one", query_one),
            ):
                data = await web_main.auth_totp_status("u1")
        finally:
            authz.set_current_principal(None)

        self.assertEqual(data["enabled"], True)
        self.assertEqual(data["pending_enrollment"], False)

    async def test_auth_totp_confirm_revokes_sessions_and_clears_cookie(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            env = {
                "ARBOR_AUTH_DB": str(auth_db),
                "ARBOR_TOTP_SECRET_FILE": str(Path(tmpdir) / "totp.secret"),
            }
            with patch.dict(os.environ, env, clear=False):
                owner = local_auth.create_local_user("owner", "secret-password", role="owner")
                session = session_mod.create_session(owner["user_id"])
                authz.set_current_principal({"backend": "local", "subject": owner["user_id"], "username": "owner", "role": "owner"})
                try:
                    request = FakeRequest({"code": "123456"}, cookies={session_mod.session_cookie_name(): session["session_id"]})
                    query_one = AsyncMock(return_value={"enabled": True, "pending_enrollment": False, "secret_file": str(Path(tmpdir) / "totp.secret")})
                    with (
                        patch.object(web_main, "query_one", query_one),
                        patch.object(web_main, "env_file_value", return_value="totp"),
                    ):
                        response = await web_main.auth_totp_confirm(owner["user_id"], request)
                    self.assertIsNone(session_mod.get_session(session["session_id"]))
                finally:
                    authz.set_current_principal(None)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(json.loads(response.body)["reauth_required"])
        self.assertIn("Max-Age=0", response.headers.get("set-cookie", ""))

    async def test_auth_totp_confirm_rejects_unpersisted_login_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            env = {
                "ARBOR_AUTH_DB": str(auth_db),
                "ARBOR_TOTP_SECRET_FILE": str(Path(tmpdir) / "totp.secret"),
            }
            with patch.dict(os.environ, env, clear=False):
                owner = local_auth.create_local_user("owner", "secret-password", role="owner")
                authz.set_current_principal({"backend": "local", "subject": owner["user_id"], "username": "owner", "role": "owner"})
                try:
                    request = FakeRequest({"code": "123456"})
                    query_one = AsyncMock(return_value={"enabled": True, "pending_enrollment": False, "secret_file": str(Path(tmpdir) / "totp.secret")})
                    with (
                        patch.object(web_main, "query_one", query_one),
                        patch.object(web_main, "env_file_value", return_value=""),
                    ):
                        response = await web_main.auth_totp_confirm(owner["user_id"], request)
                finally:
                    authz.set_current_principal(None)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.body)["error"], "failed to persist TOTP login mode to arbor.env")

    async def test_auth_totp_disable_requires_password_and_totp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            env = {
                "ARBOR_AUTH_DB": str(auth_db),
                "ARBOR_AUTH_MODE": "totp",
                "ARBOR_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
            }
            with patch.dict(os.environ, env, clear=False):
                owner = local_auth.create_local_user("owner", "secret-password", role="owner")
                session = session_mod.create_session(owner["user_id"], step_up_method="totp")
                authz.set_current_principal({"backend": "local", "subject": owner["user_id"], "username": "owner", "role": "owner"})
                try:
                    wrong_req = FakeRequest(
                        {"password": "wrong-password", "totp_code": approval_mode.totp_code("JBSWY3DPEHPK3PXP")},
                        cookies={session_mod.session_cookie_name(): session["session_id"]},
                    )
                    wrong_resp = await web_main.auth_totp_disable(owner["user_id"], wrong_req)
                    self.assertEqual(wrong_resp.status_code, 401)

                    ok_req = FakeRequest(
                        {"password": "secret-password", "totp_code": approval_mode.totp_code("JBSWY3DPEHPK3PXP")},
                        cookies={session_mod.session_cookie_name(): session["session_id"]},
                    )
                    query_one = AsyncMock(return_value={"enabled": False, "pending_enrollment": False})
                    with (
                        patch.object(web_main, "query_one", query_one),
                        patch.object(web_main, "env_file_value", return_value="cli"),
                    ):
                        ok_resp = await web_main.auth_totp_disable(owner["user_id"], ok_req)
                    self.assertIsNone(session_mod.get_session(session["session_id"]))
                finally:
                    authz.set_current_principal(None)

        self.assertEqual(ok_resp.status_code, 200)
        self.assertTrue(json.loads(ok_resp.body)["reauth_required"])
        self.assertIn("Max-Age=0", ok_resp.headers.get("set-cookie", ""))

    async def test_auth_totp_disable_rejects_unpersisted_login_mode_reset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_db = Path(tmpdir) / "auth.db"
            env = {
                "ARBOR_AUTH_DB": str(auth_db),
                "ARBOR_AUTH_MODE": "totp",
                "ARBOR_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
            }
            with patch.dict(os.environ, env, clear=False):
                owner = local_auth.create_local_user("owner", "secret-password", role="owner")
                authz.set_current_principal({"backend": "local", "subject": owner["user_id"], "username": "owner", "role": "owner"})
                try:
                    ok_req = FakeRequest(
                        {"password": "secret-password", "totp_code": approval_mode.totp_code("JBSWY3DPEHPK3PXP")},
                    )
                    query_one = AsyncMock(return_value={"enabled": False, "pending_enrollment": False})
                    with (
                        patch.object(web_main, "query_one", query_one),
                        patch.object(web_main, "env_file_value", return_value=""),
                    ):
                        response = await web_main.auth_totp_disable(owner["user_id"], ok_req)
                finally:
                    authz.set_current_principal(None)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(json.loads(response.body)["error"], "failed to persist login mode reset to arbor.env")


if __name__ == "__main__":
    unittest.main()
