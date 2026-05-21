import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import arbor.auth as auth_mod
import arbor.main as web_main
import arbor.server as server_mod


REPO_ROOT = Path(__file__).resolve().parents[2]


class FakeRequest:
    def __init__(self, body):
        self._body = body

    async def json(self):
        return self._body

    async def body(self):
        if self._body is None:
            return b""
        return json.dumps(self._body).encode("utf-8")


class FakeWebSocket:
    def __init__(self, incoming_messages, headers=None):
        self._incoming = list(incoming_messages)
        self.headers = headers or {}
        self.sent_texts = []
        self.accepted = False
        self.closed = False
        self.close_code = None
        self.close_reason = None

    async def accept(self):
        self.accepted = True

    async def receive_text(self):
        if not self._incoming:
            raise AssertionError("No more websocket input available")
        return self._incoming.pop(0)

    async def send_text(self, payload: str):
        self.sent_texts.append(payload)

    async def close(self, code: int | None = None, reason: str | None = None):
        self.closed = True
        self.close_code = code
        self.close_reason = reason


class InstallSurfaceCharacterizationTests(unittest.TestCase):
    def test_install_script_creates_usr_bin_symlinks(self):
        install_script = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/bin/arbor", install_script)
        self.assertIn("/usr/bin/arbor-daemon", install_script)
        self.assertIn("/usr/bin/arbor-approve", install_script)

    def test_setup_script_creates_log_directory_for_services(self):
        setup_script = (REPO_ROOT / "config" / "setup.sh").read_text(encoding="utf-8")
        self.assertIn('install -d -m 750 -o arbor -g arbor /var/log/arbor', setup_script)
        self.assertIn('install -d -m 750 -o arbor -g arbor /var/lib/arbor', setup_script)
        self.assertIn("ARBOR_AUTH_BACKEND", setup_script)
        self.assertIn("arbor-auth create-owner", setup_script)
        self.assertIn("chown arbor:arbor /var/lib/arbor/auth.db", setup_script)

    def test_install_script_and_service_files_share_the_same_entrypoint_paths(self):
        install_script = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
        service_files = [
            REPO_ROOT / "systemd" / "arbor.service",
            REPO_ROOT / "systemd" / "arbor-daemon.service",
            REPO_ROOT / "openrc" / "arbor",
            REPO_ROOT / "openrc" / "arbor-daemon",
        ]
        contents = [path.read_text(encoding="utf-8") for path in service_files]
        self.assertIn("/usr/bin/arbor", install_script)
        self.assertIn("/usr/bin/arbor-daemon", install_script)
        self.assertIn("/usr/bin/arbor-approve", install_script)
        self.assertTrue(any("/usr/bin/arbor" in content for content in contents))
        self.assertTrue(any("/usr/bin/arbor-daemon" in content for content in contents))

    def test_dev_sync_script_installs_arbor_approve_wrapper(self):
        sync_script = (REPO_ROOT / "sync_installed_dev.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/bin/arbor-approve", sync_script)
        self.assertIn("find /usr/lib/python-exec", sync_script)
        self.assertIn("ln -sf \"$arbor_link\" /usr/bin/arbor-approve", sync_script)
        self.assertIn("from arbor.approval_cli import main", sync_script)

    def test_dev_sync_script_installs_arbor_auth_wrapper(self):
        sync_script = (REPO_ROOT / "sync_installed_dev.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/bin/arbor-auth", sync_script)
        self.assertIn("ln -sf \"$arbor_link\" /usr/bin/arbor-auth", sync_script)
        self.assertIn("from arbor.local_auth_cli import main", sync_script)

    def test_local_auth_cli_exposes_user_role_management_commands(self):
        cli_py = (REPO_ROOT / "backend" / "arbor" / "local_auth_cli.py").read_text(encoding="utf-8")
        self.assertIn("create-user", cli_py)
        self.assertIn("list-users", cli_py)
        self.assertIn("set-role", cli_py)

    def test_frontend_login_supports_local_auth_form(self):
        index_html = (REPO_ROOT / "frontend" / "alpine" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Local auth only", index_html)
        self.assertIn('placeholder="Username"', index_html)
        self.assertIn('placeholder="Password"', index_html)
        self.assertNotIn('placeholder="Access token"', index_html)

    def test_frontend_contains_role_gating_for_sensitive_actions(self):
        index_html = (REPO_ROOT / "frontend" / "alpine" / "index.html").read_text(encoding="utf-8")
        app_js = (REPO_ROOT / "frontend" / "alpine" / "app.js").read_text(encoding="utf-8")
        self.assertIn("$store.auth.canOwner", index_html)
        self.assertIn("$store.auth.canOperate", index_html)
        self.assertIn("get canOwner()", app_js)
        self.assertIn("get canOperate()", app_js)
        self.assertIn("authRolePill()", app_js)
        self.assertIn("authRoleTooltip()", app_js)
        self.assertIn("Role: owner", app_js)


class AuthCharacterizationTests(unittest.IsolatedAsyncioTestCase):
    def test_auth_backend_is_local_only(self):
        self.assertEqual(auth_mod.auth_backend(), "local")

    async def test_require_auth_rejects_missing_session(self):
        with self.assertRaises(HTTPException) as ctx:
            request = SimpleNamespace(cookies={})
            await auth_mod.require_auth(request, None)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.detail, "Invalid or missing session")

    async def test_require_auth_accepts_valid_session_cookie(self):
        request = SimpleNamespace(cookies={"arbor_session": "sid-1"})
        with patch.object(auth_mod, "get_session", return_value={"user_id": "u1", "role": "owner", "username": "owner"}):
            self.assertEqual(await auth_mod.require_auth(request, None), "u1")


class ServerApprovalModeTests(unittest.TestCase):
    def test_none_mode_warns_at_startup(self):
        with patch("builtins.print") as printed:
            server_mod._report_approval_mode(server_mod.ApprovalMode.NONE)
        printed.assert_called_once()
        self.assertIn("ARBOR_APPROVAL_MODE=none", printed.call_args.args[0])

    def test_run_refuses_invalid_approval_mode(self):
        with (
            patch.object(server_mod, "load_ipc_key"),
            patch.object(server_mod.os.path, "exists", return_value=True),
            patch.object(server_mod, "validate_approval_mode_config", side_effect=server_mod.ApprovalModeError("bad mode")),
            patch.object(server_mod.uvicorn, "run"),
            patch("builtins.print"),
            patch.object(server_mod.sys, "exit", side_effect=SystemExit(2)),
        ):
            with self.assertRaises(SystemExit) as ctx:
                server_mod.run()
        self.assertEqual(ctx.exception.code, 2)


class ApiCharacterizationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        web_main.set_current_principal({"backend": "local", "subject": "u1", "username": "owner", "role": "owner"})

    async def asyncTearDown(self):
        web_main.set_current_principal(None)

    async def test_overlay_add_is_forbidden_when_feature_flag_is_disabled(self):
        request = FakeRequest({"name": "test", "sync_type": "git", "sync_uri": "https://example.invalid/repo.git"})
        with patch.object(web_main, "_overlay_add_enabled", return_value=False):
            response = await web_main.overlay_add("test-token", request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            json.loads(response.body),
            {"error": "overlay add is disabled; set ARBOR_ENABLE_OVERLAY_ADD=1 to enable it"},
        )

    async def test_overlay_remove_requires_explicit_confirmation(self):
        request = FakeRequest({})
        query_one = AsyncMock(return_value={"error": "overlay purge requires an explicit dangerous-action confirmation"})
        with patch.object(web_main, "query_one", query_one):
            response = await web_main.overlay_remove("test-token", "test-overlay", request, purge=1)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            json.loads(response.body),
            {"error": "overlay purge requires an explicit dangerous-action confirmation"},
        )
        query_one.assert_awaited_once_with(
            "overlay_remove",
            {
                "name": "test-overlay",
                "purge": True,
                "approve_danger": False,
                "approval_request_id": "",
                "approval_token": "",
                "request_principal": {
                    "subject": "u1",
                    "username": "owner",
                    "role": "owner",
                    "session_id": "",
                },
            },
        )

    async def test_history_purge_non_object_body_returns_400(self):
        response = await web_main.history_purge("test-token", FakeRequest(["not-a-dict"]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.body), {"error": "request body must be an object"})

    async def test_history_purge_invalid_days_returns_400(self):
        response = await web_main.history_purge("test-token", FakeRequest({"days": "not-an-int"}))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.body), {"error": "days must be an integer"})

    async def test_etc_update_resolve_non_object_body_returns_400(self):
        response = await web_main.etc_update_resolve("test-token", FakeRequest(["not-a-dict"]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.body), {"error": "request body must be an object"})

    async def test_package_info_returns_404_when_daemon_reports_not_found(self):
        with patch.object(web_main, "query_all", AsyncMock(side_effect=RuntimeError("not found"))):
            response = await web_main.package_info("test-token", "app-misc/hello")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.body), {"error": "not found"})


class WebSocketCharacterizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_ws_requires_auth_as_first_frame(self):
        websocket = FakeWebSocket([json.dumps({"type": "not-auth", "token": "test-token"})])

        with patch.object(web_main, "resolve_ws_principal", return_value={"subject": "u1", "role": "owner"}):
            result = await web_main._ws_require_auth(websocket)

        self.assertFalse(result)
        self.assertTrue(websocket.accepted)
        self.assertTrue(websocket.closed)
        self.assertEqual(websocket.close_code, 4401)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"error": "invalid or missing session", "done": True}],
        )

    async def test_ws_reports_missing_atom_after_successful_auth(self):
        websocket = FakeWebSocket([json.dumps({"type": "auth", "token": "test-token"})])

        with patch.object(web_main, "resolve_ws_principal", return_value={"subject": "u1", "role": "owner"}):
            await web_main._ws_emerge(websocket, "emerge_pretend", "", {"clean": False, "opts": ""})

        self.assertTrue(websocket.closed)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"error": "missing atom", "done": True}],
        )

    async def test_ws_emerge_pretend_stream_shape_is_preserved(self):
        calls = []
        websocket = FakeWebSocket([json.dumps({"type": "auth", "token": "test-token"})])

        async def fake_query(cmd, args=None):
            calls.append((cmd, args))
            yield {"line": "Calculating dependencies..."}
            yield {"done": True}

        with patch.object(web_main, "resolve_ws_principal", return_value={"subject": "u1", "role": "owner"}):
            with patch.object(web_main, "query", fake_query):
                await web_main._ws_emerge(websocket, "emerge_pretend", "sys-apps/portage", {"clean": False, "opts": ""})

        self.assertEqual(
            calls,
            [
                (
                    "emerge_pretend",
                    {
                        "atom": "sys-apps/portage",
                        "clean": False,
                        "opts": "",
                        "request_principal": {
                            "subject": "u1",
                            "username": "",
                            "role": "owner",
                            "session_id": "",
                        },
                    },
                )
            ],
        )
        self.assertTrue(websocket.closed)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"line": "Calculating dependencies..."}, {"done": True}],
        )


if __name__ == "__main__":
    unittest.main()
