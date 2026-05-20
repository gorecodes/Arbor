import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

import arbor.auth as auth_mod
import arbor.main as web_main


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
        self.assertTrue(any("/usr/bin/arbor" in content for content in contents))
        self.assertTrue(any("/usr/bin/arbor-daemon" in content for content in contents))


class AuthCharacterizationTests(unittest.TestCase):
    def test_verify_token_rejects_empty_candidate(self):
        self.assertFalse(auth_mod.verify_token(None))
        self.assertFalse(auth_mod.verify_token(""))

    def test_require_auth_rejects_missing_credentials(self):
        with self.assertRaises(HTTPException) as ctx:
            auth_mod.require_auth(None)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.detail, "Invalid or missing token")

    def test_require_auth_accepts_matching_bearer_token(self):
        credentials = SimpleNamespace(credentials="test-token")
        with patch.object(auth_mod, "verify_token", return_value=True):
            self.assertEqual(auth_mod.require_auth(credentials), "test-token")


class ApiCharacterizationTests(unittest.IsolatedAsyncioTestCase):
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
                "approval_text": "",
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


class WebSocketCharacterizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_ws_requires_auth_as_first_frame(self):
        websocket = FakeWebSocket([json.dumps({"type": "not-auth", "token": "test-token"})])

        with patch.object(web_main, "verify_token", side_effect=lambda token: token == "test-token"):
            result = await web_main._ws_require_auth(websocket)

        self.assertFalse(result)
        self.assertTrue(websocket.accepted)
        self.assertTrue(websocket.closed)
        self.assertEqual(websocket.close_code, 4401)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"error": "invalid or missing token", "done": True}],
        )

    async def test_ws_reports_missing_atom_after_successful_auth(self):
        websocket = FakeWebSocket([json.dumps({"type": "auth", "token": "test-token"})])

        with patch.object(web_main, "verify_token", side_effect=lambda token: token == "test-token"):
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

        with patch.object(web_main, "verify_token", side_effect=lambda token: token == "test-token"):
            with patch.object(web_main, "query", fake_query):
                await web_main._ws_emerge(websocket, "emerge_pretend", "sys-apps/portage", {"clean": False, "opts": ""})

        self.assertEqual(calls, [("emerge_pretend", {"atom": "sys-apps/portage", "clean": False, "opts": ""})])
        self.assertTrue(websocket.closed)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"line": "Calculating dependencies..."}, {"done": True}],
        )


if __name__ == "__main__":
    unittest.main()
