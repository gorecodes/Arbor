import json
import unittest
from unittest.mock import patch

import arbor.main as web_main

from test_phase0_characterization import FakeWebSocket


class WebSocketAuthSurfaceTests(unittest.IsolatedAsyncioTestCase):
    async def _raise_timeout(self):
        raise TimeoutError

    async def test_ws_auth_accepts_valid_session(self):
        websocket = FakeWebSocket(
            [json.dumps({"type": "auth", "token": "test-token"})],
            headers={"origin": "https://localhost:8443"},
        )

        with patch.object(web_main, "resolve_ws_principal", return_value={"subject": "u1", "role": "owner"}):
            result = await web_main._ws_require_auth(websocket)

        self.assertTrue(result)
        self.assertTrue(websocket.accepted)
        self.assertFalse(websocket.closed)
        self.assertEqual(websocket.sent_texts, [])

    async def test_ws_auth_rejects_missing_session(self):
        websocket = FakeWebSocket([json.dumps({"type": "auth"})])

        with patch.object(web_main, "resolve_ws_principal", return_value=None):
            result = await web_main._ws_require_auth(websocket)

        self.assertFalse(result)
        self.assertEqual(websocket.close_code, 4401)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"error": "invalid or missing session", "done": True}],
        )

    async def test_ws_auth_rejects_malformed_json(self):
        websocket = FakeWebSocket(["{not-json"])

        result = await web_main._ws_require_auth(websocket)

        self.assertFalse(result)
        self.assertEqual(websocket.close_code, 4400)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"error": "invalid auth message", "done": True}],
        )

    async def test_ws_auth_times_out_without_first_frame(self):
        websocket = FakeWebSocket([])
        websocket.receive_text = self._raise_timeout
        result = await web_main._ws_require_auth(websocket)

        self.assertFalse(result)
        self.assertEqual(websocket.close_code, 4401)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"error": "authentication required", "done": True}],
        )

    async def test_ws_auth_rejects_unrecognized_origin_after_auth(self):
        websocket = FakeWebSocket(
            [json.dumps({"type": "auth", "token": "test-token"})],
            headers={"origin": "https://evil.invalid"},
        )

        with patch.object(web_main, "resolve_ws_principal", return_value={"subject": "u1", "role": "owner"}):
            result = await web_main._ws_require_auth(websocket)

        self.assertFalse(result)
        self.assertEqual(websocket.close_code, 4403)
        self.assertEqual(
            [json.loads(payload) for payload in websocket.sent_texts],
            [{"error": "origin not allowed", "done": True}],
        )

    async def test_ws_auth_allows_missing_origin_when_session_is_valid(self):
        websocket = FakeWebSocket([json.dumps({"type": "auth", "token": "test-token"})], headers={})

        with patch.object(web_main, "resolve_ws_principal", return_value={"subject": "u1", "role": "owner"}):
            result = await web_main._ws_require_auth(websocket)

        self.assertTrue(result)
        self.assertFalse(websocket.closed)

    async def test_ws_auth_allows_configured_origin_when_session_is_valid(self):
        websocket = FakeWebSocket(
            [json.dumps({"type": "auth", "token": "test-token"})],
            headers={"origin": "https://localhost:8443"},
        )

        with patch.object(web_main, "resolve_ws_principal", return_value={"subject": "u1", "role": "owner"}):
            result = await web_main._ws_require_auth(websocket)

        self.assertTrue(result)
        self.assertFalse(websocket.closed)

    async def test_ws_auth_allows_loopback_ip_origin_when_session_is_valid(self):
        websocket = FakeWebSocket(
            [json.dumps({"type": "auth", "token": "test-token"})],
            headers={"origin": "https://127.0.0.1:8443"},
        )

        with patch.object(web_main, "resolve_ws_principal", return_value={"subject": "u1", "role": "owner"}):
            result = await web_main._ws_require_auth(websocket)

        self.assertTrue(result)
        self.assertFalse(websocket.closed)


if __name__ == "__main__":
    unittest.main()
