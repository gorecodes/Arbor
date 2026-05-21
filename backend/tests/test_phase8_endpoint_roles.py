import unittest
from unittest.mock import AsyncMock, patch

import arbor.main as web_main
from arbor.authorization import AuthorizationError, set_current_principal


class FakeRequest:
    def __init__(self, body):
        self._body = body

    async def body(self):
        import json

        if self._body is None:
            return b""
        return json.dumps(self._body).encode("utf-8")


class EndpointRoleEnforcementTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        set_current_principal(None)

    async def test_approval_request_create_denies_viewer(self):
        set_current_principal({"backend": "local", "role": "viewer", "subject": "u1"})
        req = FakeRequest({"cmd": "emerge_install", "args": {"atom": "sys-apps/portage"}})
        with self.assertRaises(AuthorizationError):
            await web_main.approval_request_create("u1", req)

    async def test_approval_request_create_allows_operator(self):
        set_current_principal({"backend": "local", "role": "operator", "subject": "u2"})
        req = FakeRequest({"cmd": "emerge_install", "args": {"atom": "sys-apps/portage"}})
        query_one = AsyncMock(return_value={"request_id": "req-1"})
        with patch.object(web_main, "query_one", query_one):
            payload = await web_main.approval_request_create("u2", req)
        self.assertEqual(payload["request_id"], "req-1")
        query_one.assert_awaited_once()

    async def test_history_purge_denies_operator(self):
        set_current_principal({"backend": "local", "role": "operator", "subject": "u2"})
        req = FakeRequest({"days": 7})
        with self.assertRaises(AuthorizationError):
            await web_main.history_purge("u2", req)


if __name__ == "__main__":
    unittest.main()
