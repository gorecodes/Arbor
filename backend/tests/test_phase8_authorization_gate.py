import unittest
from unittest.mock import AsyncMock, patch

import arbor.authorization as authz
import arbor.daemon_client as daemon_client


class AuthorizationPolicyTests(unittest.TestCase):
    def tearDown(self):
        authz.set_current_principal(None)

    def test_unknown_command_is_denied_by_default(self):
        with self.assertRaises(authz.AuthorizationError):
            authz.authorize_daemon_command("not_in_policy", {})

    def test_viewer_cannot_run_mutating_action(self):
        authz.set_current_principal({"backend": "local", "role": "viewer", "subject": "u1"})
        with self.assertRaises(authz.AuthorizationError):
            authz.authorize_daemon_command("emerge_install", {"atom": "sys-apps/portage"})

    def test_owner_can_run_mutating_action(self):
        authz.set_current_principal({"backend": "local", "role": "owner", "subject": "u1"})
        authz.authorize_daemon_command("emerge_install", {"atom": "sys-apps/portage"})


class DaemonClientAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        authz.set_current_principal(None)

    async def test_query_denies_before_opening_socket_for_unknown_command(self):
        mocked_open = AsyncMock()
        with patch.object(daemon_client.asyncio, "open_unix_connection", mocked_open):
            with self.assertRaises(authz.AuthorizationError):
                async for _ in daemon_client.query("not_in_policy", {}):
                    pass
        mocked_open.assert_not_awaited()

    async def test_query_denies_before_opening_socket_for_disallowed_role(self):
        authz.set_current_principal({"backend": "local", "role": "viewer", "subject": "u1"})
        mocked_open = AsyncMock()
        with patch.object(daemon_client.asyncio, "open_unix_connection", mocked_open):
            with self.assertRaises(authz.AuthorizationError):
                async for _ in daemon_client.query("emerge_install", {"atom": "sys-apps/portage"}):
                    pass
        mocked_open.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
