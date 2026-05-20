import unittest
from unittest.mock import AsyncMock, patch

import arbor.main as web_main
import daemon.main as daemon_main

from test_phase0_characterization import FakeRequest


class OverlayRemoveDaemonTests(unittest.IsolatedAsyncioTestCase):
    async def test_overlay_remove_requires_confirmation(self):
        chunks = [chunk async for chunk in daemon_main.cmd_overlay_remove({"name": "foo", "purge": False})]
        self.assertEqual(
            chunks,
            [{"error": "overlay remove requires an explicit dangerous-action confirmation"}],
        )

    async def test_overlay_purge_requires_matching_confirmation_text(self):
        chunks = [
            chunk async for chunk in daemon_main.cmd_overlay_remove(
                {"name": "foo", "purge": True, "approve_danger": True, "approval_text": "REMOVE foo"}
            )
        ]
        self.assertEqual(
            chunks,
            [{"error": "overlay purge confirmation text does not match the requested repository"}],
        )

    async def test_overlay_remove_accepts_matching_confirmation_text(self):
        with patch.object(daemon_main, "in_thread", AsyncMock(return_value={"ok": True})) as in_thread:
            chunks = [
                chunk async for chunk in daemon_main.cmd_overlay_remove(
                    {"name": "foo", "purge": False, "approve_danger": True, "approval_text": "REMOVE foo"}
                )
            ]

        self.assertEqual(chunks, [{"ok": True}, {"done": True}])
        in_thread.assert_awaited_once_with(daemon_main._overlay_remove, "foo", False)

    async def test_overlay_purge_accepts_matching_confirmation_text(self):
        with patch.object(daemon_main, "in_thread", AsyncMock(return_value={"ok": True})) as in_thread:
            chunks = [
                chunk async for chunk in daemon_main.cmd_overlay_remove(
                    {"name": "foo", "purge": True, "approve_danger": True, "approval_text": "PURGE foo"}
                )
            ]

        self.assertEqual(chunks, [{"ok": True}, {"done": True}])
        in_thread.assert_awaited_once_with(daemon_main._overlay_remove, "foo", True)


class OverlayRemoveWebTests(unittest.IsolatedAsyncioTestCase):
    async def test_overlay_remove_forwards_confirmation_fields(self):
        request = FakeRequest({"approve_danger": True, "approval_text": "PURGE foo"})
        query_one = AsyncMock(return_value={"ok": True})

        with patch.object(web_main, "query_one", query_one):
            response = await web_main.overlay_remove("test-token", "foo", request, purge=1)

        self.assertEqual(response, {"ok": True})
        query_one.assert_awaited_once_with(
            "overlay_remove",
            {
                "name": "foo",
                "purge": True,
                "approve_danger": True,
                "approval_text": "PURGE foo",
            },
        )

    async def test_overlay_remove_rejects_non_object_body(self):
        request = FakeRequest(["not-a-dict"])
        response = await web_main.overlay_remove("test-token", "foo", request, purge=0)
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
