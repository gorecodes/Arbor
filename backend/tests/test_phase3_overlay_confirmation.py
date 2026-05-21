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

    async def test_overlay_add_accepts_danger_ack_without_exact_text(self):
        async def fake_in_thread(fn, *args):
            if fn is daemon_main._require_approval:
                return None
            if fn is daemon_main._overlay_add:
                return {"ok": True}
            raise AssertionError(f"unexpected call: {fn}")

        with (
            patch.object(daemon_main, "_overlay_add_enabled", return_value=True),
            patch.object(daemon_main, "in_thread", AsyncMock(side_effect=fake_in_thread)) as in_thread,
        ):
            chunks = [
                chunk async for chunk in daemon_main.cmd_overlay_add(
                    {
                        "name": "foo",
                        "sync_type": "git",
                        "sync_uri": "https://example.invalid/repo.git",
                        "approve_danger": True,
                        "approval_request_id": "req-1",
                    }
                )
            ]

        self.assertEqual(
            chunks,
            [{"ok": True, "warning": "Overlay added. Review it carefully, then run sync explicitly."}, {"done": True}],
        )
        self.assertEqual(in_thread.await_count, 2)

    async def test_overlay_remove_accepts_confirmation_without_exact_text(self):
        async def fake_in_thread(fn, *args):
            if fn is daemon_main._require_approval:
                return None
            if fn is daemon_main._overlay_remove:
                return {"ok": True}
            raise AssertionError(f"unexpected call: {fn}")

        with patch.object(daemon_main, "in_thread", AsyncMock(side_effect=fake_in_thread)) as in_thread:
            chunks = [
                chunk async for chunk in daemon_main.cmd_overlay_remove(
                    {
                        "name": "foo",
                        "purge": False,
                        "approve_danger": True,
                        "approval_request_id": "req-1",
                        "approval_token": "tok-1",
                    }
                )
            ]

        self.assertEqual(chunks, [{"ok": True}, {"done": True}])
        self.assertEqual(in_thread.await_count, 2)

    async def test_overlay_purge_accepts_confirmation_without_exact_text(self):
        async def fake_in_thread(fn, *args):
            if fn is daemon_main._require_approval:
                return None
            if fn is daemon_main._overlay_remove:
                return {"ok": True}
            raise AssertionError(f"unexpected call: {fn}")

        with patch.object(daemon_main, "in_thread", AsyncMock(side_effect=fake_in_thread)) as in_thread:
            chunks = [
                chunk async for chunk in daemon_main.cmd_overlay_remove(
                    {
                        "name": "foo",
                        "purge": True,
                        "approve_danger": True,
                        "approval_request_id": "req-1",
                        "approval_token": "tok-1",
                    }
                )
            ]

        self.assertEqual(chunks, [{"ok": True}, {"done": True}])
        self.assertEqual(in_thread.await_count, 2)


class OverlayRemoveWebTests(unittest.IsolatedAsyncioTestCase):
    async def test_overlay_remove_forwards_confirmation_fields(self):
        request = FakeRequest({"approve_danger": True})
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
                "approval_request_id": "",
                "approval_token": "",
            },
        )

    async def test_overlay_remove_rejects_non_object_body(self):
        request = FakeRequest(["not-a-dict"])
        response = await web_main.overlay_remove("test-token", "foo", request, purge=0)
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
