import asyncio
import unittest
from unittest.mock import patch

import daemon.main as daemon_main


class FakeStdout:
    def __init__(self, lines):
        self._lines = list(lines)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._lines:
            raise StopAsyncIteration
        return self._lines.pop(0)


class FakeProc:
    def __init__(self, lines, returncode=None, timeout_on_terminate=False):
        self.stdout = FakeStdout(lines)
        self.returncode = returncode
        self.timeout_on_terminate = timeout_on_terminate
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    async def wait(self):
        self.wait_calls += 1
        if self.timeout_on_terminate and self.terminated and not self.killed:
            raise asyncio.TimeoutError
        if self.returncode is None:
            self.returncode = -15 if self.terminated else 0
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.returncode = -9


class PretendCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_emerge_pretend_closing_generator_terminates_live_process(self):
        proc = FakeProc([b"line one\n", b"line two\n"])

        with patch.object(daemon_main, "_checked_atom", return_value="sys-apps/portage"):
            with patch("daemon.main.asyncio.create_subprocess_exec", return_value=proc):
                gen = daemon_main.cmd_emerge_pretend({"atom": "sys-apps/portage"})
                first = await gen.__anext__()
                await gen.aclose()

        self.assertEqual(first, {"line": "line one"})
        self.assertTrue(proc.terminated)
        self.assertFalse(proc.killed)

    async def test_emerge_uninstall_pretend_kills_process_after_terminate_timeout(self):
        proc = FakeProc([b"removing...\n", b"still running\n"], timeout_on_terminate=True)

        with patch.object(daemon_main, "_checked_atom", return_value="sys-apps/portage"):
            with patch("daemon.main.asyncio.create_subprocess_exec", return_value=proc):
                gen = daemon_main.cmd_emerge_uninstall_pretend({"atom": "sys-apps/portage"})
                first = await gen.__anext__()
                await gen.aclose()

        self.assertEqual(first, {"line": "removing..."})
        self.assertTrue(proc.terminated)
        self.assertTrue(proc.killed)

    async def test_emerge_autounmask_closing_generator_terminates_second_process(self):
        proc1 = FakeProc([b"masked by: ~amd64\n"], returncode=0)
        proc2 = FakeProc([b"autounmask suggestion\n", b"extra output\n"])
        created = [proc1, proc2]

        async def fake_create_subprocess_exec(*_args, **_kwargs):
            return created.pop(0)

        with patch.object(daemon_main, "_checked_atom", return_value="sys-apps/portage"):
            with patch("daemon.main.asyncio.create_subprocess_exec", side_effect=fake_create_subprocess_exec):
                gen = daemon_main.cmd_emerge_autounmask({"atom": "sys-apps/portage"})
                first = await gen.__anext__()
                second = await gen.__anext__()
                await gen.aclose()

        self.assertEqual(first, {"line": "-- scanning dependency tree for masked packages..."})
        self.assertEqual(second, {"line": "autounmask suggestion"})
        self.assertFalse(proc1.terminated)
        self.assertTrue(proc2.terminated)
        self.assertFalse(proc2.killed)

    async def test_emerge_pretend_success_shape_is_preserved(self):
        proc = FakeProc(
            [b"Calculating dependencies...\n", b"[ebuild N ] sys-apps/portage\n"],
            returncode=None,
        )

        with patch.object(daemon_main, "_checked_atom", return_value="sys-apps/portage"):
            with patch("daemon.main.asyncio.create_subprocess_exec", return_value=proc):
                chunks = []
                async for chunk in daemon_main.cmd_emerge_pretend(
                    {"atom": "sys-apps/portage", "clean": False, "opts": ""}
                ):
                    chunks.append(chunk)

        self.assertEqual(
            chunks,
            [
                {"line": "Calculating dependencies..."},
                {"line": "[ebuild N ] sys-apps/portage"},
                {"done": True, "returncode": 0, "needs_unmask": False},
            ],
        )


if __name__ == "__main__":
    unittest.main()
