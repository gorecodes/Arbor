"""
Client for communicating with the Arbor privilege daemon over Unix socket.
"""

import asyncio
import json
from typing import AsyncIterator

from .authorization import authorize_daemon_command
from .ipc_auth import sign_request

SOCKET_PATH = "/run/arbor/daemon.sock"

# Default asyncio StreamReader limit is 64 KiB — far too small for large
# emerge logs. Set to 64 MiB so long history entries don't cause read errors.
_READER_LIMIT = 64 * 1024 * 1024


async def query(cmd: str, args: dict = None) -> AsyncIterator[dict]:
    request_args = dict(args or {})
    authorize_daemon_command(cmd, request_args)
    reader, writer = await asyncio.open_unix_connection(SOCKET_PATH, limit=_READER_LIMIT)
    try:
        request = json.dumps(sign_request(cmd, request_args)) + "\n"
        writer.write(request.encode())  # nosemgrep: python.django.security.injection.request-data-write.request-data-write
        await writer.drain()

        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=120.0)
            if not line:
                break
            data = json.loads(line.decode())
            yield data
            if data.get("done") or data.get("error"):
                break
    finally:
        writer.close()
        await writer.wait_closed()


async def query_one(cmd: str, args: dict = None) -> dict:
    async for item in query(cmd, args):
        return item
    return {}


async def query_all(cmd: str, args: dict = None) -> list[dict]:
    results = []
    async for item in query(cmd, args):
        if item.get("error"):
            raise RuntimeError(item["error"])
        results.append(item)
    return results
