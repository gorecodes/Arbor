"""
emerge_log.py — Parse /var/log/emerge.log to compute per-category compile times.

Runs entirely in the arbor web process (no root needed — emerge.log is 644).
Results are cached in memory and invalidated automatically when the file changes.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

EMERGE_LOG = Path("/var/log/emerge.log")

# Compiled once at import time for efficiency.
_RE_START = re.compile(r"^(\d+):\s+>>> emerge \(\d+ of \d+\) (\S+) to /")
_RE_END   = re.compile(r"^(\d+):\s+::: completed emerge \(\d+ of \d+\) (\S+) to /")

# Module-level cache: (mtime_at_last_read, result).
# Written only by _get_cached(); safe for single-process async use.
_cache: tuple[float, dict[str, int]] | None = None


def _parse_emerge_log(path: Path = EMERGE_LOG) -> dict[str, int]:
    """
    Read emerge.log and return {category: total_seconds}, sorted descending.

    Algorithm:
      - On '>>> emerge' lines: record start timestamp keyed by atom.
      - On '::: completed emerge' lines: pop the start, compute delta, add to category.
      - Incomplete entries (emerge was killed) are silently skipped via dict.pop default.
    """
    in_progress: dict[str, int] = {}  # atom -> start_timestamp
    totals: dict[str, int] = {}       # category -> accumulated seconds

    try:
        # buffering=65536 speeds up large files; errors="replace" skips bad bytes.
        with path.open("r", errors="replace", buffering=65536) as fh:
            for line in fh:
                m = _RE_START.match(line)
                if m:
                    ts, atom = int(m.group(1)), m.group(2)
                    in_progress[atom] = ts
                    continue

                m = _RE_END.match(line)
                if m:
                    ts, atom = int(m.group(1)), m.group(2)
                    start = in_progress.pop(atom, None)
                    if start is None:
                        continue
                    delta = ts - start
                    if delta <= 0:
                        continue
                    cat = atom.split("/")[0]
                    totals[cat] = totals.get(cat, 0) + delta

    except FileNotFoundError:
        pass
    except PermissionError:
        pass

    return dict(sorted(totals.items(), key=lambda kv: kv[1], reverse=True))


def _get_cached() -> dict[str, int]:
    """
    Return cached result if emerge.log hasn't changed since last read,
    otherwise re-parse and update the cache.
    """
    global _cache

    try:
        mtime = EMERGE_LOG.stat().st_mtime
    except (FileNotFoundError, PermissionError):
        return {}

    if _cache is not None and _cache[0] == mtime:
        return _cache[1]

    result = _parse_emerge_log()
    _cache = (mtime, result)
    return result


async def compile_time_by_category() -> dict[str, int]:
    """Async entry point — offloads the blocking file read to a thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_cached)
