"""
emerge_log.py — Parse /var/log/emerge.log to compute per-category compile times
and per-CP ETA estimates.

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

# Module-level caches: (mtime_at_last_read, result).
# Written only by their respective _get_*_cached(); safe for single-process async use.
_cache: tuple[float, dict[str, int]] | None = None
_cp_cache: tuple[float, dict[str, list[int]]] | None = None

# Keep at most this many build times per CP (most recent wins).
_CP_MAX_SAMPLES = 5


def _atom_to_cp(atom: str) -> str:
    """Strip version from cat/pkg-ver → cat/pkg using portage, with regex fallback."""
    try:
        from portage.versions import cpv_getkey
        cp = cpv_getkey(atom)
        if cp:
            return cp
    except Exception:
        pass
    m = re.match(r'^([a-zA-Z0-9+_][a-zA-Z0-9+_./-]*/[a-zA-Z0-9+_][a-zA-Z0-9+_.-]*)', atom)
    return m.group(1) if m else atom


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


def _parse_emerge_log_per_cp(path: Path = EMERGE_LOG) -> dict[str, list[int]]:
    """Read emerge.log and return {cp: [last N build times in seconds]}."""
    in_progress: dict[str, int] = {}
    cp_times: dict[str, list[int]] = {}

    try:
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
                    cp = _atom_to_cp(atom)
                    times = cp_times.setdefault(cp, [])
                    times.append(delta)
                    if len(times) > _CP_MAX_SAMPLES:
                        times.pop(0)

    except (FileNotFoundError, PermissionError):
        pass

    return cp_times


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


def _get_cp_cached() -> dict[str, list[int]]:
    global _cp_cache

    try:
        mtime = EMERGE_LOG.stat().st_mtime
    except (FileNotFoundError, PermissionError):
        return {}

    if _cp_cache is not None and _cp_cache[0] == mtime:
        return _cp_cache[1]

    result = _parse_emerge_log_per_cp()
    _cp_cache = (mtime, result)
    return result


def estimate_eta(atoms: list[str]) -> dict:
    """
    Given a list of CPV atoms (e.g. from a pretend output), return an ETA estimate.

    Confidence levels (per item):
      "exact"    — this CP has been built before on this machine
      "category" — CP unknown, using category average
      "global"   — category also unknown, using global average
      "unknown"  — no history at all (fresh system)
    """
    cp_times = _get_cp_cached()

    # Category averages as first fallback.
    cat_sum: dict[str, float] = {}
    cat_count: dict[str, int] = {}
    for cp, times in cp_times.items():
        cat = cp.split("/")[0]
        avg = sum(times) / len(times)
        cat_sum[cat] = cat_sum.get(cat, 0.0) + avg
        cat_count[cat] = cat_count.get(cat, 0) + 1
    cat_avgs: dict[str, float] = {
        cat: cat_sum[cat] / cat_count[cat] for cat in cat_sum
    }

    # Global average as second fallback.
    all_times = [t for times in cp_times.values() for t in times]
    global_avg = sum(all_times) / len(all_times) if all_times else 0.0

    items = []
    total = 0
    rough = False

    for atom in atoms:
        cp = _atom_to_cp(atom)
        cat = cp.split("/")[0]

        if cp in cp_times:
            times = cp_times[cp]
            secs = round(sum(times) / len(times))
            confidence = "exact"
        elif cat in cat_avgs:
            secs = round(cat_avgs[cat])
            confidence = "category"
            rough = True
        elif global_avg:
            secs = round(global_avg)
            confidence = "global"
            rough = True
        else:
            secs = 0
            confidence = "unknown"
            rough = True

        total += secs
        items.append({"cp": cp, "seconds": secs, "confidence": confidence})

    return {"total_seconds": total, "rough": rough, "items": items}


async def compile_time_by_category() -> dict[str, int]:
    """Async entry point — offloads the blocking file read to a thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_cached)


async def compile_time_estimate(atoms: list[str]) -> dict:
    """Async entry point for ETA estimation."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, estimate_eta, atoms)
