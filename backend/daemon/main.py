"""
Arbor privilege daemon — runs as root, listens on a Unix socket.
All portage calls run in a thread executor to avoid event loop conflicts.
"""

import asyncio
import json
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

SOCKET_PATH = "/run/arbor/daemon.sock"
ALLOWED_COMMANDS = {
    "world_updates",
    "installed_packages",
    "pkg_stats",
    "package_info",
    "package_search",
    "system_status",
    "use_flags",
    "global_use_flags_audit",
    "use_flag_origins",
    "package_deps",
    "dep_graph",
    "emerge_pretend",
    "emerge_install",
    "emerge_autounmask",
    "emerge_uninstall_pretend",
    "emerge_uninstall",
    "emerge_world_update",
    "emerge_depclean_pretend",
    "emerge_depclean",
    "emerge_preserved_rebuild",
    "emerge_sync",
    "etc_update_check",
    "etc_update_resolve",
    "job_attach",
    "job_status",
    "job_cancel",
    "job_list",
    "history_list",
    "history_log",
    "history_delete",
    "history_purge",
    "history_stats",
    "overlay_list",
    "overlay_add",
    "overlay_remove",
    "overlay_sync",
}

# ---------------------------------------------------------------------------
# Job registry — tracks long-running emerge processes across connections
# ---------------------------------------------------------------------------

class _Job:
    def __init__(self, atom: str, proc, kind: str = "install"):
        self.atom = atom
        self.kind = kind
        self.proc = proc
        self.logs: list = []
        self.status: str = "running"   # running | done | failed
        self.returncode = None
        self.created_at: float = time.time()
        self._queues: list = []

    def _push(self, chunk: dict):
        self.logs.append(chunk)
        for q in self._queues:
            q.put_nowait(chunk)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._queues.append(q)
        for chunk in list(self.logs):
            q.put_nowait(chunk)
        if self.status != "running":
            q.put_nowait(None)  # sentinel so reader always terminates
        return q

    def unsubscribe(self, q: asyncio.Queue):
        try:
            self._queues.remove(q)
        except ValueError:
            pass


_jobs: dict[str, _Job] = {}
# Serializes the check-then-spawn dance in job creation so two concurrent
# clients clicking "install <atom>" can't both decide "no running job" and
# spawn duplicate emerge processes.
_jobs_lock: asyncio.Lock | None = None

# ---------------------------------------------------------------------------
# Portage reload — detect repos.conf changes and reinitialize portage.db
# ---------------------------------------------------------------------------

_REPOS_CONF_PATHS = [Path("/etc/portage/repos.conf"), Path("/etc/portage/repos.conf.d")]
_repos_conf_mtime: float = 0.0
_portage_reload_lock = threading.Lock()


def _repos_conf_mtime_now() -> float:
    """Return the latest mtime across all repos.conf files/dirs."""
    t = 0.0
    for p in _REPOS_CONF_PATHS:
        try:
            if p.is_dir():
                t = max(t, p.stat().st_mtime, *(f.stat().st_mtime for f in p.iterdir()))
            elif p.exists():
                t = max(t, p.stat().st_mtime)
        except OSError:
            pass
    return t


def _maybe_reload_portage():
    """Reload portage module if repos.conf has changed since last load."""
    global _repos_conf_mtime
    current = _repos_conf_mtime_now()
    if current <= _repos_conf_mtime:
        return
    with _portage_reload_lock:
        if current <= _repos_conf_mtime:
            return
        import importlib, sys
        for key in [k for k in sys.modules if k == "portage" or k.startswith("portage.")]:
            del sys.modules[key]
        import portage  # noqa: F401  — re-populates sys.modules
        _repos_conf_mtime = _repos_conf_mtime_now()
        log.info("portage reloaded (repos.conf changed)")

# ---------------------------------------------------------------------------
# SQLite history store
# ---------------------------------------------------------------------------

_DB_PATH = "/var/lib/arbor/history.db"
_db_lock = threading.Lock()


def _db_init():
    Path(_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with _db_lock:
        with sqlite3.connect(_DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS job_history (
                    job_id TEXT PRIMARY KEY,
                    atom TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    returncode INTEGER,
                    created_at REAL NOT NULL,
                    finished_at REAL,
                    log TEXT
                )
            """)


def _history_save(job_id: str, atom: str, kind: str, status: str, returncode, created_at: float, finished_at: float, log_text: str):
    with _db_lock:
        with sqlite3.connect(_DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO job_history "
                "(job_id, atom, kind, status, returncode, created_at, finished_at, log) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (job_id, atom, kind, status, returncode, created_at, finished_at, log_text),
            )


def _history_list(limit: int, offset: int, kind: str) -> dict:
    with _db_lock:
        with sqlite3.connect(_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            if kind:
                total = conn.execute("SELECT COUNT(*) FROM job_history WHERE kind=?", (kind,)).fetchone()[0]
                rows = conn.execute(
                    "SELECT job_id, atom, kind, status, returncode, created_at, finished_at "
                    "FROM job_history WHERE kind=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (kind, limit, offset),
                ).fetchall()
            else:
                total = conn.execute("SELECT COUNT(*) FROM job_history").fetchone()[0]
                rows = conn.execute(
                    "SELECT job_id, atom, kind, status, returncode, created_at, finished_at "
                    "FROM job_history ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return {"items": [dict(r) for r in rows], "total": total}


def _history_log(job_id: str) -> dict:
    with _db_lock:
        with sqlite3.connect(_DB_PATH) as conn:
            row = conn.execute("SELECT log FROM job_history WHERE job_id=?", (job_id,)).fetchone()
            if row is None:
                return {"error": "not found"}
            return {"log": row[0] or ""}


def _history_delete(job_id: str) -> dict:
    with _db_lock:
        with sqlite3.connect(_DB_PATH) as conn:
            deleted = conn.execute("DELETE FROM job_history WHERE job_id=?", (job_id,)).rowcount
            if deleted == 0:
                return {"error": "not found"}
            return {"ok": True}


def _history_purge(days: int) -> dict:
    cutoff = time.time() - days * 86400
    with _db_lock:
        with sqlite3.connect(_DB_PATH) as conn:
            deleted = conn.execute("DELETE FROM job_history WHERE created_at < ?", (cutoff,)).rowcount
            return {"deleted": deleted}


def _history_stats() -> dict:
    cutoff_30d = time.time() - 30 * 86400
    with _db_lock:
        with sqlite3.connect(_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            rows = conn.execute(
                "SELECT date(created_at, 'unixepoch') as day, COUNT(*) as cnt "
                "FROM job_history WHERE created_at >= ? GROUP BY day ORDER BY day",
                (cutoff_30d,),
            ).fetchall()
            activity_30d = [{"day": r["day"], "cnt": r["cnt"]} for r in rows]

            rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM job_history GROUP BY status"
            ).fetchall()
            status_counts = {r["status"]: r["cnt"] for r in rows}

            rows = conn.execute(
                "SELECT kind, COUNT(*) as cnt FROM job_history GROUP BY kind ORDER BY cnt DESC"
            ).fetchall()
            kind_counts = [{"kind": r["kind"], "cnt": r["cnt"]} for r in rows]

            rows = conn.execute(
                "SELECT atom, (finished_at - created_at) as duration "
                "FROM job_history "
                "WHERE finished_at IS NOT NULL AND status = 'done' AND duration > 0 "
                "ORDER BY duration DESC LIMIT 10"
            ).fetchall()
            top_slow = [{"atom": r["atom"], "duration": r["duration"]} for r in rows]

            total = conn.execute("SELECT COUNT(*) FROM job_history").fetchone()[0]

            cutoff_90d = time.time() - 90 * 86400
            rows = conn.execute(
                "SELECT date(created_at, 'unixepoch') as day, "
                "SUM(finished_at - created_at) as total_secs "
                "FROM job_history WHERE created_at >= ? AND status='done' "
                "AND finished_at IS NOT NULL GROUP BY day ORDER BY day",
                (cutoff_90d,),
            ).fetchall()
            compile_by_day = [{"day": r["day"], "secs": r["total_secs"]} for r in rows]

            return {
                "activity_30d": activity_30d,
                "status_counts": status_counts,
                "kind_counts": kind_counts,
                "top_slow": top_slow,
                "compile_by_day": compile_by_day,
                "total": total,
            }


def _get_jobs_lock() -> asyncio.Lock:
    global _jobs_lock
    if _jobs_lock is None:
        _jobs_lock = asyncio.Lock()
    return _jobs_lock

_ANSI = re.compile(r'\x1b\[[0-9;]*[mKJH]|\x1b\].*?(?:\x07|\x1b\\)')

# Strict atom format. We use this only as a syntactic guard before any
# subprocess call or file write. We deliberately keep it more permissive than
# portage.dep.Atom (which we also try below) so that bare CPVs like
# "cat/pkg-1.0" are accepted.
_ATOM_RE = re.compile(
    r'^[<>=~!]?=?[a-z0-9][a-z0-9+._-]*/[a-zA-Z0-9+._-]+'
    r'(?::[\w.+/-]+)?(?:\[[\w,!?=+\-*]+\])?$'
)

# Valid keyword forms for /etc/portage/package.accept_keywords entries.
_KEYWORD_RE = re.compile(r'^(\*\*|~?\*|~?[a-z0-9][a-z0-9_-]*)$')


def _valid_atom(atom: str) -> bool:
    if not atom or len(atom) > 256:
        return False
    if any(c in atom for c in ('\n', '\r', '\t', ' ', '\x00')):
        return False
    if not _ATOM_RE.match(atom):
        return False
    # Best-effort cross-check with portage's own parser.
    try:
        from portage.dep import Atom
        Atom(atom, allow_wildcard=False, allow_repo=False)
        return True
    except Exception:
        try:
            from portage.versions import cpv_getkey
            return cpv_getkey(atom) is not None
        except Exception:
            return False


def _valid_keyword(kw: str) -> bool:
    if not kw or len(kw) > 32:
        return False
    return bool(_KEYWORD_RE.match(kw))


def _normalize_atom(atom: str) -> str:
    """Add = prefix to bare CPVs (e.g. cat/pkg-1.0 → =cat/pkg-1.0)."""
    if not atom or atom.startswith(("=", "<", ">", "~", "!")):
        return atom
    try:
        from portage.versions import cpv_getkey
        cp = cpv_getkey(atom)
        if cp and cp != atom:
            return "=" + atom
    except Exception:
        pass
    return atom


def _checked_atom(raw: str) -> str | None:
    """Normalize and validate an atom from a client. Return None if invalid."""
    atom = _normalize_atom(raw)
    return atom if _valid_atom(atom) else None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [arbor-daemon] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4)


async def in_thread(fn, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, fn, *args)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=10.0)
        request = json.loads(raw.decode())
        cmd = request.get("cmd")

        if cmd not in ALLOWED_COMMANDS:
            await send(writer, {"error": f"command '{cmd}' not allowed"})
            return

        log.info("cmd=%s args=%s", cmd, request.get("args", {}))
        handler = HANDLERS.get(cmd)
        async for chunk in handler(request.get("args", {})):
            await send(writer, chunk)

    except asyncio.TimeoutError:
        await send(writer, {"error": "timeout"})
    except json.JSONDecodeError:
        await send(writer, {"error": "invalid json"})
    except Exception as e:
        log.exception("unhandled error")
        await send(writer, {"error": str(e)})
    finally:
        writer.close()
        await writer.wait_closed()


async def send(writer: asyncio.StreamWriter, data: dict):
    writer.write(json.dumps(data).encode() + b"\n")
    await writer.drain()


# ---------------------------------------------------------------------------
# Sync helpers — run inside thread executor, no asyncio calls allowed
# ---------------------------------------------------------------------------

def _system_status():
    import shutil
    import portage
    db = portage.db[portage.root]["vartree"].dbapi
    pkg_count = len(db.cpv_all())
    disk = shutil.disk_usage("/")
    try:
        last_sync = Path("/var/db/repos/gentoo/metadata/timestamp.chk").read_text().strip()
    except FileNotFoundError:
        last_sync = "unknown"

    # RAM from /proc/meminfo (no external deps)
    mem_total = mem_available = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1]) * 1024
    except OSError:
        pass
    mem_used = mem_total - mem_available

    # CPU load (stdlib os.getloadavg — no psutil needed)
    try:
        load1, load5, load15 = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        cpu_pct = round(min(100.0, (load1 / cpu_count) * 100), 1)
    except OSError:
        load1 = load5 = load15 = 0.0
        cpu_count = 1
        cpu_pct = 0.0

    return [{
        "pkg_count":    pkg_count,
        "disk_total":   disk.total,
        "disk_used":    disk.used,
        "disk_free":    disk.free,
        "mem_total":    mem_total,
        "mem_used":     mem_used,
        "mem_available": mem_available,
        "cpu_pct":      cpu_pct,
        "cpu_load1":    round(load1, 2),
        "cpu_count":    cpu_count,
        "last_sync":    last_sync,
    }]


def _installed_packages(search: str):
    import portage
    db = portage.db[portage.root]["vartree"].dbapi
    results = []
    for cpv in sorted(db.cpv_all()):
        if search and search not in cpv.lower():
            continue
        cat, pf = cpv.split("/", 1)
        slot, build_time = db.aux_get(cpv, ["SLOT", "BUILD_TIME"])
        results.append({"cpv": cpv, "cat": cat, "pf": pf, "slot": slot, "build_time": build_time})
    return results


def _pkg_stats():
    import portage
    import subprocess
    from collections import Counter
    from portage.versions import cpv_getversion, cpv_getkey
    _maybe_reload_portage()
    db = portage.db[portage.root]["vartree"].dbapi
    arch = portage.settings.get("ARCH", "amd64")

    use_counter: Counter = Counter()
    kw_dist = {"stable": 0, "testing": 0, "live": 0, "unknown": 0}
    src_vs_bin = {"source": 0, "binary": 0}
    license_counter: Counter = Counter()
    cp_count: dict = {}

    def _cat_license(lic: str) -> str:
        u = lic.upper()
        PROPRIETARY = ("NVIDIA", "INTEL-", "AMD-GPU", "STEAM", "SKYPE",
                       "ELASTIC", "SSPL", "BUSL", "COMMERCIAL", "NO-SOURCE",
                       "GOOGLE-", "MICROSOFT-")
        COPYLEFT    = ("GPL-", "LGPL-", "AGPL-", "MPL-", "CDDL",
                       "CC-BY-SA", "EUPL", "EUPL-")
        PERMISSIVE  = ("MIT", "APACHE-", "BSD", "ISC", "BOOST", "ZLIB",
                       "CC0-", "PUBLIC-DOMAIN", "ARTISTIC", "PSF-",
                       "UNLICENSE", "WTFPL", "OPENSSL")
        if any(x in u for x in PROPRIETARY):  return "proprietary"
        if any(x in u for x in COPYLEFT):     return "copyleft"
        if any(x in u for x in PERMISSIVE):   return "permissive"
        return "other"

    for cpv in db.cpv_all():
        try:
            cp = cpv_getkey(cpv)
            if cp:
                cp_count[cp] = cp_count.get(cp, 0) + 1
            use_str, keywords_str, build_id, license_str = db.aux_get(
                cpv, ["USE", "KEYWORDS", "BUILD_ID", "LICENSE"]
            )
            for flag in use_str.split():
                if flag and not flag.startswith("-"):
                    use_counter[flag] += 1
            try:
                ver = cpv_getversion(cpv) or ""
            except Exception:
                ver = ""
            if ver == "9999" or ver.endswith("-9999"):
                kw_dist["live"] += 1
            elif arch in keywords_str.split():
                kw_dist["stable"] += 1
            elif ("~" + arch) in keywords_str.split():
                kw_dist["testing"] += 1
            else:
                kw_dist["unknown"] += 1
            if build_id and build_id.strip():
                src_vs_bin["binary"] += 1
            else:
                src_vs_bin["source"] += 1
            license_counter[_cat_license(license_str)] += 1
        except Exception:
            pass

    slotted = sorted(
        [{"cp": cp, "count": c} for cp, c in cp_count.items() if c > 1],
        key=lambda x: x["count"], reverse=True
    )[:20]

    def _du(path: str) -> int:
        try:
            r = subprocess.run(
                ["du", "-sb", path],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                return int(r.stdout.split()[0])
        except Exception:
            pass
        return 0

    portage_disk = {
        "repos":     _du("/var/db/repos"),
        "distfiles": _du("/var/cache/distfiles"),
        "binpkgs":   _du("/var/cache/binpkgs"),
        "vartree":   _du("/var/db/pkg"),
    }

    return {
        "top_use_flags": [{"flag": k, "cnt": v} for k, v in use_counter.most_common(20)],
        "keyword_dist":  kw_dist,
        "portage_disk":  portage_disk,
        "slotted":       slotted,
        "src_vs_bin":    src_vs_bin,
        "license_dist":  dict(license_counter),
        "total":         sum(kw_dist.values()),
    }


def _package_info(atom: str):
    _maybe_reload_portage()
    import portage
    from portage.versions import cpv_getkey

    vdb = portage.db[portage.root]["vartree"].dbapi
    porttree = portage.db[portage.root]["porttree"].dbapi
    fields = ["DESCRIPTION", "HOMEPAGE", "LICENSE", "SLOT", "USE", "IUSE",
              "DEPEND", "RDEPEND", "BUILD_TIME", "SIZE"]

    try:
        cp = cpv_getkey(atom)
    except Exception:
        cp = None
    cp = cp or atom
    # Prepend = only for CPVs (atom has a version: cpv_getkey returns a different string)
    is_cpv = cp != atom and not atom.startswith(("=", "<", ">", "~"))
    exact = ("=" + atom) if is_cpv else atom

    installed = vdb.match(exact) or vdb.match(atom)
    if installed:
        results = []
        for cpv in installed:
            values = vdb.aux_get(cpv, fields)
            results.append({"cpv": cpv, **dict(zip(fields, values)), "installed": True})
        return results

    # Not installed — look in porttree by CP then filter to requested CPV
    versions = porttree.cp_list(cp)
    if not versions:
        return [{"error": "not found"}]
    # Pick the exact CPV if present, otherwise the latest
    cpv = atom if atom in versions else versions[-1]
    try:
        values = porttree.aux_get(cpv, fields)
        return [{"cpv": cpv, **dict(zip(fields, values)), "installed": False}]
    except Exception:
        return [{"error": "not found"}]


def _package_search(query: str):
    _maybe_reload_portage()
    import portage
    porttree = portage.db[portage.root]["porttree"].dbapi
    vartree  = portage.db[portage.root]["vartree"].dbapi

    all_cps = porttree.cp_all()
    matches = [cp for cp in all_cps if query.lower() in cp.lower()][:50]

    results = []
    for cp in matches:
        versions = porttree.cp_list(cp)
        best = versions[-1] if versions else None
        desc = ""
        if best:
            try:
                desc = porttree.aux_get(best, ["DESCRIPTION"])[0]
            except Exception:
                pass
        installed = bool(vartree.match(cp))
        results.append({"cp": cp, "best": best or "", "description": desc, "installed": installed})
    return results


def _use_flags(atom: str):
    _maybe_reload_portage()
    import portage
    from portage.versions import cpv_getkey

    vdb = portage.db[portage.root]["vartree"].dbapi
    porttree = portage.db[portage.root]["porttree"].dbapi

    try:
        _cp = cpv_getkey(atom)
    except Exception:
        _cp = None
    exact = ("=" + atom) if (_cp and _cp != atom and not atom.startswith(("=", "<", ">", "~"))) else atom
    installed = vdb.match(exact) or vdb.match(atom)

    if installed:
        cpv = installed[-1]
        iuse_raw, use_active = vdb.aux_get(cpv, ["IUSE", "USE"])
        active_set = set(use_active.split())
    else:
        try:
            cp = cpv_getkey(atom) or atom
        except Exception:
            cp = atom
        versions = porttree.cp_list(cp)
        if not versions:
            return [{"cpv": atom, "flags": []}]
        cpv = atom if atom in versions else versions[-1]
        try:
            iuse_raw = porttree.aux_get(cpv, ["IUSE"])[0]
        except Exception:
            return [{"cpv": cpv, "flags": []}]
        active_set = set()  # not installed, no active USE

    descriptions = {}
    forced_flags = frozenset()
    masked_flags = frozenset()
    try:
        from .use_origin import _flag_descriptions, _forced_and_masked_flags

        descriptions = _flag_descriptions(cpv)
        forced_flags, masked_flags = _forced_and_masked_flags(cpv)
    except Exception:
        pass

    flags = []
    for flag in iuse_raw.split():
        default_on = flag.startswith("+")
        flag_name = flag.lstrip("+-")
        enabled = flag_name in active_set
        source = "profile"
        if flag_name in forced_flags:
            enabled = True
            source = "forced"
        elif flag_name in masked_flags:
            enabled = False
            source = "masked"

        flags.append(
            {
                "name": flag_name,
                "description": descriptions.get(flag_name, ""),
                "enabled": enabled,
                "default_on": default_on,
                "source": source,
                "forced": flag_name in forced_flags,
                "masked": flag_name in masked_flags,
            }
        )
    return [{"cpv": cpv, "flags": flags, "installed": bool(installed)}]


def _package_deps(atom: str):
    _maybe_reload_portage()
    import portage
    from portage.versions import cpv_getkey

    vdb = portage.db[portage.root]["vartree"].dbapi
    porttree = portage.db[portage.root]["porttree"].dbapi

    try:
        _cp = cpv_getkey(atom)
    except Exception:
        _cp = None
    exact = ("=" + atom) if (_cp and _cp != atom and not atom.startswith(("=", "<", ">", "~"))) else atom
    installed = vdb.match(exact) or vdb.match(atom)

    if installed:
        cpv = installed[-1]
        rdepend, depend = vdb.aux_get(cpv, ["RDEPEND", "DEPEND"])
    else:
        try:
            cp = cpv_getkey(atom) or atom
        except Exception:
            cp = atom
        versions = porttree.cp_list(cp)
        if not versions:
            return [{"cpv": atom, "rdepend": "", "depend": ""}]
        cpv = atom if atom in versions else versions[-1]
        try:
            rdepend, depend = porttree.aux_get(cpv, ["RDEPEND", "DEPEND"])
        except Exception:
            return [{"cpv": cpv, "rdepend": "", "depend": ""}]

    return [{"cpv": cpv, "rdepend": rdepend, "depend": depend}]


# ---------------------------------------------------------------------------
# Async handlers — delegate blocking work to thread, stream results
# ---------------------------------------------------------------------------

async def cmd_system_status(_args):
    for item in await in_thread(_system_status):
        yield item

async def cmd_installed_packages(args):
    search = args.get("search", "").lower()
    for item in await in_thread(_installed_packages, search):
        yield item


async def cmd_pkg_stats(_args):
    yield await in_thread(_pkg_stats)

async def cmd_package_info(args):
    atom = args.get("atom", "")
    if not _valid_atom(atom):
        yield {"error": "invalid atom"}
        return
    for item in await in_thread(_package_info, atom):
        yield item

async def cmd_package_search(args):
    query = args.get("query", "")
    if not query:
        yield {"error": "query required"}
        return
    try:
        for item in await in_thread(_package_search, query):
            yield item
    except Exception as e:
        log.exception("package_search failed")
        yield {"error": str(e)}
    yield {"done": True}

async def cmd_world_updates(_args):
    async for item in _start_background_job(
        "@world-pretend",
        ["emerge", "--pretend", "--update", "--deep", "--newuse", "--with-bdeps=y",
         "--color=n", "@world"],
        kind="world-pretend",
    ):
        yield item

async def cmd_use_flags(args):
    atom = args.get("atom", "")
    if not _valid_atom(atom):
        yield {"error": "invalid atom"}
        return
    for item in await in_thread(_use_flags, atom):
        yield item


async def cmd_use_flag_origins(args):
    atom = str(args.get("atom", "")).strip()
    category = str(args.get("category", "")).strip()
    package_name = str(args.get("package_name", "")).strip()
    if atom:
        try:
            from portage.dep import Atom
            from portage.versions import cpv_getkey
            cp = cpv_getkey(atom) or atom
            Atom(cp, allow_wildcard=False, allow_repo=False)
            category, package_name = cp.split("/", 1)
        except Exception:
            yield {"error": "invalid atom"}
            return
    elif not category or not package_name:
        yield {"error": "category and package_name are required"}
        return
    try:
        from portage.dep import Atom
        Atom(f"{category}/{package_name}", allow_wildcard=False, allow_repo=False)
    except Exception:
        yield {"error": "invalid package"}
        return
    try:
        from .use_origin import trace_use_flag_origins
        yield await in_thread(trace_use_flag_origins, category, package_name)
    except ModuleNotFoundError:
        yield {"error": "use origin support not installed"}
    except LookupError:
        yield {"error": "not found"}
    except Exception as e:
        yield {"error": str(e)}


async def cmd_global_use_flags_audit(_args):
    try:
        from .use_origin import trace_package_overrides_audit
        yield await in_thread(trace_package_overrides_audit)
    except ModuleNotFoundError:
        yield {"error": "use origin support not installed"}
    except Exception as e:
        yield {"error": str(e)}


async def cmd_package_deps(args):
    atom = args.get("atom", "")
    if not _valid_atom(atom):
        yield {"error": "invalid atom"}
        return
    for item in await in_thread(_package_deps, atom):
        yield item


def _dep_graph(atom: str, max_depth: int, max_nodes: int = 80):
    _maybe_reload_portage()
    import portage
    from portage.dep import dep_getkey
    from portage.versions import cpv_getkey
    from collections import deque

    vdb = portage.db[portage.root]["vartree"].dbapi
    porttree = portage.db[portage.root]["porttree"].dbapi

    nodes = {}
    edges = set()

    def resolve_cpv(a):
        try:
            installed = vdb.match(a)
        except Exception:
            installed = []
        if installed:
            cpv = installed[-1]
            use_raw = vdb.aux_get(cpv, ["USE"])[0] or ""
            return cpv, set(use_raw.split()), True
        try:
            cp = cpv_getkey(a) or a
        except Exception:
            cp = a
        versions = porttree.cp_list(cp)
        if not versions:
            return None, set(), False
        cpv = a if a in versions else versions[-1]
        return cpv, set(), False

    def get_deps(cpv, use_flags, installed):
        try:
            raw = (vdb if installed else porttree).aux_get(cpv, ["RDEPEND"])[0] or ""
            if not raw.strip():
                return []
            try:
                from portage.dep import use_reduce
                tokens = use_reduce(raw, uselist=use_flags, flat=True, token_class=str)
            except Exception:
                tokens = raw.split()
            seen = set()
            result = []
            for token in tokens:
                if not isinstance(token, str) or not token:
                    continue
                if token in ("||", "&&", "^^", "(", ")") or token.endswith("?") or token.startswith("!"):
                    continue
                token = token.split("[")[0].split(":")[0]
                if "/" not in token:
                    continue
                try:
                    cp = dep_getkey(token)
                    if cp and "/" in cp and not cp.startswith("!") and cp not in seen:
                        seen.add(cp)
                        result.append(cp)
                except Exception:
                    continue
            return result
        except Exception as e:
            log.warning("get_deps failed for %s: %s", cpv, e)
            return []

    try:
        root_cp = cpv_getkey(atom) or atom
    except Exception:
        root_cp = atom

    # BFS — processes nodes closest to root first, respects max_nodes limit
    queue = deque([(atom, max_depth)])
    visited = {}  # cp -> max depth explored

    while queue and len(nodes) < max_nodes:
        atom_in, depth = queue.popleft()
        if depth <= 0:
            continue
        try:
            cp = cpv_getkey(atom_in) or atom_in
        except Exception:
            cp = atom_in
        if not cp:
            continue
        if visited.get(cp, -1) >= depth:
            continue
        visited[cp] = depth

        cpv, use_flags, installed = resolve_cpv(atom_in)
        if cpv is None:
            continue

        nodes[cp] = {"id": cp, "cpv": cpv, "installed": installed}

        for dep_cp in get_deps(cpv, use_flags, installed):
            if dep_cp:
                edges.add((cp, dep_cp))
                if len(nodes) < max_nodes:
                    queue.append((dep_cp, depth - 1))

    # Add stub nodes for edge targets not yet in nodes, check if installed
    for src, tgt in list(edges):
        if tgt not in nodes:
            try:
                is_installed = bool(vdb.match(tgt))
            except Exception:
                is_installed = False
            nodes[tgt] = {"id": tgt, "cpv": tgt, "installed": is_installed}

    return [{
        "nodes": list(nodes.values()),
        "edges": [{"source": s, "target": t} for s, t in edges],
        "root": root_cp,
    }]


async def cmd_dep_graph(args):
    atom = args.get("atom", "")
    depth = min(int(args.get("depth", 2)), 4)
    max_nodes = min(int(args.get("max_nodes", 80)), 300)
    if not _valid_atom(atom):
        yield {"error": "invalid atom"}
        return
    try:
        for item in await in_thread(_dep_graph, atom, depth, max_nodes):
            yield item
    except Exception as e:
        log.exception("dep_graph failed")
        yield {"error": str(e)}


# ---------------------------------------------------------------------------
# emerge / etc-update handlers
# ---------------------------------------------------------------------------

_EMERGE_ENV = {**os.environ, "NOCOLOR": "true", "TERM": "dumb"}


# Whitelist of emerge flags the frontend is allowed to toggle. The key is the
# token sent by the client. Bool entries map to the literal flag; int entries
# use a `{}` placeholder filled with a validated value from the request.
# Unknown tokens are silently dropped — never interpolate user input directly.
_BOOL = "bool"
_INT  = "int"

_INSTALL_OPTS = {
    "keep-going":  (_BOOL, "--keep-going"),
    "usepkg":      (_BOOL, "--usepkg"),
    "buildpkg":    (_BOOL, "--buildpkg"),
    "oneshot":     (_BOOL, "--oneshot"),
    "quiet-build": (_BOOL, "--quiet-build"),
    "jobs":        (_INT,  "--jobs={}",      1, 64),
    "backtrack":   (_INT,  "--backtrack={}", 0, 1000),
}
_UPDATE_OPTS = {
    "keep-going":  (_BOOL, "--keep-going"),
    "usepkg":      (_BOOL, "--usepkg"),
    "buildpkg":    (_BOOL, "--buildpkg"),
    "quiet-build": (_BOOL, "--quiet-build"),
    "jobs":        (_INT,  "--jobs={}",      1, 64),
    "backtrack":   (_INT,  "--backtrack={}", 0, 1000),
}


def _parse_opts(opts_str: str, whitelist: dict) -> list[str]:
    """Parse 'k1,k2:V,k3' into a list of emerge flags, dropping anything not
    in the whitelist or out of its declared range."""
    if not opts_str:
        return []
    seen, out = set(), []
    for raw in opts_str.split(","):
        token = raw.strip()
        if not token:
            continue
        name, _, val = token.partition(":") if ":" in token else (token, "", None)
        if not name or name in seen:
            continue
        seen.add(name)
        spec = whitelist.get(name)
        if spec is None:
            continue
        kind, template, *bounds = spec
        if kind == _BOOL:
            if val is None:
                out.append(template)
        elif kind == _INT:
            if val is None or not val.lstrip("-").isdigit():
                continue
            try:
                n = int(val)
            except ValueError:
                continue
            lo, hi = (bounds + [0, 9999])[:2]
            if n < lo or n > hi:
                continue
            out.append(template.format(n))
    return out


def _write_keywords(entries: list) -> tuple:
    """Write [(atom, keyword), ...] to package.accept_keywords/arbor-accepted.

    Each (atom, keyword) is validated; malformed entries are dropped. This is
    the only file we ever modify on the user's behalf — every other portage
    config change must go through the etc-update flow.
    Returns (path, list_of_written_lines, list_of_rejected).
    """
    kw_path = Path("/etc/portage/package.accept_keywords")
    target = kw_path / "arbor-accepted" if kw_path.is_dir() else kw_path
    target.parent.mkdir(parents=True, exist_ok=True)
    existing = target.read_text() if target.exists() else ""
    written = []
    rejected = []
    with open(target, "a") as f:
        for atom, kw in entries:
            if not _valid_atom(atom) or not _valid_keyword(kw):
                rejected.append(f"{atom!r} {kw!r}")
                continue
            line = f"{atom} {kw}\n"
            if line not in existing:
                f.write(f"# Added by arbor\n{line}")
                existing += line
                written.append(f"{atom} {kw}")
    return str(target), written, rejected


# NOTE: a previous version of this module auto-applied ._cfg* files under
# /etc/portage created by `emerge --autounmask-write`. That blew away local
# admin edits without confirmation. We now never call `--autounmask-write`
# from the daemon, and any ._cfg* file is surfaced through the normal
# etc-update flow so the user can review and confirm each change.


async def cmd_emerge_pretend(args):
    atom = _checked_atom(args.get("atom", ""))
    if not atom:
        yield {"error": "invalid atom"}
        return
    # After autounmask-write, run without --autounmask=y so we get a clean result
    clean = args.get("clean", False)
    user_opts = _parse_opts(args.get("opts", ""), _INSTALL_OPTS)
    cmd = ["emerge", "--pretend", "--verbose", "--color=n", *user_opts]
    if not clean:
        cmd.append("--autounmask=y")
    cmd.append(atom)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=_EMERGE_ENV,
    )
    lines = []
    async for raw in proc.stdout:
        line = _ANSI.sub("", raw.decode(errors="replace").rstrip())
        lines.append(line)
        yield {"line": line}
    await proc.wait()
    full = "\n".join(lines)
    # Only flag needs_unmask when emerge actually failed due to masking
    needs_unmask = proc.returncode != 0 and any(s in full for s in [
        "autounmask-write",
        "package.accept_keywords",
        "package.license",
        "package.unmask",
        "missing keyword",
        "masked by: ~",
    ])
    yield {"done": True, "returncode": proc.returncode, "needs_unmask": needs_unmask}


_MASKED_RE = re.compile(
    r"-\s+([\w.+@/-]+(?:-[\d][\w.+@-]*)?)::\S+\s+\(masked by:\s+(~[\w-]+|missing)\s+keyword"
)


async def cmd_emerge_autounmask(args):
    """Scan masked deps and write keyword entries to package.accept_keywords/arbor-accepted."""
    atom = _checked_atom(args.get("atom", ""))
    if not atom:
        yield {"error": "invalid atom"}
        return

    # Step 1 — plain pretend to collect ALL masked packages (shows "masked by:" lines).
    yield {"line": "-- scanning dependency tree for masked packages..."}
    proc1 = await asyncio.create_subprocess_exec(
        "emerge", "--pretend", "--color=n", atom,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=_EMERGE_ENV,
    )
    scan_lines = []
    async for raw in proc1.stdout:
        scan_lines.append(_ANSI.sub("", raw.decode(errors="replace").rstrip()))
    await proc1.wait()
    scan_full = "\n".join(scan_lines)

    # Step 2 — run a plain --autounmask=y pretend so portage prints the full
    # autounmask report (without --autounmask-write — we never want emerge to
    # write into /etc/portage behind the user's back).
    proc2 = await asyncio.create_subprocess_exec(
        "emerge", "--pretend", "--autounmask=y", "--color=n", atom,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=_EMERGE_ENV,
    )
    async for raw in proc2.stdout:
        yield {"line": _ANSI.sub("", raw.decode(errors="replace").rstrip())}
    await proc2.wait()

    # Step 3 — parse the plain-pretend output for "masked by" lines and write
    # keyword entries to our own file under /etc/portage/package.accept_keywords.
    # We never touch any other portage config file: USE/license/mask changes
    # the user must apply manually.
    entries = []
    for m in _MASKED_RE.finditer(scan_full):
        cpv_raw, kw_raw = m.group(1), m.group(2)
        kw = "**" if kw_raw == "missing" else kw_raw
        entries.append((_normalize_atom(cpv_raw), kw))
    entries.append((atom, "**"))  # always accept the main atom

    kw_file, written, rejected = await in_thread(_write_keywords, entries)
    if written:
        for w in written:
            yield {"line": f"-- wrote '{w}' → {kw_file}"}
    else:
        yield {"line": f"-- no new keyword entries needed in {kw_file}"}
    for r in rejected:
        yield {"line": f"-- rejected invalid entry: {r}"}

    yield {"done": True, "returncode": 0}


async def _run_job(job_id: str):
    job = _jobs[job_id]
    try:
        async for raw in job.proc.stdout:
            job._push({"line": _ANSI.sub("", raw.decode(errors="replace").rstrip())})
        await job.proc.wait()
        job.returncode = job.proc.returncode
        job.status = "done" if job.proc.returncode == 0 else "failed"
        job._push({"done": True, "returncode": job.proc.returncode})
    except Exception as e:
        log.exception("job %s error", job_id)
        job.status = "failed"
        job.returncode = -1
        job._push({"error": str(e), "done": True})
    finally:
        for q in list(job._queues):
            q.put_nowait(None)  # sentinel: stream ended
        log.info("job %s finished status=%s rc=%s", job_id, job.status, job.returncode)
        finished_at = time.time()
        log_text = "\n".join(c["line"] for c in job.logs if "line" in c)
        try:
            await in_thread(_history_save, job_id, job.atom, job.kind, job.status,
                            job.returncode, job.created_at, finished_at, log_text)
        except Exception as exc:
            log.warning("failed to persist history for job %s: %s", job_id, exc)


async def _cleanup_jobs():
    """Remove finished jobs older than 30 minutes, draining any lingering subscriber queues."""
    while True:
        await asyncio.sleep(300)
        cutoff = time.time() - 1800
        stale = [jid for jid, j in _jobs.items()
                 if j.status != "running" and j.created_at < cutoff]
        for jid in stale:
            job = _jobs.pop(jid)
            for q in list(job._queues):
                q.put_nowait(None)
            log.info("evicted job %s from registry", jid)


async def cmd_emerge_install(args):
    atom = _checked_atom(args.get("atom", ""))
    if not atom:
        yield {"error": "invalid atom"}
        return
    user_opts = _parse_opts(args.get("opts", ""), _INSTALL_OPTS)

    async with _get_jobs_lock():
        # Return existing running job for the same atom instead of spawning a duplicate
        for jid, job in _jobs.items():
            if job.atom == atom and job.status == "running":
                log.info("reattaching to existing job %s for %s", jid, atom)
                yield {"job_id": jid, "resumed": True}
                return

        proc = await asyncio.create_subprocess_exec(
            "emerge", "--verbose", "--color=n", *user_opts, atom,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=_EMERGE_ENV,
        )
        job_id = str(uuid.uuid4())
        _jobs[job_id] = _Job(atom, proc, kind="install")

    asyncio.create_task(_run_job(job_id))
    log.info("started job %s for %s", job_id, atom)
    yield {"job_id": job_id}


async def _start_background_job(key: str, cmd: list, kind: str = "task"):
    async with _get_jobs_lock():
        for jid, job in _jobs.items():
            if job.atom == key and job.status == "running":
                log.info("reattaching to existing job %s for %s", jid, key)
                yield {"job_id": jid, "resumed": True}
                return
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=_EMERGE_ENV,
        )
        job_id = str(uuid.uuid4())
        _jobs[job_id] = _Job(key, proc, kind=kind)

    asyncio.create_task(_run_job(job_id))
    log.info("started job %s for %s", job_id, key)
    yield {"job_id": job_id}


async def cmd_emerge_uninstall_pretend(args):
    atom = _checked_atom(args.get("atom", ""))
    if not atom:
        yield {"error": "invalid atom"}
        return
    proc = await asyncio.create_subprocess_exec(
        "emerge", "--pretend", "--unmerge", "--verbose", "--color=n", atom,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=_EMERGE_ENV,
    )
    async for raw in proc.stdout:
        yield {"line": _ANSI.sub("", raw.decode(errors="replace").rstrip())}
    await proc.wait()
    yield {"done": True, "returncode": proc.returncode}


async def cmd_emerge_uninstall(args):
    atom = _checked_atom(args.get("atom", ""))
    if not atom:
        yield {"error": "invalid atom"}
        return
    async for item in _start_background_job(
        f"uninstall:{atom}",
        ["emerge", "--unmerge", "--verbose", "--color=n", atom],
        kind="uninstall",
    ):
        yield item


async def cmd_emerge_world_update(args):
    user_opts = _parse_opts(args.get("opts", ""), _UPDATE_OPTS)
    async for item in _start_background_job(
        "@world",
        ["emerge", "--update", "--deep", "--newuse", "--with-bdeps=y", "--color=n",
         *user_opts, "@world"],
        kind="world",
    ):
        yield item


async def cmd_emerge_depclean_pretend(_args):
    async for item in _start_background_job(
        "@depclean-pretend",
        ["emerge", "--depclean", "--pretend", "--color=n"],
        kind="depclean-pretend",
    ):
        yield item


async def cmd_emerge_depclean(_args):
    async for item in _start_background_job(
        "@depclean",
        ["emerge", "--depclean", "--color=n"],
        kind="depclean",
    ):
        yield item


async def cmd_emerge_preserved_rebuild(_args):
    async for item in _start_background_job(
        "@preserved-rebuild",
        ["emerge", "@preserved-rebuild", "--color=n"],
        kind="preserved-rebuild",
    ):
        yield item


async def cmd_emerge_sync(_args):
    async for item in _start_background_job(
        "@sync",
        ["emaint", "sync", "-a"],
        kind="sync",
    ):
        yield item


async def cmd_job_attach(args):
    job_id = args.get("job_id", "")
    if not job_id or job_id not in _jobs:
        yield {"error": "job not found"}
        return

    job = _jobs[job_id]
    q = job.subscribe()
    try:
        while True:
            try:
                chunk = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Keepalive so daemon_client timeout doesn't fire
                yield {"keepalive": True}
                continue
            if chunk is None:
                break  # sentinel
            yield chunk
            if chunk.get("done") or chunk.get("error"):
                break
    finally:
        job.unsubscribe(q)


async def cmd_job_status(args):
    job_id = args.get("job_id", "")
    if not job_id or job_id not in _jobs:
        yield {"error": "job not found"}
        return
    job = _jobs[job_id]
    yield {"job_id": job_id, "atom": job.atom, "kind": job.kind,
           "status": job.status, "returncode": job.returncode}


async def cmd_job_list(_args):
    for jid, job in _jobs.items():
        if job.status == "running":
            yield {"job_id": jid, "atom": job.atom, "kind": job.kind,
                   "status": job.status, "returncode": job.returncode, "created_at": job.created_at}
    yield {"done": True}


async def cmd_job_cancel(args):
    job_id = args.get("job_id", "")
    if not job_id or job_id not in _jobs:
        yield {"error": "job not found"}
        return
    job = _jobs[job_id]
    if job.status == "running" and job.proc:
        try:
            job.proc.terminate()
            await asyncio.wait_for(job.proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            job.proc.kill()
        job.status = "failed"
        job.returncode = -1
        job._push({"done": True, "returncode": -1, "error": "cancelled"})
        for q in list(job._queues):
            q.put_nowait(None)
        log.info("cancelled job %s", job_id)
    yield {"ok": True}


def _etc_update_check():
    import subprocess, difflib
    result = subprocess.run(
        ["find", "/etc", "-name", "._cfg*", "-type", "f"],
        capture_output=True, text=True,
    )
    cfg_files = [f for f in result.stdout.strip().splitlines() if f]
    pending = []
    for cfg in cfg_files:
        real = re.sub(r"/\._cfg\d+_", "/", cfg)
        try:
            new_text = Path(cfg).read_text(errors="replace")
            try:
                old_text = Path(real).read_text(errors="replace")
                has_old = True
            except FileNotFoundError:
                old_text = ""
                has_old = False
            diff = "".join(difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=real, tofile=cfg, n=3,
            ))
            pending.append({
                "cfg_file": cfg,
                "real_file": real,
                "has_old": has_old,
                "diff": diff,
            })
        except Exception as e:
            log.warning("etc_update_check error %s: %s", cfg, e)
    return pending


async def cmd_etc_update_check(_args):
    for item in await in_thread(_etc_update_check):
        yield item
    yield {"done": True}


_CFG_BASENAME_RE = re.compile(r"^\._cfg\d+_[^/]+$")


def _etc_update_resolve(cfg_file: str, action: str):
    # cfg_file arrives from the client. Validate strictly: it must live under
    # /etc, must be a regular file, and its basename must match Portage's
    # ._cfgNNN_<name> convention. Without these checks an authenticated user
    # could delete or overwrite any file on the system as root.
    try:
        cfg_path = Path(cfg_file).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return [{"error": "invalid path"}]

    try:
        cfg_path.relative_to(Path("/etc"))
    except ValueError:
        return [{"error": "forbidden path: must be under /etc"}]

    if not _CFG_BASENAME_RE.match(cfg_path.name):
        return [{"error": "not a portage cfg-update file"}]

    if not cfg_path.is_file() or cfg_path.is_symlink():
        return [{"error": f"{cfg_path} not found or not a regular file"}]

    real_basename = re.sub(r"^\._cfg\d+_", "", cfg_path.name)
    real_path = cfg_path.with_name(real_basename)

    if action == "replace":
        real_path.parent.mkdir(parents=True, exist_ok=True)
        real_path.write_bytes(cfg_path.read_bytes())
    cfg_path.unlink()
    return [{"ok": True, "cfg_file": str(cfg_path), "action": action}]


async def cmd_etc_update_resolve(args):
    cfg_file = args.get("cfg_file", "")
    action = args.get("action", "")
    if not cfg_file or action not in ("keep", "replace"):
        yield {"error": "cfg_file and action (keep|replace) required"}
        return
    for item in await in_thread(_etc_update_resolve, cfg_file, action):
        yield item


async def cmd_history_list(args):
    limit = min(max(int(args.get("limit", 50)), 1), 500)
    offset = max(int(args.get("offset", 0)), 0)
    kind = args.get("kind", "")
    yield await in_thread(_history_list, limit, offset, kind)


async def cmd_history_log(args):
    yield await in_thread(_history_log, args.get("job_id", ""))


async def cmd_history_delete(args):
    yield await in_thread(_history_delete, args.get("job_id", ""))


async def cmd_history_purge(args):
    days = max(int(args.get("days", 30)), 1)
    yield await in_thread(_history_purge, days)


async def cmd_history_stats(args):
    yield await in_thread(_history_stats)


# ---------------------------------------------------------------------------
# Overlay management
# ---------------------------------------------------------------------------

_OVERLAY_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')
_OVERLAY_URL_RE  = re.compile(r'^(https?://|git://|git\+https://).+')


def _overlay_list() -> list:
    import portage
    repos = []
    for r in portage.portdb.repositories:
        last_sync = ""
        ts_file = Path(r.location) / "metadata" / "timestamp.chk"
        try:
            last_sync = ts_file.read_text().strip() if ts_file.exists() else ""
        except OSError:
            pass
        ebuild_count = 0
        try:
            ebuild_count = sum(1 for _ in Path(r.location).rglob("*.ebuild"))
        except OSError:
            pass
        repos.append({
            "name":       r.name,
            "location":   r.location,
            "sync_type":  r.sync_type or "",
            "sync_uri":   r.sync_uri  or "",
            "last_sync":  last_sync,
            "ebuilds":    ebuild_count,
        })
    # gentoo main repo first, then alphabetical
    repos.sort(key=lambda r: (r["name"] != "gentoo", r["name"]))
    return repos


def _overlay_add(name: str, sync_type: str, sync_uri: str) -> dict:
    import subprocess
    if not _OVERLAY_NAME_RE.match(name):
        return {"error": "invalid overlay name"}
    if not _OVERLAY_URL_RE.match(sync_uri):
        return {"error": "invalid sync URI — must start with https:// or git://"}
    allowed_types = {"git", "rsync", "svn"}
    if sync_type not in allowed_types:
        return {"error": f"unsupported sync type — allowed: {', '.join(sorted(allowed_types))}"}
    result = subprocess.run(
        ["eselect", "repository", "add", name, sync_type, sync_uri],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {"error": result.stderr.strip() or result.stdout.strip() or "eselect failed"}
    return {"ok": True}


def _overlay_remove(name: str, purge: bool) -> dict:
    import subprocess
    if not _OVERLAY_NAME_RE.match(name):
        return {"error": "invalid overlay name"}
    if name == "gentoo":
        return {"error": "cannot remove the main gentoo repository"}
    cmd = ["eselect", "repository", "remove"]
    if purge:
        cmd.append("--force")
    cmd.append(name)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return {"error": result.stderr.strip() or result.stdout.strip() or "eselect failed"}
    return {"ok": True}


async def cmd_overlay_list(_args):
    _maybe_reload_portage()
    items = await in_thread(_overlay_list)
    for item in items:
        yield item
    yield {"done": True}


async def cmd_overlay_add(args):
    global _repos_conf_mtime
    name      = args.get("name", "").strip()
    sync_type = args.get("sync_type", "git").strip()
    sync_uri  = args.get("sync_uri", "").strip()
    result = await in_thread(_overlay_add, name, sync_type, sync_uri)
    if "error" in result:
        yield result
        return
    _repos_conf_mtime = 0.0  # force portage reload on next overlay_list
    # kick off sync as a background job
    async for item in _start_background_job(
        f"@sync:{name}",
        ["emaint", "sync", "-r", name],
        kind="sync",
    ):
        yield item


async def cmd_overlay_remove(args):
    global _repos_conf_mtime
    name  = args.get("name", "").strip()
    purge = bool(args.get("purge", False))
    result = await in_thread(_overlay_remove, name, purge)
    yield result
    if "ok" in result:
        _repos_conf_mtime = 0.0  # force portage reload on next overlay_list
        yield {"done": True}


async def cmd_overlay_sync(args):
    name = args.get("name", "").strip()
    if not _OVERLAY_NAME_RE.match(name):
        yield {"error": "invalid overlay name"}
        return
    async for item in _start_background_job(
        f"@sync:{name}",
        ["emaint", "sync", "-r", name],
        kind="sync",
    ):
        yield item


HANDLERS = {
    "system_status":      cmd_system_status,
    "installed_packages": cmd_installed_packages,
    "pkg_stats":          cmd_pkg_stats,
    "package_info":       cmd_package_info,
    "package_search":     cmd_package_search,
    "world_updates":      cmd_world_updates,
    "use_flags":          cmd_use_flags,
    "global_use_flags_audit": cmd_global_use_flags_audit,
    "use_flag_origins":   cmd_use_flag_origins,
    "package_deps":       cmd_package_deps,
    "dep_graph":          cmd_dep_graph,
    "emerge_pretend":            cmd_emerge_pretend,
    "emerge_install":            cmd_emerge_install,
    "emerge_autounmask":         cmd_emerge_autounmask,
    "emerge_uninstall_pretend":  cmd_emerge_uninstall_pretend,
    "emerge_uninstall":          cmd_emerge_uninstall,
    "emerge_world_update":       cmd_emerge_world_update,
    "emerge_depclean_pretend":   cmd_emerge_depclean_pretend,
    "emerge_depclean":           cmd_emerge_depclean,
    "emerge_preserved_rebuild":  cmd_emerge_preserved_rebuild,
    "emerge_sync":               cmd_emerge_sync,
    "etc_update_check":          cmd_etc_update_check,
    "etc_update_resolve": cmd_etc_update_resolve,
    "job_attach":         cmd_job_attach,
    "job_status":         cmd_job_status,
    "job_cancel":         cmd_job_cancel,
    "job_list":           cmd_job_list,
    "history_list":       cmd_history_list,
    "history_log":        cmd_history_log,
    "history_delete":     cmd_history_delete,
    "history_purge":      cmd_history_purge,
    "history_stats":      cmd_history_stats,
    "overlay_list":       cmd_overlay_list,
    "overlay_add":        cmd_overlay_add,
    "overlay_remove":     cmd_overlay_remove,
    "overlay_sync":       cmd_overlay_sync,
}


async def main():
    import grp

    if os.geteuid() != 0:
        log.error("arbor-daemon must run as root")
        sys.exit(1)

    try:
        arbor_gid = grp.getgrnam("arbor").gr_gid
    except KeyError:
        log.error("group 'arbor' not found — create it before running the daemon")
        sys.exit(1)

    socket_dir = Path(SOCKET_PATH).parent
    socket_dir.mkdir(parents=True, exist_ok=True)
    os.chown(socket_dir, 0, arbor_gid)
    os.chmod(socket_dir, 0o750)

    if Path(SOCKET_PATH).exists():
        Path(SOCKET_PATH).unlink()

    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)
    os.chown(SOCKET_PATH, 0, arbor_gid)
    os.chmod(SOCKET_PATH, 0o660)

    _db_init()
    asyncio.create_task(_cleanup_jobs())
    log.info("listening on %s", SOCKET_PATH)
    async with server:
        await server.serve_forever()


def cli():
    """Sync entry point for the console script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli()
