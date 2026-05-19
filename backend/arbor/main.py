"""
Arbor web backend — FastAPI, runs as unprivileged user.
Talks to arbor-daemon via Unix socket for all Portage operations.
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .auth import require_auth, verify_token
from .daemon_client import query, query_all, query_one
from .emerge_log import compile_time_by_category

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [arbor] %(levelname)s %(message)s",
)

app = FastAPI(title="Arbor", version="0.1.0", docs_url=None, redoc_url=None)

# CORS — default to loopback only. Set ARBOR_CORS_ORIGINS to a comma-separated
# list to override (e.g. "https://arbor.lan,http://localhost:5173").
_default_cors = "https://localhost:8443,http://localhost:5173"
_cors_origins = [
    o.strip() for o in os.environ.get("ARBOR_CORS_ORIGINS", _default_cors).split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

Auth = Annotated[str, Depends(require_auth)]


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def system_status(auth: Auth):
    data = await query_one("system_status")
    return data


@app.get("/api/packages")
async def installed_packages(auth: Auth, search: str = Query(default="")):
    results = await query_all("installed_packages", {"search": search})
    # strip the trailing {"done": true} sentinel if present
    return [r for r in results if "cpv" in r]


@app.get("/api/package")
async def package_info(auth: Auth, atom: str = Query(min_length=1)):
    results = await query_all("package_info", {"atom": atom})
    packages = [r for r in results if "cpv" in r]
    if not packages:
        return JSONResponse(status_code=404, content={"error": "not found"})
    return packages


@app.get("/api/search")
async def search_packages(auth: Auth, q: str = Query(min_length=2)):
    results = await query_all("package_search", {"query": q})
    return [r for r in results if "cp" in r]


@app.get("/api/package/use-flags")
async def use_flags(auth: Auth, atom: str = Query(min_length=1)):
    data = await query_one("use_flags", {"atom": atom})
    return data


@app.get("/api/package/use-flag-origins")
async def use_flag_origins(
    auth: Auth,
    atom: str = Query(default=""),
    category: str = Query(default=""),
    package_name: str = Query(default=""),
):
    data = await query_one(
        "use_flag_origins",
        {"atom": atom, "category": category, "package_name": package_name},
    )
    if "error" in data:
        status = 404 if data["error"] == "not found" else 400
        return JSONResponse(status_code=status, content=data)
    return data


@app.get("/api/use-flags-audit")
async def global_use_flags_audit(auth: Auth):
    data = await query_one("global_use_flags_audit", {})
    if "error" in data:
        return JSONResponse(status_code=400, content=data)
    return data


@app.get("/api/package/deps")
async def package_deps(auth: Auth, atom: str = Query(min_length=1)):
    data = await query_one("package_deps", {"atom": atom})
    return data


@app.get("/api/package/dep-graph")
async def dep_graph(auth: Auth, atom: str = Query(min_length=1), depth: int = Query(default=2, ge=1, le=4), max_nodes: int = Query(default=80, ge=10, le=300)):
    data = await query_one("dep_graph", {"atom": atom, "depth": depth, "max_nodes": max_nodes})
    return data


# ---------------------------------------------------------------------------
# emerge — REST + WebSocket endpoints
# ---------------------------------------------------------------------------

async def _ws_emerge(websocket: WebSocket, token: str, cmd: str, atom: str, extra_args: dict = {}):
    if not verify_token(token):
        await websocket.close(code=4401)
        return
    if not atom:
        await websocket.close(code=4400)
        return
    await websocket.accept()
    try:
        async for chunk in query(cmd, {"atom": atom, **extra_args}):
            await websocket.send_text(json.dumps(chunk))
            if chunk.get("done"):
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"error": str(e), "done": True}))
        except Exception:
            pass
    finally:
        await websocket.close()


async def _ws_job_cmd(websocket: WebSocket, token: str, daemon_cmd: str, args: dict):
    """Start (or resume) a background job and stream its output."""
    if not verify_token(token):
        await websocket.close(code=4401); return
    await websocket.accept()
    try:
        job_id = None
        async for chunk in query(daemon_cmd, args):
            if chunk.get("error"):
                await websocket.send_text(json.dumps({"error": chunk["error"], "done": True}))
                return
            if "job_id" in chunk:
                job_id = chunk["job_id"]
                await websocket.send_text(json.dumps(chunk))
                break
        if not job_id:
            await websocket.send_text(json.dumps({"error": "failed to start job", "done": True}))
            return
        async for chunk in query("job_attach", {"job_id": job_id}):
            if chunk.get("keepalive"): continue
            if chunk.get("error") and not chunk.get("done"):
                chunk = {**chunk, "done": True}
            await websocket.send_text(json.dumps(chunk))
            if chunk.get("done") or chunk.get("error"): break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try: await websocket.send_text(json.dumps({"error": str(e), "done": True}))
        except Exception: pass
    finally:
        await websocket.close()


@app.websocket("/ws/emerge/pretend")
async def ws_emerge_pretend(websocket: WebSocket, token: str = Query(default=""), atom: str = Query(default=""), clean: str = Query(default="0"), opts: str = Query(default="")):
    await _ws_emerge(websocket, token, "emerge_pretend", atom, {"clean": clean == "1", "opts": opts})


@app.websocket("/ws/emerge/install")
async def ws_emerge_install(websocket: WebSocket, token: str = Query(default=""), atom: str = Query(default=""), opts: str = Query(default="")):
    if not atom:
        await websocket.close(code=4400); return
    await _ws_job_cmd(websocket, token, "emerge_install", {"atom": atom, "opts": opts})


@app.websocket("/ws/emerge/uninstall-pretend")
async def ws_emerge_uninstall_pretend(websocket: WebSocket, token: str = Query(default=""), atom: str = Query(default="")):
    await _ws_emerge(websocket, token, "emerge_uninstall_pretend", atom)


@app.websocket("/ws/emerge/uninstall")
async def ws_emerge_uninstall(websocket: WebSocket, token: str = Query(default=""), atom: str = Query(default="")):
    if not atom:
        await websocket.close(code=4400); return
    await _ws_job_cmd(websocket, token, "emerge_uninstall", {"atom": atom})


@app.websocket("/ws/emerge/world-update")
async def ws_emerge_world_update(websocket: WebSocket, token: str = Query(default=""), opts: str = Query(default="")):
    await _ws_job_cmd(websocket, token, "emerge_world_update", {"opts": opts})


@app.websocket("/ws/emerge/depclean-pretend")
async def ws_emerge_depclean_pretend(websocket: WebSocket, token: str = Query(default="")):
    await _ws_job_cmd(websocket, token, "emerge_depclean_pretend", {})


@app.websocket("/ws/emerge/depclean")
async def ws_emerge_depclean(websocket: WebSocket, token: str = Query(default="")):
    await _ws_job_cmd(websocket, token, "emerge_depclean", {})


@app.websocket("/ws/emerge/preserved-rebuild")
async def ws_emerge_preserved_rebuild(websocket: WebSocket, token: str = Query(default="")):
    await _ws_job_cmd(websocket, token, "emerge_preserved_rebuild", {})


@app.websocket("/ws/emerge/world-pretend")
async def ws_emerge_world_pretend(websocket: WebSocket, token: str = Query(default="")):
    await _ws_job_cmd(websocket, token, "world_updates", {})


@app.websocket("/ws/emerge/sync")
async def ws_emerge_sync(websocket: WebSocket, token: str = Query(default="")):
    await _ws_job_cmd(websocket, token, "emerge_sync", {})


@app.websocket("/ws/jobs/{job_id}")
async def ws_job_attach(websocket: WebSocket, job_id: str, token: str = Query(default="")):
    if not verify_token(token):
        await websocket.close(code=4401); return
    await websocket.accept()
    try:
        async for chunk in query("job_attach", {"job_id": job_id}):
            if chunk.get("keepalive"):
                continue
            await websocket.send_text(json.dumps(chunk))
            if chunk.get("done") or chunk.get("error"):
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"error": str(e), "done": True}))
        except Exception:
            pass
    finally:
        await websocket.close()


@app.get("/api/jobs")
async def job_list(auth: Auth, atom: str = Query(default="")):
    results = await query_all("job_list", {})
    jobs = [r for r in results if "job_id" in r]
    if atom:
        # The daemon normalizes CPV atoms with a leading = (e.g. dev-libs/foo-1.0 →
        # =dev-libs/foo-1.0), so match against both the raw and prefixed form.
        # Uninstall jobs store their atom as "uninstall:{atom}", so also match that.
        variants = {atom}
        if not atom.startswith(("=", "<", ">", "~", "!")):
            variants.add("=" + atom)
        for v in list(variants):
            variants.add("uninstall:" + v)
        jobs = [j for j in jobs if j["atom"] in variants]
    return jobs


@app.get("/api/jobs/{job_id}")
async def job_status(auth: Auth, job_id: str):
    data = await query_one("job_status", {"job_id": job_id})
    if "error" in data:
        return JSONResponse(status_code=404, content=data)
    return data


@app.post("/api/jobs/{job_id}/cancel")
async def job_cancel(auth: Auth, job_id: str):
    data = await query_one("job_cancel", {"job_id": job_id})
    if "error" in data:
        return JSONResponse(status_code=404, content=data)
    return data


@app.websocket("/ws/emerge/autounmask")
async def ws_emerge_autounmask(websocket: WebSocket, token: str = Query(default=""), atom: str = Query(default="")):
    await _ws_emerge(websocket, token, "emerge_autounmask", atom)


@app.get("/api/emerge/etc-update")
async def etc_update_check(auth: Auth):
    results = await query_all("etc_update_check", {})
    return [r for r in results if "cfg_file" in r]


@app.get("/api/history")
async def history_list(
    auth: Auth,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    kind: str = Query(default=""),
):
    data = await query_one("history_list", {"limit": limit, "offset": offset, "kind": kind})
    return data


@app.get("/api/history/{job_id}/log")
async def history_log(auth: Auth, job_id: str):
    data = await query_one("history_log", {"job_id": job_id})
    if "error" in data:
        return JSONResponse(status_code=404, content=data)
    return data


@app.delete("/api/history/{job_id}")
async def history_delete(auth: Auth, job_id: str):
    data = await query_one("history_delete", {"job_id": job_id})
    if "error" in data:
        return JSONResponse(status_code=404, content=data)
    return data


@app.post("/api/history/purge")
async def history_purge(auth: Auth, request: Request):
    body = await request.json()
    days = max(int(body.get("days", 30)), 1)
    data = await query_one("history_purge", {"days": days})
    return data


@app.get("/api/stats")
async def history_stats(auth: Auth):
    data = await query_one("history_stats", {})
    return data


@app.get("/api/pkg-stats")
async def pkg_stats(auth: Auth):
    data = await query_one("pkg_stats", {})
    return data


@app.get("/api/analytics/compile-time-by-category")
async def analytics_compile_time(auth: Auth):
    """
    Returns per-Portage-category total compile time (seconds) extracted from
    /var/log/emerge.log, sorted descending. Result is cached in memory and
    invalidated automatically when the log file changes.
    """
    return await compile_time_by_category()


@app.post("/api/emerge/etc-update/resolve")
async def etc_update_resolve(auth: Auth, request: Request):
    body = await request.json()
    cfg_file = body.get("cfg_file", "")
    action = body.get("action", "")
    data = await query_one("etc_update_resolve", {"cfg_file": cfg_file, "action": action})
    return data


# ---------------------------------------------------------------------------
# Overlay management
# ---------------------------------------------------------------------------

@app.get("/api/overlays")
async def overlay_list(auth: Auth):
    results = await query_all("overlay_list", {})
    return [r for r in results if "name" in r]


@app.post("/api/overlays")
async def overlay_add(auth: Auth, request: Request):
    body = await request.json()
    name      = str(body.get("name", "")).strip()
    sync_type = str(body.get("sync_type", "git")).strip()
    sync_uri  = str(body.get("sync_uri", "")).strip()
    data = await query_one("overlay_add", {"name": name, "sync_type": sync_type, "sync_uri": sync_uri})
    if "error" in data:
        return JSONResponse(status_code=400, content=data)
    return data


@app.delete("/api/overlays/{name}")
async def overlay_remove(auth: Auth, name: str, purge: int = Query(default=0)):
    data = await query_one("overlay_remove", {"name": name, "purge": bool(purge)})
    if "error" in data:
        return JSONResponse(status_code=400, content=data)
    return data


@app.websocket("/ws/overlays/sync/{name}")
async def ws_overlay_sync(websocket: WebSocket, name: str, token: str = Query(default="")):
    if not verify_token(token):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    try:
        job_id = None
        async for chunk in query("overlay_sync", {"name": name}):
            await websocket.send_text(json.dumps(chunk))
            if "job_id" in chunk:
                job_id = chunk["job_id"]
            if chunk.get("done") or chunk.get("error"):
                break
        if not job_id:
            await websocket.send_text(json.dumps({"error": "failed to start sync", "done": True}))
            return
        async for chunk in query("job_attach", {"job_id": job_id}):
            await websocket.send_text(json.dumps(chunk))
            if chunk.get("done") or chunk.get("error"):
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"error": str(e), "done": True}))
        except Exception:
            pass
    finally:
        await websocket.close()


# ---------------------------------------------------------------------------
# WebSocket — streaming endpoints
# ---------------------------------------------------------------------------

@app.websocket("/ws/updates")
async def ws_world_updates(websocket: WebSocket, token: str = Query(default="")):
    if not verify_token(token):
        await websocket.close(code=4401)
        return

    await websocket.accept()
    try:
        async for chunk in query("world_updates"):
            await websocket.send_text(json.dumps(chunk))
            if chunk.get("done"):
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_text(json.dumps({"error": str(e)}))
    finally:
        await websocket.close()


# ---------------------------------------------------------------------------
# Serve frontend static files (populated by Svelte build)
# ---------------------------------------------------------------------------

# Search order: ARBOR_STATIC_DIR env, install paths, repo dev paths.
# Alpine (no-build) layout has files directly in /usr/lib/arbor/frontend/.
# The old dist/ layout is kept as a fallback during transition.
_static_candidates = [
    os.environ.get("ARBOR_STATIC_DIR"),
    "/usr/share/arbor/frontend",                                       # Portage-installed (ebuild)
    "/usr/lib/arbor/frontend",                                         # installed (alpine, no-build)
    "/usr/lib/arbor/frontend/dist",                                    # installed (old dist)
    str(Path(__file__).parent.parent.parent / "frontend" / "alpine"), # dev (alpine)
    str(Path(__file__).parent.parent.parent / "frontend" / "dist"),   # dev (old dist)
]
for _candidate in _static_candidates:
    if _candidate and Path(_candidate).is_dir():
        app.mount("/", StaticFiles(directory=_candidate, html=True), name="static")
        break
