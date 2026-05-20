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
from .config_env import env_enabled, env_list
from .daemon_client import query, query_all, query_one
from .emerge_log import compile_time_by_category

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [arbor] %(levelname)s %(message)s",
)

app = FastAPI(title="Arbor", version="0.1.0", docs_url=None, redoc_url=None)

# The frontend uses Alpine's CSP-friendly build, so script-src can omit
# unsafe-eval. Inline styles are still used by the current UI.
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response

def _default_loopback_origins() -> list[str]:
    origins: list[str] = []
    for scheme in ("https", "http"):
        origins.extend([
            f"{scheme}://localhost:8443",
            f"{scheme}://127.0.0.1:8443",
            f"{scheme}://[::1]:8443",
        ])
    return origins


# CORS — default to local loopback origins only. Set ARBOR_CORS_ORIGINS to a
# comma-separated list to override.
_cors_origins = env_list("ARBOR_CORS_ORIGINS", _default_loopback_origins())
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

Auth = Annotated[str, Depends(require_auth)]
_WS_AUTH_TIMEOUT = 5

def _overlay_add_enabled() -> bool:
    return env_enabled("ARBOR_ENABLE_OVERLAY_ADD")


async def _json_object_body(request: Request, *, allow_empty: bool = True) -> dict | JSONResponse:
    raw_body = await request.body()
    if not raw_body:
        return {} if allow_empty else JSONResponse(status_code=400, content={"error": "request body must be a JSON object"})
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "invalid JSON body"})
    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "request body must be an object"})
    return body


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
    try:
        results = await query_all("package_info", {"atom": atom})
    except RuntimeError as exc:
        if str(exc) == "not found":
            return JSONResponse(status_code=404, content={"error": "not found"})
        raise
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


@app.get("/api/approval-requests")
async def approval_request_list(auth: Auth, status: str = Query(default="pending")):
    results = await query_all("approval_request_list", {"status": status})
    return [r for r in results if "request_id" in r]


@app.get("/api/approval-requests/{request_id}")
async def approval_request_show(auth: Auth, request_id: str):
    data = await query_one("approval_request_show", {"request_id": request_id})
    if "error" in data:
        return JSONResponse(status_code=404, content=data)
    return data


@app.post("/api/approval-requests")
async def approval_request_create(auth: Auth, request: Request):
    body = await _json_object_body(request, allow_empty=False)
    if isinstance(body, JSONResponse):
        return body
    cmd = str(body.get("cmd", "")).strip()
    args = body.get("args", {})
    if not isinstance(args, dict):
        return JSONResponse(status_code=400, content={"error": "args must be an object"})
    data = await query_one("approval_request_create", {"cmd": cmd, "args": args})
    if "error" in data:
        return JSONResponse(status_code=400, content=data)
    return data


# ---------------------------------------------------------------------------
# emerge — REST + WebSocket endpoints
# ---------------------------------------------------------------------------

async def _ws_fail(websocket: WebSocket, code: int, error: str):
    try:
        await websocket.send_text(json.dumps({"error": error, "done": True}))
    except Exception:
        pass
    try:
        await websocket.close(code=code, reason=error)
    except Exception:
        pass


def _ws_origin_allowed(origin: str | None) -> bool:
    if not origin:
        return True
    return origin in _cors_origins


async def _ws_require_auth(websocket: WebSocket) -> bool:
    await websocket.accept()
    try:
        # Authenticate from the first frame so tokens never appear in URLs or logs.
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=_WS_AUTH_TIMEOUT)
    except asyncio.TimeoutError:
        await _ws_fail(websocket, 4401, "authentication required")
        return False
    except WebSocketDisconnect:
        return False
    except Exception:
        await _ws_fail(websocket, 4400, "invalid auth message")
        return False

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        await _ws_fail(websocket, 4400, "invalid auth message")
        return False

    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get("type") != "auth" or not verify_token(token):
        await _ws_fail(websocket, 4401, "invalid or missing token")
        return False
    origin = websocket.headers.get("origin")
    if not _ws_origin_allowed(origin):
        await _ws_fail(websocket, 4403, "origin not allowed")
        return False
    return True


async def _ws_emerge(websocket: WebSocket, cmd: str, atom: str, extra_args: dict | None = None):
    if not await _ws_require_auth(websocket):
        return
    if not atom:
        await _ws_fail(websocket, 4400, "missing atom")
        return
    try:
        async for chunk in query(cmd, {"atom": atom, **(extra_args or {})}):
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
        try:
            await websocket.close()
        except Exception:
            pass


async def _ws_job_cmd(websocket: WebSocket, daemon_cmd: str, args: dict):
    """Start (or resume) a background job and stream its output."""
    if not await _ws_require_auth(websocket):
        return
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
        try:
            await websocket.close()
        except Exception:
            pass


@app.websocket("/ws/emerge/pretend")
async def ws_emerge_pretend(websocket: WebSocket, atom: str = Query(default=""), clean: str = Query(default="0"), opts: str = Query(default="")):
    await _ws_emerge(websocket, "emerge_pretend", atom, {"clean": clean == "1", "opts": opts})


@app.websocket("/ws/emerge/install")
async def ws_emerge_install(
    websocket: WebSocket,
    atom: str = Query(default=""),
    opts: str = Query(default=""),
    approval_request_id: str = Query(default=""),
    approval_token: str = Query(default=""),
):
    await _ws_job_cmd(
        websocket,
        "emerge_install",
        {
            "atom": atom,
            "opts": opts,
            "approval_request_id": approval_request_id,
            "approval_token": approval_token,
        },
    )


@app.websocket("/ws/emerge/uninstall-pretend")
async def ws_emerge_uninstall_pretend(websocket: WebSocket, atom: str = Query(default="")):
    await _ws_emerge(websocket, "emerge_uninstall_pretend", atom)


@app.websocket("/ws/emerge/uninstall")
async def ws_emerge_uninstall(
    websocket: WebSocket,
    atom: str = Query(default=""),
    approval_request_id: str = Query(default=""),
    approval_token: str = Query(default=""),
):
    await _ws_job_cmd(
        websocket,
        "emerge_uninstall",
        {
            "atom": atom,
            "approval_request_id": approval_request_id,
            "approval_token": approval_token,
        },
    )


@app.websocket("/ws/emerge/world-update")
async def ws_emerge_world_update(
    websocket: WebSocket,
    opts: str = Query(default=""),
    approval_request_id: str = Query(default=""),
    approval_token: str = Query(default=""),
):
    await _ws_job_cmd(
        websocket,
        "emerge_world_update",
        {
            "opts": opts,
            "approval_request_id": approval_request_id,
            "approval_token": approval_token,
        },
    )


@app.websocket("/ws/emerge/depclean-pretend")
async def ws_emerge_depclean_pretend(websocket: WebSocket):
    await _ws_job_cmd(websocket, "emerge_depclean_pretend", {})


@app.websocket("/ws/emerge/depclean")
async def ws_emerge_depclean(
    websocket: WebSocket,
    approval_request_id: str = Query(default=""),
    approval_token: str = Query(default=""),
):
    await _ws_job_cmd(
        websocket,
        "emerge_depclean",
        {
            "approval_request_id": approval_request_id,
            "approval_token": approval_token,
        },
    )


@app.websocket("/ws/emerge/preserved-rebuild")
async def ws_emerge_preserved_rebuild(
    websocket: WebSocket,
    approval_request_id: str = Query(default=""),
    approval_token: str = Query(default=""),
):
    await _ws_job_cmd(
        websocket,
        "emerge_preserved_rebuild",
        {
            "approval_request_id": approval_request_id,
            "approval_token": approval_token,
        },
    )


@app.websocket("/ws/emerge/world-pretend")
async def ws_emerge_world_pretend(websocket: WebSocket):
    await _ws_job_cmd(websocket, "world_updates", {})


@app.websocket("/ws/emerge/sync")
async def ws_emerge_sync(
    websocket: WebSocket,
    approval_request_id: str = Query(default=""),
    approval_token: str = Query(default=""),
):
    await _ws_job_cmd(
        websocket,
        "emerge_sync",
        {
            "approval_request_id": approval_request_id,
            "approval_token": approval_token,
        },
    )


@app.websocket("/ws/jobs/{job_id}")
async def ws_job_attach(websocket: WebSocket, job_id: str):
    if not await _ws_require_auth(websocket):
        return
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
        try:
            await websocket.close()
        except Exception:
            pass


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
async def job_cancel(auth: Auth, job_id: str, request: Request):
    body = await _json_object_body(request)
    if isinstance(body, JSONResponse):
        return body
    data = await query_one(
        "job_cancel",
        {
            "job_id": job_id,
            "approval_request_id": str(body.get("approval_request_id", "")).strip(),
            "approval_token": str(body.get("approval_token", "")).strip(),
        },
    )
    if "error" in data:
        return JSONResponse(status_code=404 if data["error"] == "job not found" else 400, content=data)
    return data


@app.websocket("/ws/emerge/autounmask")
async def ws_emerge_autounmask(
    websocket: WebSocket,
    atom: str = Query(default=""),
    approval_request_id: str = Query(default=""),
    approval_token: str = Query(default=""),
):
    await _ws_emerge(
        websocket,
        "emerge_autounmask",
        atom,
        {
            "approval_request_id": approval_request_id,
            "approval_token": approval_token,
        },
    )


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
async def history_delete(auth: Auth, job_id: str, request: Request):
    body = await _json_object_body(request)
    if isinstance(body, JSONResponse):
        return body
    data = await query_one(
        "history_delete",
        {
            "job_id": job_id,
            "approval_request_id": str(body.get("approval_request_id", "")).strip(),
            "approval_token": str(body.get("approval_token", "")).strip(),
        },
    )
    if "error" in data:
        return JSONResponse(status_code=404 if data["error"] == "not found" else 400, content=data)
    return data


@app.post("/api/history/purge")
async def history_purge(auth: Auth, request: Request):
    body = await _json_object_body(request)
    if isinstance(body, JSONResponse):
        return body
    try:
        days = max(int(body.get("days", 30)), 1)
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "days must be an integer"})
    data = await query_one(
        "history_purge",
        {
            "days": days,
            "approval_request_id": str(body.get("approval_request_id", "")).strip(),
            "approval_token": str(body.get("approval_token", "")).strip(),
        },
    )
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
    body = await _json_object_body(request)
    if isinstance(body, JSONResponse):
        return body
    cfg_file = body.get("cfg_file", "")
    action = body.get("action", "")
    data = await query_one(
        "etc_update_resolve",
        {
            "cfg_file": cfg_file,
            "action": action,
            "approval_request_id": str(body.get("approval_request_id", "")).strip(),
            "approval_token": str(body.get("approval_token", "")).strip(),
        },
    )
    return data


# ---------------------------------------------------------------------------
# Overlay management
# ---------------------------------------------------------------------------

@app.get("/api/overlays")
async def overlay_list(auth: Auth):
    results = await query_all("overlay_list", {})
    return [r for r in results if "name" in r]


@app.get("/api/overlays/config")
async def overlay_config(auth: Auth):
    return {"add_enabled": _overlay_add_enabled()}


@app.post("/api/overlays")
async def overlay_add(auth: Auth, request: Request):
    if not _overlay_add_enabled():
        return JSONResponse(status_code=403, content={"error": "overlay add is disabled; set ARBOR_ENABLE_OVERLAY_ADD=1 to enable it"})
    body = await _json_object_body(request)
    if isinstance(body, JSONResponse):
        return body
    name      = str(body.get("name", "")).strip()
    sync_type = str(body.get("sync_type", "git")).strip()
    sync_uri  = str(body.get("sync_uri", "")).strip()
    approve_danger = bool(body.get("approve_danger", False))
    approval_text = str(body.get("approval_text", "")).strip()
    data = await query_one("overlay_add", {
        "name": name,
        "sync_type": sync_type,
        "sync_uri": sync_uri,
        "approve_danger": approve_danger,
        "approval_text": approval_text,
        "approval_request_id": str(body.get("approval_request_id", "")).strip(),
        "approval_token": str(body.get("approval_token", "")).strip(),
    })
    if "error" in data:
        return JSONResponse(status_code=400, content=data)
    return data


@app.delete("/api/overlays/{name}")
async def overlay_remove(auth: Auth, name: str, request: Request, purge: int = Query(default=0)):
    body = await _json_object_body(request)
    if isinstance(body, JSONResponse):
        return body
    data = await query_one("overlay_remove", {
        "name": name,
        "purge": bool(purge),
        "approve_danger": bool(body.get("approve_danger", False)),
        "approval_text": str(body.get("approval_text", "")).strip(),
        "approval_request_id": str(body.get("approval_request_id", "")).strip(),
        "approval_token": str(body.get("approval_token", "")).strip(),
    })
    if "error" in data:
        return JSONResponse(status_code=400, content=data)
    return data


@app.websocket("/ws/overlays/sync/{name}")
async def ws_overlay_sync(
    websocket: WebSocket,
    name: str,
    approval_request_id: str = Query(default=""),
    approval_token: str = Query(default=""),
):
    if not await _ws_require_auth(websocket):
        return
    try:
        job_id = None
        async for chunk in query(
            "overlay_sync",
            {
                "name": name,
                "approval_request_id": approval_request_id,
                "approval_token": approval_token,
            },
        ):
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
        try:
            await websocket.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# WebSocket — streaming endpoints
# ---------------------------------------------------------------------------

@app.websocket("/ws/updates")
async def ws_world_updates(websocket: WebSocket):
    if not await _ws_require_auth(websocket):
        return
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
        try:
            await websocket.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Serve frontend static files
# ---------------------------------------------------------------------------

# Search order: ARBOR_STATIC_DIR env, install paths, repo dev paths.
# Alpine (no-build) layout has files directly in /usr/lib/arbor/frontend/ and
# in the repository under frontend/alpine/. The old dist/ layout is kept as a
# compatibility fallback.
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
