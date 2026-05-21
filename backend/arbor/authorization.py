from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Mapping

from .action_security import APPROVAL_REQUIRED, DESTRUCTIVE, PRETEND, READONLY, TRUST_HEAVY, classify_action


class AuthorizationError(PermissionError):
    pass


_KNOWN_DAEMON_COMMANDS = {
    "approval_request_approve",
    "approval_request_cancel",
    "approval_request_create",
    "approval_request_list",
    "approval_request_show",
    "dep_graph",
    "emerge_autounmask",
    "emerge_depclean",
    "emerge_depclean_pretend",
    "emerge_install",
    "emerge_pretend",
    "emerge_preserved_rebuild",
    "emerge_sync",
    "emerge_uninstall",
    "emerge_uninstall_pretend",
    "emerge_world_update",
    "etc_update_check",
    "etc_update_resolve",
    "global_use_flags_audit",
    "history_delete",
    "history_list",
    "history_log",
    "history_purge",
    "history_stats",
    "installed_packages",
    "job_attach",
    "job_cancel",
    "job_list",
    "job_status",
    "overlay_add",
    "overlay_list",
    "overlay_remove",
    "overlay_sync",
    "package_deps",
    "package_info",
    "package_search",
    "pkg_stats",
    "system_status",
    "use_flag_origins",
    "use_flags",
    "world_updates",
    "totp_status",
    "totp_enroll_begin",
    "totp_enroll_confirm",
    "totp_disable",
}

_ROLE_ALLOWED_CLASSES = {
    "owner": {READONLY, PRETEND, APPROVAL_REQUIRED, TRUST_HEAVY, DESTRUCTIVE},
    "operator": {READONLY, PRETEND, APPROVAL_REQUIRED},
    "viewer": {READONLY, PRETEND},
}
_ROLE_ORDER = {"viewer": 0, "operator": 1, "owner": 2}

_principal_ctx: ContextVar[dict[str, Any] | None] = ContextVar("arbor_principal", default=None)


def set_current_principal(principal: Mapping[str, Any] | None) -> None:
    if principal is None:
        _principal_ctx.set(None)
        return
    _principal_ctx.set(dict(principal))


def current_principal() -> dict[str, Any]:
    principal = _principal_ctx.get()
    if principal is None:
        raise AuthorizationError("authentication context is missing")
    return principal


def _principal_role(principal: Mapping[str, Any]) -> str:
    raw_role = str(principal.get("role", "")).strip().lower()
    if not raw_role:
        raise AuthorizationError("principal role is missing")
    return raw_role


def principal_role(principal: Mapping[str, Any] | None = None) -> str:
    effective = dict(principal) if principal is not None else current_principal()
    return _principal_role(effective)


def require_min_role(required_role: str, principal: Mapping[str, Any] | None = None) -> None:
    required = str(required_role).strip().lower()
    required_rank = _ROLE_ORDER.get(required)
    if required_rank is None:
        raise AuthorizationError(f"invalid required role '{required_role}'")
    current = principal_role(principal)
    current_rank = _ROLE_ORDER.get(current, _ROLE_ORDER["viewer"])
    if current_rank < required_rank:
        raise AuthorizationError(f"role '{current}' is not allowed for this endpoint")


def authorize_daemon_command(
    cmd: str,
    args: Mapping[str, Any] | None = None,
    *,
    principal: Mapping[str, Any] | None = None,
) -> None:
    if cmd not in _KNOWN_DAEMON_COMMANDS:
        raise AuthorizationError(f"command '{cmd}' is not allowed by web policy")

    effective = dict(principal) if principal is not None else current_principal()
    role = _principal_role(effective)
    allowed_classes = _ROLE_ALLOWED_CLASSES.get(role, {READONLY, PRETEND})
    action_class = classify_action(cmd, args)
    if action_class not in allowed_classes:
        raise AuthorizationError(f"role '{role}' cannot execute '{cmd}'")
