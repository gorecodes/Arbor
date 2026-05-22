from __future__ import annotations

import time
from contextvars import ContextVar
from typing import Any, Mapping

from .action_security import APPROVAL_REQUIRED, DESTRUCTIVE, PRETEND, READONLY, TRUST_HEAVY, classify_action

DEFAULT_STEP_UP_MAX_AGE_SECONDS = 120.0


class AuthorizationError(PermissionError):
    pass


class StepUpRequiredError(PermissionError):
    """Raised when an endpoint needs a recent re-auth (password or TOTP)."""
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


def require_recent_step_up(
    max_age_seconds: float = DEFAULT_STEP_UP_MAX_AGE_SECONDS,
    *,
    principal: Mapping[str, Any] | None = None,
) -> None:
    effective = dict(principal) if principal is not None else current_principal()
    step_up_at = effective.get("step_up_at")
    if step_up_at is None:
        raise StepUpRequiredError("step_up_required")
    try:
        age = time.time() - float(step_up_at)
    except (TypeError, ValueError):
        raise StepUpRequiredError("step_up_required")
    if age > max_age_seconds:
        raise StepUpRequiredError("step_up_required")


def require_recent_step_up_unless_cli_mode(
    max_age_seconds: float = DEFAULT_STEP_UP_MAX_AGE_SECONDS,
    *,
    principal: Mapping[str, Any] | None = None,
) -> None:
    """Enforce step-up unless the system is in ARBOR_APPROVAL_MODE=cli.

    In cli mode the secondary approval is the arbor-approve confirmation
    on a root shell, which is itself a stronger step-up than re-typing a
    password in the browser. Adding password step-up on top would just
    burn UX without adding security.

    In any other mode (currently only 'none' with explicit ack) we
    require a recent step-up: a session cookie alone is not enough to
    launch mutating actions.
    """
    # Local import: approval_mode imports config_env, not this module,
    # so there is no cycle, but it keeps the dependency direction tidy.
    from .approval_mode import ApprovalMode, effective_approval_mode

    if effective_approval_mode() is ApprovalMode.CLI:
        return
    require_recent_step_up(max_age_seconds, principal=principal)


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
