from __future__ import annotations

from typing import Any, Mapping

READONLY = "readonly"
PRETEND = "pretend"
APPROVAL_REQUIRED = "approval_required"
DESTRUCTIVE = "destructive"
TRUST_HEAVY = "trust_heavy"

_READONLY_COMMANDS = {
    "approval_request_create",
    "approval_request_approve",
    "approval_request_cancel",
    "approval_request_list",
    "approval_request_show",
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
    "job_attach",
    "job_status",
    "job_list",
    "history_list",
    "history_log",
    "history_stats",
    "overlay_list",
    "totp_status",
    "news_list",
    "news_mark_read",
    "news_mark_all_read",
    "glsa_list",
    "eclean_pretend",
    "snapshot_export",
}

_PRETEND_COMMANDS = {
    "emerge_pretend",
    "emerge_uninstall_pretend",
    "emerge_depclean_pretend",
}

_APPROVAL_REQUIRED_COMMANDS = {
    "emerge_install",
    "emerge_autounmask",
    "emerge_uninstall",
    "emerge_world_update",
    "emerge_preserved_rebuild",
    "emerge_sync",
    "overlay_sync",
    "job_cancel",
    "history_delete",
    "history_purge",
    "eclean_run",
    "snapshot_import",
}

_TARGET_KEYS = ("atom", "name", "cfg_file", "job_id")


def _args_dict(args: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(args or {})


def classify_action(cmd: str, args: Mapping[str, Any] | None = None) -> str:
    data = _args_dict(args)
    if cmd in _READONLY_COMMANDS:
        return READONLY
    if cmd in _PRETEND_COMMANDS:
        return PRETEND
    if cmd == "overlay_add":
        return TRUST_HEAVY
    if cmd in {"totp_enroll_begin", "totp_enroll_confirm", "totp_disable"}:
        return TRUST_HEAVY
    if cmd == "overlay_remove":
        return DESTRUCTIVE if bool(data.get("purge", False)) else TRUST_HEAVY
    if cmd == "etc_update_check":
        return READONLY
    if cmd == "etc_update_resolve":
        return TRUST_HEAVY if data.get("action") == "replace" else DESTRUCTIVE
    if cmd == "overlays_config":
        return READONLY
    if cmd in _APPROVAL_REQUIRED_COMMANDS:
        return APPROVAL_REQUIRED
    # Fail closed for any command that is not explicitly read-only or pretend.
    return APPROVAL_REQUIRED


def approval_required_for_action(cmd: str, args: Mapping[str, Any] | None = None) -> bool:
    return classify_action(cmd, args) in {APPROVAL_REQUIRED, DESTRUCTIVE, TRUST_HEAVY}


def action_target(cmd: str, args: Mapping[str, Any] | None = None) -> str:
    data = _args_dict(args)
    if cmd == "overlay_add":
        name = str(data.get("name", "")).strip()
        sync_uri = str(data.get("sync_uri", "")).strip()
        return f"{name} {sync_uri}".strip()
    if cmd == "overlay_remove":
        return str(data.get("name", "")).strip()
    if cmd == "etc_update_resolve":
        return str(data.get("cfg_file", "")).strip()
    if cmd == "history_purge":
        days = data.get("days")
        return f"{days}d" if days is not None else ""
    for key in _TARGET_KEYS:
        value = data.get(key)
        if value:
            return str(value).strip()
    return ""


def action_metadata(cmd: str, args: Mapping[str, Any] | None = None) -> dict[str, Any]:
    action_class = classify_action(cmd, args)
    target = action_target(cmd, args)
    approval_required = action_class in {APPROVAL_REQUIRED, DESTRUCTIVE, TRUST_HEAVY}
    metadata = {
        "action_cmd": cmd,
        "action_class": action_class,
        "approval_required": approval_required,
        "confirmation_tier": (
            "none"
            if not approval_required
            else "strong"
            if action_class in {DESTRUCTIVE, TRUST_HEAVY}
            else "standard"
        ),
    }
    if target:
        metadata["action_target"] = target
    return metadata


def infer_job_action(cmd_kind: str, atom: str) -> tuple[str, dict[str, Any]]:
    if cmd_kind == "install":
        return "emerge_install", {"atom": atom}
    if cmd_kind == "uninstall":
        target = atom.removeprefix("uninstall:")
        return "emerge_uninstall", {"atom": target}
    if cmd_kind == "world":
        return "emerge_world_update", {}
    if cmd_kind == "depclean-pretend":
        return "emerge_depclean_pretend", {}
    if cmd_kind == "depclean":
        return "emerge_depclean", {}
    if cmd_kind == "preserved-rebuild":
        return "emerge_preserved_rebuild", {}
    if cmd_kind == "sync":
        if atom.startswith("@sync:"):
            return "overlay_sync", {"name": atom.partition(":")[2]}
        return "emerge_sync", {}
    return "", {}
