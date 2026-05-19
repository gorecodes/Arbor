from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Literal


OriginType = Literal[
    "profile_defaults",
    "make_conf",
    "profile_package.use",
    "user_package.use",
]

_USE_TOKEN_RE = re.compile(r"^-?[A-Za-z0-9][A-Za-z0-9+_@-]*$")
_USE_DESC_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9+_@-]*)\s+-\s+(.+)$")


@dataclass(frozen=True)
class ResolvedPackage:
    cp: str
    cpv: str
    installed: bool
    iuse_order: tuple[str, ...]
    default_enabled: dict[str, bool]


@dataclass(frozen=True)
class UseMutation:
    flag: str
    enabled: bool
    origin_type: OriginType
    origin_file: str
    source_atom: str | None
    token: str
    sequence: int

    def as_dict(self) -> dict[str, object]:
        return {
            "flag": self.flag,
            "enabled": self.enabled,
            "origin_type": self.origin_type,
            "origin_file": self.origin_file,
            "source_atom": self.source_atom,
            "token": self.token,
            "sequence": self.sequence,
        }


def _iter_config_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []

    files: list[Path] = []
    for child in sorted(path.rglob("*")):
        if not child.is_file():
            continue
        name = child.name
        if name.startswith(".") or name.endswith("~"):
            continue
        files.append(child)
    return files


def _split_use_tokens(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        parts = shlex.split(raw, comments=False, posix=True)
    except ValueError:
        parts = raw.split()

    tokens: list[str] = []
    for part in parts:
        if not part or "$" in part:
            continue
        if part == "-*" or _USE_TOKEN_RE.match(part):
            tokens.append(part)
    return tokens


def _load_use_assignment(path: Path) -> list[str]:
    from portage.util import getconfig

    try:
        config = getconfig(
            str(path),
            tolerant=True,
            allow_sourcing=False,
            expand=False,
            recursive=False,
        )
    except Exception:
        return []
    if not config:
        return []
    return _split_use_tokens(config.get("USE"))


def _iter_package_use_entries(path: Path, cpv: str) -> list[tuple[str, str, list[str]]]:
    from portage.dep import Atom, match_from_list

    matches: list[tuple[str, str, list[str]]] = []
    for cfg_path in _iter_config_files(path):
        try:
            with cfg_path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    atom_text, raw_tokens = parts[0], parts[1:]
                    try:
                        atom = Atom(atom_text, allow_wildcard=True, allow_repo=True)
                    except Exception:
                        continue
                    if not match_from_list(atom, [cpv]):
                        continue
                    tokens = _split_use_tokens(" ".join(raw_tokens))
                    if not tokens:
                        continue
                    matches.append((str(cfg_path), atom_text, tokens))
        except OSError:
            continue
    return matches


def _iter_package_use_lines(path: Path) -> list[tuple[str, str, list[str]]]:
    from portage.dep import Atom

    entries: list[tuple[str, str, list[str]]] = []
    for cfg_path in _iter_config_files(path):
        try:
            with cfg_path.open("r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    atom_text, raw_tokens = parts[0], parts[1:]
                    try:
                        Atom(atom_text, allow_wildcard=True, allow_repo=True)
                    except Exception:
                        continue
                    tokens = _split_use_tokens(" ".join(raw_tokens))
                    if not tokens:
                        continue
                    entries.append((str(cfg_path), atom_text, tokens))
        except OSError:
            continue
    return entries


def _group_package_use_entries(path: Path, target: dict[str, list[tuple[str, str, list[str], object]]]) -> None:
    from portage.dep import Atom

    for origin_file, atom_text, tokens in _iter_package_use_lines(path):
        try:
            atom = Atom(atom_text, allow_wildcard=True, allow_repo=True)
        except Exception:
            continue
        if not atom.cp or "/" not in atom.cp:
            continue
        target.setdefault(atom.cp, []).append((origin_file, atom_text, tokens, atom))


def _apply_grouped_package_use_entries(
    histories: dict[str, list[UseMutation]],
    valid_flags: tuple[str, ...],
    cpv: str,
    grouped_entries: dict[str, list[tuple[str, str, list[str], object]]],
    origin_type: OriginType,
    sequence: int,
) -> int:
    from portage.dep import match_from_list
    from portage.versions import cpv_getkey

    cp = cpv_getkey(cpv) or cpv
    for origin_file, atom_text, tokens, atom in grouped_entries.get(cp, []):
        try:
            if not match_from_list(atom, [cpv]):
                continue
        except Exception:
            continue
        sequence = _apply_tokens(
            histories,
            valid_flags,
            tokens,
            origin_type,
            origin_file,
            sequence,
            source_atom=atom_text,
        )
    return sequence


def _resolve_package(category: str, package_name: str) -> ResolvedPackage:
    import portage

    cp = f"{category}/{package_name}"
    vdb = portage.db[portage.root]["vartree"].dbapi
    porttree = portage.db[portage.root]["porttree"].dbapi

    installed_matches = vdb.match(cp)
    if installed_matches:
        cpv = portage.best(installed_matches)
        iuse_raw = vdb.aux_get(cpv, ["IUSE"])[0]
        installed = True
    else:
        visible_matches = porttree.match(cp)
        if visible_matches:
            cpv = portage.best(visible_matches)
        else:
            cp_list = porttree.cp_list(cp)
            if not cp_list:
                raise LookupError("package not found")
            cpv = portage.best(cp_list)
        iuse_raw = porttree.aux_get(cpv, ["IUSE"])[0]
        installed = False

    iuse_order: list[str] = []
    default_enabled: dict[str, bool] = {}
    for token in iuse_raw.split():
        flag = token.lstrip("+-")
        if not flag or flag in default_enabled:
            continue
        iuse_order.append(flag)
        default_enabled[flag] = token.startswith("+")

    return ResolvedPackage(
        cp=cp,
        cpv=cpv,
        installed=installed,
        iuse_order=tuple(iuse_order),
        default_enabled=default_enabled,
    )


def _use_context() -> tuple[Path, tuple[str, ...]]:
    import portage

    config_root = Path(portage.settings.get("PORTAGE_CONFIGROOT") or "/")
    profile_chain = tuple(str(Path(profile)) for profile in portage.settings.profiles)
    return config_root, profile_chain


def _read_use_desc_file(path: Path, prefix: str = "") -> dict[str, str]:
    descriptions: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                match = _USE_DESC_RE.match(line)
                if not match:
                    continue
                flag_name, description = match.groups()
                name = f"{prefix}{flag_name}" if prefix else flag_name
                descriptions[name] = " ".join(description.split())
    except OSError:
        return {}
    return descriptions


def _flag_descriptions(cpv: str) -> dict[str, str]:
    import portage
    from portage.xml.metadata import MetaDataXML

    porttree = portage.db[portage.root]["porttree"].dbapi

    try:
        ebuild_path = Path(porttree.findname(cpv))
    except Exception:
        return {}

    repo_root = ebuild_path.parents[2]
    descriptions: dict[str, str] = {}

    descriptions.update(_read_use_desc_file(repo_root / "profiles" / "use.desc"))

    desc_dir = repo_root / "profiles" / "desc"
    if desc_dir.is_dir():
        for desc_file in sorted(desc_dir.glob("*.desc")):
            descriptions.update(_read_use_desc_file(desc_file, prefix=f"{desc_file.stem}_"))

    metadata_path = ebuild_path.parent / "metadata.xml"
    try:
        for use_flag in MetaDataXML(str(metadata_path), herds="ignore").use():
            if use_flag.name and use_flag.description:
                descriptions[use_flag.name] = " ".join(str(use_flag.description).split())
    except Exception:
        pass

    return descriptions


def _forced_and_masked_flags(cpv: str) -> tuple[frozenset[str], frozenset[str]]:
    import portage

    use_manager = portage.settings._use_manager
    try:
        forced_flags = frozenset(use_manager.getUseForce(cpv))
    except Exception:
        forced_flags = frozenset()
    try:
        masked_flags = frozenset(use_manager.getUseMask(cpv))
    except Exception:
        masked_flags = frozenset()
    return forced_flags, masked_flags


def _effective_source(flag: str, origin_type: OriginType | None, forced_flags: frozenset[str], masked_flags: frozenset[str]) -> str:
    if flag in forced_flags:
        return "forced"
    if flag in masked_flags:
        return "masked"
    if origin_type is None:
        return "default"
    if origin_type in {"profile_package.use", "user_package.use"}:
        return "package.use"
    if origin_type == "make_conf":
        return "make.conf"
    return "profile"


def _apply_tokens(
    histories: dict[str, list[UseMutation]],
    valid_flags: tuple[str, ...],
    tokens: list[str],
    origin_type: OriginType,
    origin_file: str,
    sequence: int,
    source_atom: str | None = None,
) -> int:
    valid_set = set(valid_flags)

    for token in tokens:
        if token == "-*":
            for flag in valid_flags:
                sequence += 1
                histories[flag].append(
                    UseMutation(
                        flag=flag,
                        enabled=False,
                        origin_type=origin_type,
                        origin_file=origin_file,
                        source_atom=source_atom,
                        token=token,
                        sequence=sequence,
                    )
                )
            continue

        enabled = not token.startswith("-")
        flag = token[1:] if not enabled else token
        if flag not in valid_set:
            continue

        sequence += 1
        histories[flag].append(
            UseMutation(
                flag=flag,
                enabled=enabled,
                origin_type=origin_type,
                origin_file=origin_file,
                source_atom=source_atom,
                token=token,
                sequence=sequence,
            )
        )
    return sequence


def _apply_global_tokens(
    histories: dict[str, list[UseMutation]],
    flag_order: list[str],
    tokens: list[str],
    origin_type: OriginType,
    origin_file: str,
    sequence: int,
) -> int:
    for token in tokens:
        if token == "-*":
            for flag in list(flag_order):
                sequence += 1
                histories[flag].append(
                    UseMutation(
                        flag=flag,
                        enabled=False,
                        origin_type=origin_type,
                        origin_file=origin_file,
                        source_atom=None,
                        token=token,
                        sequence=sequence,
                    )
                )
            continue

        enabled = not token.startswith("-")
        flag = token[1:] if not enabled else token
        if not flag:
            continue
        if flag not in histories:
            histories[flag] = []
            flag_order.append(flag)

        sequence += 1
        histories[flag].append(
            UseMutation(
                flag=flag,
                enabled=enabled,
                origin_type=origin_type,
                origin_file=origin_file,
                source_atom=None,
                token=token,
                sequence=sequence,
            )
        )
    return sequence


def trace_global_use_flag_audit() -> dict[str, object]:
    config_root, profile_chain = _use_context()
    histories: dict[str, list[UseMutation]] = {}
    flag_order: list[str] = []
    sequence = 0

    for profile in profile_chain:
        make_defaults = Path(profile) / "make.defaults"
        sequence = _apply_global_tokens(
            histories,
            flag_order,
            _load_use_assignment(make_defaults),
            "profile_defaults",
            str(make_defaults),
            sequence,
        )

    make_conf = config_root / "etc/portage/make.conf"
    sequence = _apply_global_tokens(
        histories,
        flag_order,
        _load_use_assignment(make_conf),
        "make_conf",
        str(make_conf),
        sequence,
    )

    flags: list[dict[str, object]] = []
    for flag in sorted(flag_order):
        history = histories.get(flag, [])
        if not history:
            continue
        winner = history[-1]
        flags.append(
            {
                "name": flag,
                "enabled": winner.enabled,
                "final_status": "enabled" if winner.enabled else "disabled",
                "source": _effective_source(flag, winner.origin_type, frozenset(), frozenset()),
                "origin_type": winner.origin_type,
                "origin_file": winner.origin_file,
                "history": [entry.as_dict() for entry in history],
            }
        )

    return {
        "profile_chain": list(profile_chain),
        "flags": flags,
        "total": len(flags),
    }


def _trace_installed_flag_usage() -> dict[str, dict[str, object]]:
    import portage
    from portage.versions import cpv_getkey

    config_root, profile_chain = _use_context()
    vdb = portage.db[portage.root]["vartree"].dbapi
    profile_defaults = [
        (str(Path(profile) / "make.defaults"), _load_use_assignment(Path(profile) / "make.defaults"))
        for profile in profile_chain
    ]
    make_conf = config_root / "etc/portage/make.conf"
    make_conf_tokens = _load_use_assignment(make_conf)
    profile_package_entries: dict[str, list[tuple[str, str, list[str], object]]] = {}
    user_package_entries: dict[str, list[tuple[str, str, list[str], object]]] = {}

    for profile in profile_chain:
        _group_package_use_entries(Path(profile) / "package.use", profile_package_entries)
    _group_package_use_entries(config_root / "etc/portage/package.use", user_package_entries)

    usage: dict[str, dict[str, object]] = {}

    for cpv in sorted(vdb.cpv_all()):
        try:
            iuse_raw, use_raw = vdb.aux_get(cpv, ["IUSE", "USE"])
        except Exception:
            continue

        cp = cpv_getkey(cpv) or cpv
        built_enabled_flags = set(use_raw.split())
        iuse_order: list[str] = []
        default_enabled: dict[str, bool] = {}
        for token in iuse_raw.split():
            flag = token.lstrip("+-")
            if not flag or flag in default_enabled:
                continue
            iuse_order.append(flag)
            default_enabled[flag] = token.startswith("+")

        if not iuse_order:
            continue

        histories: dict[str, list[UseMutation]] = {
            flag: [] for flag in iuse_order
        }
        valid_flags = tuple(iuse_order)
        sequence = 0

        for origin_file, tokens in profile_defaults:
            sequence = _apply_tokens(
                histories,
                valid_flags,
                tokens,
                "profile_defaults",
                origin_file,
                sequence,
            )

        sequence = _apply_tokens(
            histories,
            valid_flags,
            make_conf_tokens,
            "make_conf",
            str(make_conf),
            sequence,
        )

        sequence = _apply_grouped_package_use_entries(
            histories,
            valid_flags,
            cpv,
            profile_package_entries,
            "profile_package.use",
            sequence,
        )
        sequence = _apply_grouped_package_use_entries(
            histories,
            valid_flags,
            cpv,
            user_package_entries,
            "user_package.use",
            sequence,
        )

        forced_flags, masked_flags = _forced_and_masked_flags(cpv)

        for flag in iuse_order:
            configured_enabled = default_enabled.get(flag, False)
            origin_type: OriginType | None = None
            origin_file: str | None = None
            if histories[flag]:
                configured_enabled = histories[flag][-1].enabled
                origin_type = histories[flag][-1].origin_type
                origin_file = histories[flag][-1].origin_file

            configured_source = _effective_source(flag, origin_type, forced_flags, masked_flags)
            if configured_source == "forced":
                configured_enabled = True
            elif configured_source == "masked":
                configured_enabled = False

            built_enabled = flag in built_enabled_flags
            mismatch = built_enabled != configured_enabled

            flag_usage = usage.setdefault(
                flag,
                {
                    "installed_support_count": 0,
                    "installed_enabled_count": 0,
                    "installed_disabled_count": 0,
                    "mismatch_count": 0,
                    "installed_packages_enabled": [],
                    "installed_packages_disabled": [],
                },
            )

            package_entry = {
                "cp": cp,
                "cpv": cpv,
                "installed": True,
                "enabled": built_enabled,
                "configured_enabled": configured_enabled,
                "configured_source": configured_source,
                "configured_origin_type": origin_type,
                "configured_origin_file": origin_file,
                "default_on": default_enabled.get(flag, False),
                "forced": flag in forced_flags,
                "masked": flag in masked_flags,
                "mismatch": mismatch,
            }

            flag_usage["installed_support_count"] += 1
            if mismatch:
                flag_usage["mismatch_count"] += 1
            if built_enabled:
                flag_usage["installed_enabled_count"] += 1
                flag_usage["installed_packages_enabled"].append(package_entry)
            else:
                flag_usage["installed_disabled_count"] += 1
                flag_usage["installed_packages_disabled"].append(package_entry)

    for flag_usage in usage.values():
        flag_usage["installed_packages_enabled"].sort(key=lambda item: item["cp"])
        flag_usage["installed_packages_disabled"].sort(key=lambda item: item["cp"])

    return usage


def _make_flag_audit_entry(name: str) -> dict[str, object]:
    return {
        "name": name,
        "description": "",
        "has_global": False,
        "global_enabled": None,
        "global_status": None,
        "global_source": None,
        "global_origin_type": None,
        "global_origin_file": None,
        "global_history": [],
        "package_override_count": 0,
        "package_override_enabled_count": 0,
        "package_override_disabled_count": 0,
        "local_count": 0,
        "enabled_count": 0,
        "disabled_count": 0,
        "installed_support_count": 0,
        "installed_enabled_count": 0,
        "installed_disabled_count": 0,
        "installed_usage_count": 0,
        "mismatch_count": 0,
        "forced_count": 0,
        "masked_count": 0,
        "override_packages_enabled": [],
        "override_packages_disabled": [],
        "override_packages": [],
        "packages_enabled": [],
        "packages_disabled": [],
        "packages": [],
        "installed_packages_enabled": [],
        "installed_packages_disabled": [],
    }


def trace_package_overrides_audit() -> dict[str, object]:
    from portage.dep import Atom

    config_root, profile_chain = _use_context()
    global_audit = trace_global_use_flag_audit()
    installed_flag_usage = _trace_installed_flag_usage()
    global_flags = {
        flag["name"]: {
            "enabled": flag["enabled"],
            "final_status": flag["final_status"],
            "origin_type": flag["origin_type"],
            "origin_file": flag["origin_file"],
            "history": flag["history"],
        }
        for flag in global_audit["flags"]
    }
    package_sources: dict[str, dict[str, set[str]]] = {}

    def _remember(cp: str, origin_type: OriginType, origin_file: str) -> None:
        if "/" not in cp:
            return
        data = package_sources.setdefault(
            cp,
            {
                "profile_package.use": set(),
                "user_package.use": set(),
            },
        )
        data[origin_type].add(origin_file)

    for profile in profile_chain:
        for origin_file, atom_text, _tokens in _iter_package_use_lines(Path(profile) / "package.use"):
            try:
                atom = Atom(atom_text, allow_wildcard=True, allow_repo=True)
            except Exception:
                continue
            if atom.cp:
                _remember(atom.cp, "profile_package.use", origin_file)

    for origin_file, atom_text, _tokens in _iter_package_use_lines(config_root / "etc/portage/package.use"):
        try:
            atom = Atom(atom_text, allow_wildcard=True, allow_repo=True)
        except Exception:
            continue
        if atom.cp:
            _remember(atom.cp, "user_package.use", origin_file)

    packages: list[dict[str, object]] = []
    counts = {
        "packages": 0,
        "flags": 0,
        "user_package_overrides": 0,
        "profile_package_overrides": 0,
        "enabled": 0,
        "disabled": 0,
    }

    for cp in sorted(package_sources):
        category, package_name = cp.split("/", 1)
        try:
            report = trace_use_flag_origins(category, package_name)
        except LookupError:
            continue

        flags: list[dict[str, object]] = []
        for flag in report["flags"]:
            history = flag.get("history") or []
            if not history:
                continue
            package_history = [
                step for step in history
                if step.get("origin_type") in {"profile_package.use", "user_package.use"}
            ]
            if not package_history:
                continue

            winner_type = flag.get("origin_type")
            if winner_type == "user_package.use":
                counts["user_package_overrides"] += 1
            elif winner_type == "profile_package.use":
                counts["profile_package_overrides"] += 1

            if flag.get("enabled"):
                counts["enabled"] += 1
            else:
                counts["disabled"] += 1

            counts["flags"] += 1
            flags.append(
                {
                    "name": flag["name"],
                    "description": flag.get("description") or "",
                    "enabled": flag["enabled"],
                    "final_status": "enabled" if flag["enabled"] else "disabled",
                    "source": flag.get("source") or _effective_source(
                        flag["name"],
                        flag.get("origin_type"),
                        frozenset(),
                        frozenset(),
                    ),
                    "forced": bool(flag.get("forced")),
                    "masked": bool(flag.get("masked")),
                    "default_on": bool(flag.get("default_on")),
                    "origin_type": flag.get("origin_type"),
                    "origin_file": flag.get("origin_file"),
                    "history": history,
                }
            )

        if not flags:
            continue

        counts["packages"] += 1
        packages.append(
            {
                "cp": report["cp"],
                "cpv": report["cpv"],
                "installed": report["installed"],
                "flags": sorted(flags, key=lambda item: item["name"]),
                "source_files": {
                    "profile_package.use": sorted(package_sources[cp]["profile_package.use"]),
                    "user_package.use": sorted(package_sources[cp]["user_package.use"]),
                },
            }
        )

    flag_index: dict[str, dict[str, object]] = {}

    for global_flag in global_audit["flags"]:
        entry = _make_flag_audit_entry(global_flag["name"])
        entry.update(
            {
                "has_global": True,
                "global_enabled": bool(global_flag["enabled"]),
                "global_status": global_flag["final_status"],
                "global_source": global_flag.get("source") or _effective_source(
                    global_flag["name"],
                    global_flag.get("origin_type"),
                    frozenset(),
                    frozenset(),
                ),
                "global_origin_type": global_flag.get("origin_type"),
                "global_origin_file": global_flag.get("origin_file"),
                "global_history": global_flag.get("history") or [],
            }
        )
        flag_index[global_flag["name"]] = entry
 
    for flag_name, usage in installed_flag_usage.items():
        entry = flag_index.setdefault(flag_name, _make_flag_audit_entry(flag_name))
        entry["installed_support_count"] = usage["installed_support_count"]
        entry["installed_enabled_count"] = usage["installed_enabled_count"]
        entry["installed_disabled_count"] = usage["installed_disabled_count"]
        entry["installed_usage_count"] = usage["installed_support_count"]
        entry["mismatch_count"] = usage.get("mismatch_count", 0)
        entry["installed_packages_enabled"] = usage["installed_packages_enabled"]
        entry["installed_packages_disabled"] = usage["installed_packages_disabled"]

    for package in packages:
        for flag in package["flags"]:
            entry = flag_index.setdefault(flag["name"], _make_flag_audit_entry(flag["name"]))

            if flag.get("description") and not entry["description"]:
                entry["description"] = flag["description"]

            package_entry = {
                "cp": package["cp"],
                "cpv": package["cpv"],
                "installed": package["installed"],
                "enabled": flag["enabled"],
                "source": flag.get("source"),
                "forced": bool(flag.get("forced")),
                "masked": bool(flag.get("masked")),
                "origin_type": flag.get("origin_type"),
                "origin_file": flag.get("origin_file"),
                "history": flag.get("history") or [],
            }

            entry["override_packages"].append(package_entry)
            entry["packages"].append(package_entry)
            entry["package_override_count"] += 1
            entry["local_count"] += 1
            if flag["enabled"]:
                entry["package_override_enabled_count"] += 1
                entry["enabled_count"] += 1
                entry["override_packages_enabled"].append(package_entry)
                entry["packages_enabled"].append(package_entry)
            else:
                entry["package_override_disabled_count"] += 1
                entry["disabled_count"] += 1
                entry["override_packages_disabled"].append(package_entry)
                entry["packages_disabled"].append(package_entry)
            if flag.get("forced"):
                entry["forced_count"] += 1
            if flag.get("masked"):
                entry["masked_count"] += 1

    flags = [
        {
            **entry,
            "override_packages": sorted(entry["override_packages"], key=lambda item: item["cp"]),
            "override_packages_enabled": sorted(entry["override_packages_enabled"], key=lambda item: item["cp"]),
            "override_packages_disabled": sorted(entry["override_packages_disabled"], key=lambda item: item["cp"]),
            "packages": sorted(entry["packages"], key=lambda item: item["cp"]),
            "packages_enabled": sorted(entry["packages_enabled"], key=lambda item: item["cp"]),
            "packages_disabled": sorted(entry["packages_disabled"], key=lambda item: item["cp"]),
        }
        for entry in flag_index.values()
    ]
    flags.sort(key=lambda item: item["name"])

    return {
        "profile_chain": list(profile_chain),
        "packages": packages,
        "flags": flags,
        "counts": counts,
        "global_flags_total": global_audit["total"],
        "global_flags": global_flags,
    }


def trace_use_flag_origins(category: str, package_name: str) -> dict[str, object]:
    import portage
    from portage.dep import Atom

    cp = f"{category}/{package_name}"
    Atom(cp, allow_wildcard=False, allow_repo=False)

    resolved = _resolve_package(category, package_name)
    config_root, profile_chain = _use_context()
    descriptions = _flag_descriptions(resolved.cpv)
    forced_flags, masked_flags = _forced_and_masked_flags(resolved.cpv)

    histories: dict[str, list[UseMutation]] = {
        flag: [] for flag in resolved.iuse_order
    }
    sequence = 0

    for profile in profile_chain:
        profile_path = Path(profile)
        make_defaults = profile_path / "make.defaults"
        sequence = _apply_tokens(
            histories,
            resolved.iuse_order,
            _load_use_assignment(make_defaults),
            "profile_defaults",
            str(make_defaults),
            sequence,
        )

    make_conf = config_root / "etc/portage/make.conf"
    sequence = _apply_tokens(
        histories,
        resolved.iuse_order,
        _load_use_assignment(make_conf),
        "make_conf",
        str(make_conf),
        sequence,
    )

    for profile in profile_chain:
        for origin_file, atom_text, tokens in _iter_package_use_entries(
            Path(profile) / "package.use",
            resolved.cpv,
        ):
            sequence = _apply_tokens(
                histories,
                resolved.iuse_order,
                tokens,
                "profile_package.use",
                origin_file,
                sequence,
                source_atom=atom_text,
            )

    for origin_file, atom_text, tokens in _iter_package_use_entries(
        config_root / "etc/portage/package.use",
        resolved.cpv,
    ):
        sequence = _apply_tokens(
            histories,
            resolved.iuse_order,
            tokens,
            "user_package.use",
            origin_file,
            sequence,
            source_atom=atom_text,
        )

    flags: list[dict[str, object]] = []
    for flag in resolved.iuse_order:
        history = histories[flag]
        final_enabled = resolved.default_enabled.get(flag, False)
        origin_type: OriginType | None = None
        origin_file: str | None = None
        if history:
            final_enabled = history[-1].enabled
            origin_type = history[-1].origin_type
            origin_file = history[-1].origin_file

        source = _effective_source(flag, origin_type, forced_flags, masked_flags)
        if source == "forced":
            final_enabled = True
        elif source == "masked":
            final_enabled = False

        flags.append(
            {
                "name": flag,
                "description": descriptions.get(flag, ""),
                "default_on": resolved.default_enabled.get(flag, False),
                "enabled": final_enabled,
                "source": source,
                "forced": flag in forced_flags,
                "masked": flag in masked_flags,
                "origin_type": origin_type,
                "origin_file": origin_file,
                "history": [entry.as_dict() for entry in history],
            }
        )

    return {
        "cp": resolved.cp,
        "cpv": resolved.cpv,
        "installed": resolved.installed,
        "profile_chain": list(profile_chain),
        "flags": flags,
    }
