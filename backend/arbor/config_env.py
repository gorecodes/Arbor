from __future__ import annotations

import os
from pathlib import Path

_ENABLED_VALUES = {"1", "true", "yes", "on"}


def env_file_path() -> Path:
    return Path(os.environ.get("ARBOR_ENV_FILE", "/etc/arbor/arbor.env"))


def env_value(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is not None:
        return value
    try:
        for raw_line in env_file_path().read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            key, sep, file_value = line.partition("=")
            if sep and key.strip() == name:
                return file_value.strip().strip("\"'")
    except OSError:
        return default
    return default


def env_int(name: str, default: int) -> int:
    return int(env_value(name, str(default)))


def env_list(name: str, default: list[str] | tuple[str, ...] | None = None) -> list[str]:
    raw = env_value(name, "")
    if raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    return list(default or [])


def env_enabled(name: str) -> bool:
    return env_value(name).strip().lower() in _ENABLED_VALUES
