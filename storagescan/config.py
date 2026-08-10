"""User configuration. JSON, because Python 3.9 has no tomllib."""

from __future__ import annotations

import dataclasses
import json
import os
import posixpath
from dataclasses import dataclass
from typing import Optional, Tuple


class ConfigError(Exception):
    """Raised when a config file exists but cannot be used."""


@dataclass(frozen=True)
class Config:
    scan_paths: Tuple[str, ...] = ("~/",)
    exclude: Tuple[str, ...] = ()
    fast_depth: int = 6
    large_file_bytes: int = 1_073_741_824
    stale_days: int = 180
    trash_by_default: bool = True

    def expanded_scan_paths(self) -> Tuple[str, ...]:
        seen = []
        for raw in self.scan_paths:
            path = posixpath.normpath(os.path.expanduser(raw))
            if path not in seen:
                seen.append(path)
        return tuple(seen)

    def expanded_excludes(self) -> Tuple[str, ...]:
        return tuple(
            posixpath.normpath(os.path.expanduser(raw)) for raw in self.exclude
        )

    def is_excluded(self, path: str) -> bool:
        path = posixpath.normpath(path)
        for excluded in self.expanded_excludes():
            if path == excluded or path.startswith(excluded.rstrip("/") + "/"):
                return True
        return False


def default_config_path() -> str:
    return os.path.expanduser("~/.config/storagescan/config.json")


def load(path: Optional[str] = None) -> Config:
    """Load config, falling back to defaults when the file is absent."""
    path = path or default_config_path()
    if not os.path.exists(path):
        return Config()
    try:
        with open(path, "r") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ConfigError("could not read config {}: {}".format(path, exc))
    if not isinstance(payload, dict):
        raise ConfigError("config {} must contain a JSON object".format(path))

    known = {f.name for f in dataclasses.fields(Config)}
    kwargs = {}
    for key, value in payload.items():
        if key not in known:
            continue
        kwargs[key] = tuple(value) if isinstance(value, list) else value
    try:
        return Config(**kwargs)
    except TypeError as exc:
        raise ConfigError("invalid config {}: {}".format(path, exc))
