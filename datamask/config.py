"""Masking configuration: TOML files, ``--rule`` arguments and salt handling."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import DatamaskError
from .masker import ON_ERROR
from .strategies import Strategy, build_strategy

DEFAULT_SALT_ENV = "DATAMASK_SALT"
_TOP_LEVEL_KEYS = {"salt", "seed", "on_error", "default", "columns"}


@dataclass
class Config:
    rules: dict[str, Strategy] = field(default_factory=dict)
    salt: str | None = None
    seed: int = 0
    on_error: str = "null"
    default: Strategy | None = None


def load_config(path: str) -> Config:
    """Parse a TOML config file. Unknown keys are errors, so typos do not pass silently."""
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        raise DatamaskError(f"config file not found: {path}") from None
    except OSError as exc:
        raise DatamaskError(f"cannot read config {path}: {exc.strerror or exc}") from None
    try:
        data = tomllib.loads(raw.decode("utf-8-sig"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise DatamaskError(f"{path}: invalid TOML ({exc})") from None
    return config_from_dict(data, source=path)


def config_from_dict(data: Mapping[str, Any], source: str = "config") -> Config:
    unknown = sorted(set(data) - _TOP_LEVEL_KEYS)
    if unknown:
        raise DatamaskError(
            f"{source}: unknown key(s) {', '.join(unknown)} "
            f"(allowed: {', '.join(sorted(_TOP_LEVEL_KEYS))})"
        )
    config = Config()
    if "salt" in data:
        if not isinstance(data["salt"], str) or not data["salt"]:
            raise DatamaskError(f"{source}: salt must be a non-empty string")
        config.salt = data["salt"]
    if "seed" in data:
        if isinstance(data["seed"], bool) or not isinstance(data["seed"], int):
            raise DatamaskError(f"{source}: seed must be an integer")
        config.seed = data["seed"]
    if "on_error" in data:
        if data["on_error"] not in ON_ERROR:
            raise DatamaskError(f"{source}: on_error must be one of {', '.join(ON_ERROR)}")
        config.on_error = data["on_error"]
    if "default" in data:
        config.default = _build(data["default"], "default", source)
    columns = data.get("columns", {})
    if not isinstance(columns, dict):
        raise DatamaskError(f"{source}: [columns] must be a table of column = rule")
    for column, spec in columns.items():
        config.rules[column] = _build(spec, column, source)
    return config


def _build(spec: Any, label: str, source: str) -> Strategy:
    try:
        return build_strategy(spec)
    except DatamaskError as exc:
        raise DatamaskError(f"{source}: rule for {label!r}: {exc}") from None


def parse_rule_args(items: Iterable[str]) -> dict[str, Strategy]:
    """Parse repeated ``--rule column=strategy[:k=v,...]`` arguments."""
    rules: dict[str, Strategy] = {}
    for item in items:
        column, eq, spec = item.partition("=")
        column = column.strip()
        if not eq or not column or not spec.strip():
            raise DatamaskError(f"--rule expects column=strategy, got {item!r}")
        try:
            rules[column] = build_strategy(spec.strip())
        except DatamaskError as exc:
            raise DatamaskError(f"--rule {column}: {exc}") from None
    return rules


def resolve_salt(
    config_salt: str | None = None,
    env_name: str = DEFAULT_SALT_ENV,
    salt_file: str | None = None,
) -> bytes | None:
    """Find the salt: salt file, then environment variable, then the config file."""
    if salt_file:
        try:
            text = Path(salt_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            reason = exc.strerror or exc
            raise DatamaskError(f"cannot read salt file {salt_file}: {reason}") from None
        if not text:
            raise DatamaskError(f"salt file {salt_file} is empty")
        return text.encode()
    from_env = os.environ.get(env_name)
    if from_env:
        return from_env.encode()
    if config_salt:
        return config_salt.encode()
    return None


def _toml_str(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_config(specs: Mapping[str, str], header: str = "") -> str:
    """Render ``column -> spec string`` pairs as a TOML config file."""
    lines = [header.rstrip(), ""] if header else []
    lines.append("[columns]")
    for column, spec in specs.items():
        lines.append(f"{_toml_str(column)} = {_toml_str(spec)}")
    return "\n".join(lines) + "\n"
