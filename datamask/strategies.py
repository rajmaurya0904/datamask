"""Masking strategies.

A strategy turns one cell into a safer cell. Empty cells (``None`` or ``""``) always pass
through untouched, because an empty value discloses nothing. A strategy that cannot make
sense of a value raises ``ValueError``; the masker then replaces the cell with ``None``
instead of letting the original through (see ``Masker`` for the policy).

Strategies are described by a short spec string, ``name`` or ``name:key=value,key=value``,
for example ``partial:keep_last=4`` or ``date:to=year``.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import random
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, ClassVar

from .errors import DatamaskError
from .generate import ALL_FIELDS, Generator
from .patterns import KINDS, scrub_text

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def text_of(value: Any) -> str:
    """Canonical text form of a cell, used for hashing and string masking."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def is_empty(value: Any) -> bool:
    return value is None or value == ""


@dataclass
class Context:
    """Secret material shared by all strategies in one run."""

    salt: bytes
    seed: int = 0

    def digest(self, label: str, value: str) -> bytes:
        msg = f"{label}\x00{value}".encode()
        return hmac.new(self.salt, msg, hashlib.sha256).digest()

    def rng_for(self, label: str, value: str) -> random.Random:
        return random.Random(int.from_bytes(self.digest(label, value), "big"))


class Strategy:
    """Base class. Subclasses set ``name``, ``params`` and implement ``apply``."""

    name: ClassVar[str] = ""
    summary: ClassVar[str] = ""
    params: ClassVar[dict[str, tuple[type, Any]]] = {}
    column_wise: ClassVar[bool] = False

    def __init__(self, **options: Any) -> None:
        self.options = {key: default for key, (_, default) in self.params.items()}
        self.options.update(options)

    def apply(self, value: Any, ctx: Context) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def apply_column(self, values: list[Any], ctx: Context) -> list[Any]:
        return [v if is_empty(v) else self.apply(v, ctx) for v in values]

    def validate(self) -> None:
        """Hook for subclasses to reject nonsensical option combinations."""


class Keep(Strategy):
    name = "keep"
    summary = "leave the column unchanged"

    def apply(self, value: Any, ctx: Context) -> Any:
        return value


class Nullify(Strategy):
    name = "nullify"
    summary = "replace every value with an empty cell"

    def apply(self, value: Any, ctx: Context) -> Any:
        return None


class Redact(Strategy):
    name = "redact"
    summary = "replace with fixed text"
    params = {"text": (str, "[REDACTED]")}

    def apply(self, value: Any, ctx: Context) -> Any:
        return self.options["text"]


class Drop(Strategy):
    name = "drop"
    summary = "remove the column from the output"

    def apply(self, value: Any, ctx: Context) -> Any:
        return None


class Hash(Strategy):
    name = "hash"
    summary = "salted HMAC-SHA256, hex, truncated (joinable, not reversible without the salt)"
    params = {"length": (int, 16), "fold": (bool, False)}

    def validate(self) -> None:
        if not 8 <= self.options["length"] <= 64:
            raise DatamaskError("hash: length must be between 8 and 64")

    def apply(self, value: Any, ctx: Context) -> Any:
        text = text_of(value)
        if self.options["fold"]:
            text = text.strip().casefold()
        return ctx.digest("hash", text).hex()[: self.options["length"]]


class Partial(Strategy):
    name = "partial"
    summary = "keep the first/last N letters and digits, mask the rest, keep separators"
    params = {"keep_first": (int, 0), "keep_last": (int, 0), "char": (str, "*")}

    def validate(self) -> None:
        if self.options["keep_first"] < 0 or self.options["keep_last"] < 0:
            raise DatamaskError("partial: keep_first and keep_last must not be negative")
        if len(self.options["char"]) != 1:
            raise DatamaskError("partial: char must be a single character")

    def apply(self, value: Any, ctx: Context) -> Any:
        text = text_of(value)
        positions = [i for i, c in enumerate(text) if c.isalnum()]
        first, last = self.options["keep_first"], self.options["keep_last"]
        if len(positions) <= first + last:
            visible: set[int] = set()  # too short to show anything safely
        else:
            visible = set(positions[:first]) | set(positions[len(positions) - last :])
        mask = self.options["char"]
        return "".join(
            c if (not c.isalnum() or i in visible) else mask for i, c in enumerate(text)
        )


class Email(Strategy):
    name = "email"
    summary = "mask the local part of an address, optionally keep the domain"
    params = {"keep": (int, 1), "keep_domain": (bool, True), "char": (str, "*")}

    def validate(self) -> None:
        if self.options["keep"] < 0:
            raise DatamaskError("email: keep must not be negative")
        if len(self.options["char"]) != 1:
            raise DatamaskError("email: char must be a single character")

    def apply(self, value: Any, ctx: Context) -> Any:
        text = text_of(value).strip()
        local, sep, domain = text.rpartition("@")
        if not sep or not local or not domain:
            raise ValueError("not an email address")
        keep = self.options["keep"]
        shown = local[:keep] if len(local) > keep else ""
        masked = shown + self.options["char"] * max(len(local) - len(shown), 3)
        return f"{masked}@{domain if self.options['keep_domain'] else 'masked.invalid'}"


class Scrub(Strategy):
    name = "scrub"
    summary = "keep free text but replace emails, IPs, cards, IBANs and phones with tokens"
    params = {"kinds": (str, "+".join(KINDS))}

    def validate(self) -> None:
        wanted = [k for k in self.options["kinds"].split("+") if k]
        bad = [k for k in wanted if k not in KINDS]
        if bad or not wanted:
            raise DatamaskError(
                f"scrub: kinds must be a '+'-joined subset of {'+'.join(KINDS)}"
                + (f" (got {', '.join(bad)})" if bad else "")
            )
        self.options["kinds"] = "+".join(wanted)

    def apply(self, value: Any, ctx: Context) -> Any:
        return scrub_text(text_of(value), tuple(self.options["kinds"].split("+")))


class Pseudonym(Strategy):
    name = "pseudonym"
    summary = "replace with a consistent fake value of the given kind (same input, same output)"
    params = {"kind": (str, ""), "locale": (str, "en")}

    def validate(self) -> None:
        kind = self.options["kind"]
        if kind == "name":
            self.options["kind"] = kind = "full_name"
        if not kind:
            raise DatamaskError("pseudonym: needs kind=<one of " + ", ".join(ALL_FIELDS) + ">")
        if kind not in ALL_FIELDS:
            raise DatamaskError(
                f"pseudonym: unknown kind {kind!r} (available: {', '.join(ALL_FIELDS)})"
            )
        Generator(locales=self.options["locale"])  # fail early on a bad locale

    def apply(self, value: Any, ctx: Context) -> Any:
        kind = self.options["kind"]
        text = text_of(value)
        seed = int.from_bytes(ctx.digest(f"pseudonym:{kind}", text), "big")
        gen = Generator(seed=seed, locales=self.options["locale"])
        person = gen.person()
        if kind == "email":
            local, _, domain = person["email"].partition("@")
            return f"{local}{gen.rng.randint(10, 9999)}@{domain}"
        return person[kind]


_DATE_FORMATS = ("%Y-%m-%d", "%d/%m/%Y", "%d.%m.%Y", "%Y/%m/%d")


def parse_date(text: str) -> date:
    text = text.strip()
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        pass
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"unrecognised date {text!r}")


class DateGeneralize(Strategy):
    name = "date"
    summary = "reduce a date to its year, month or decade"
    params = {"to": (str, "year")}

    def validate(self) -> None:
        if self.options["to"] not in {"year", "month", "decade"}:
            raise DatamaskError("date: to must be year, month or decade")

    def apply(self, value: Any, ctx: Context) -> Any:
        d = parse_date(text_of(value))
        to = self.options["to"]
        if to == "year":
            return f"{d.year:04d}"
        if to == "month":
            return f"{d.year:04d}-{d.month:02d}"
        start = d.year // 10 * 10
        return f"{start}s"


class Bucket(Strategy):
    name = "bucket"
    summary = "replace a number with the range it falls in, e.g. 34 -> 30-39"
    params = {"width": (int, 10)}

    def validate(self) -> None:
        if self.options["width"] < 1:
            raise DatamaskError("bucket: width must be at least 1")

    def apply(self, value: Any, ctx: Context) -> Any:
        try:
            number = float(text_of(value).replace(",", "."))
        except ValueError:
            raise ValueError("not a number") from None
        width = self.options["width"]
        low = int(number // width * width)
        return f"{low}-{low + width - 1}"


class Prefix(Strategy):
    name = "prefix"
    summary = "keep only the first N characters (postcodes, area codes)"
    params = {"keep": (int, 3)}

    def validate(self) -> None:
        if self.options["keep"] < 0:
            raise DatamaskError("prefix: keep must not be negative")

    def apply(self, value: Any, ctx: Context) -> Any:
        return text_of(value).strip().replace(" ", "")[: self.options["keep"]]


class Subnet(Strategy):
    name = "subnet"
    summary = "reduce an IP address to its network (IPv4 /24, IPv6 /48 by default)"
    params = {"v4": (int, 24), "v6": (int, 48)}

    def validate(self) -> None:
        if not 0 <= self.options["v4"] <= 32 or not 0 <= self.options["v6"] <= 128:
            raise DatamaskError("subnet: v4 must be 0-32 and v6 must be 0-128")

    def apply(self, value: Any, ctx: Context) -> Any:
        addr = ipaddress.ip_address(text_of(value).strip())
        bits = self.options["v4"] if addr.version == 4 else self.options["v6"]
        return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


class Noise(Strategy):
    name = "noise"
    summary = "perturb a number by up to +/-pct percent (same input, same output)"
    params = {"pct": (float, 10.0), "decimals": (int, -1)}

    def validate(self) -> None:
        if not 0 < self.options["pct"] <= 100:
            raise DatamaskError("noise: pct must be greater than 0 and at most 100")

    def apply(self, value: Any, ctx: Context) -> Any:
        text = text_of(value)
        try:
            number = float(text)
        except ValueError:
            raise ValueError("not a number") from None
        factor = 1 + ctx.rng_for("noise", text).uniform(-1, 1) * self.options["pct"] / 100
        result = number * factor
        decimals = self.options["decimals"]
        if decimals >= 0:
            return round(result, decimals)
        if re.fullmatch(r"-?\d+", text.strip()):
            return round(result)
        return round(result, 2)


class Shuffle(Strategy):
    name = "shuffle"
    summary = "permute the column's values among rows (breaks row linkage)"
    column_wise = True

    def apply(self, value: Any, ctx: Context) -> Any:  # pragma: no cover - column-wise only
        return value

    def apply_column(self, values: list[Any], ctx: Context) -> list[Any]:
        shuffled = list(values)
        random.Random(ctx.seed).shuffle(shuffled)
        return shuffled


_TYPES = (
    Keep, Drop, Nullify, Redact, Scrub, Hash, Partial, Email, Pseudonym, DateGeneralize,
    Bucket, Prefix, Subnet, Noise, Shuffle,
)
REGISTRY: dict[str, type[Strategy]] = {cls.name: cls for cls in _TYPES}


def _coerce(strategy: str, key: str, kind: type, raw: str) -> Any:
    try:
        if kind is bool:
            lowered = raw.strip().lower()
            if lowered in _TRUE:
                return True
            if lowered in _FALSE:
                return False
            raise ValueError
        if kind is int:
            return int(raw)
        if kind is float:
            return float(raw)
    except ValueError:
        raise DatamaskError(
            f"{strategy}: parameter {key} must be {kind.__name__}, got {raw!r}"
        ) from None
    return raw


def build_strategy(spec: str | dict[str, Any]) -> Strategy:
    """Create a strategy from ``"name:k=v,k=v"`` or ``{"strategy": name, **params}``."""
    raw_params: dict[str, Any]
    if isinstance(spec, dict):
        raw_params = dict(spec)
        name = raw_params.pop("strategy", None)
        if not isinstance(name, str):
            raise DatamaskError("a column rule table needs a 'strategy' key")
    elif isinstance(spec, str):
        name, _, rest = spec.partition(":")
        name = name.strip()
        raw_params = {}
        for part in filter(None, (p.strip() for p in rest.split(","))):
            key, eq, val = part.partition("=")
            if not eq:
                raise DatamaskError(f"{name}: expected key=value, got {part!r}")
            raw_params[key.strip()] = val
    else:
        raise DatamaskError(f"a column rule must be a string or table, got {type(spec).__name__}")
    if name not in REGISTRY:
        raise DatamaskError(f"unknown strategy {name!r} (available: {', '.join(REGISTRY)})")
    cls = REGISTRY[name]
    options: dict[str, Any] = {}
    for key, raw in raw_params.items():
        if key not in cls.params:
            accepted = ", ".join(cls.params) or "none"
            raise DatamaskError(f"{name}: unknown parameter {key!r} (accepted: {accepted})")
        kind = cls.params[key][0]
        if isinstance(raw, str):
            options[key] = _coerce(name, key, kind, raw)
        elif isinstance(raw, kind) or (kind is float and isinstance(raw, int)):
            options[key] = raw
        else:
            raise DatamaskError(f"{name}: parameter {key} must be {kind.__name__}, got {raw!r}")
    strategy = cls(**options)
    strategy.validate()
    return strategy
