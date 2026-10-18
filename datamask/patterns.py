"""Find PII-looking substrings in free text (emails, IPs, cards, IBANs, phones)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .checks import iban_valid, luhn_valid

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
CARD_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{2,5}){3,8}\b")
# A phone number must look like one: a leading "+" or a bracket / separator layout.
PHONE_RE = re.compile(
    r"(?<![\w+])(?<!\d[\s.-])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{1,5}\)[\s.-]?)?"
    r"\d[\d\s.-]{6,16}\d(?!\w)(?![\s.-]\d)"
)

KINDS = ("email", "ip", "card", "iban", "phone")
TOKENS = {"email": "[EMAIL]", "ip": "[IP]", "card": "[CARD]", "iban": "[IBAN]", "phone": "[PHONE]"}


@dataclass(frozen=True)
class Match:
    kind: str
    start: int
    end: int


def _digits(text: str) -> str:
    return "".join(c for c in text if c.isdigit())


def looks_like_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    return True


_DATEISH = re.compile(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}")


def looks_like_phone(text: str) -> bool:
    """A phone-ish string: 8-15 digits, and either a leading + or visible grouping."""
    stripped = text.strip()
    if _DATEISH.fullmatch(stripped) or _DATEISH.match(stripped):
        return False
    digits = _digits(stripped)
    if not 8 <= len(digits) <= 15:
        return False
    if not re.fullmatch(r"\+?[\d\s().\-]+", stripped):
        return False
    has_grouping = bool(re.search(r"[\s().\-]", stripped))
    return stripped.startswith("+") or has_grouping or len(digits) >= 10


def find_pii(text: str, kinds: tuple[str, ...] = KINDS) -> list[Match]:
    """Return non-overlapping matches, earlier kinds in ``KINDS`` winning ties."""
    found: list[Match] = []
    taken: list[tuple[int, int]] = []

    def free(start: int, end: int) -> bool:
        return all(end <= s or start >= e for s, e in taken)

    def add(kind: str, start: int, end: int) -> None:
        if free(start, end):
            found.append(Match(kind, start, end))
            taken.append((start, end))

    if "email" in kinds:
        for m in EMAIL_RE.finditer(text):
            add("email", m.start(), m.end())
    if "iban" in kinds:
        for m in IBAN_RE.finditer(text):
            if iban_valid(m.group()):
                add("iban", m.start(), m.end())
    if "card" in kinds:
        for m in CARD_RE.finditer(text):
            if luhn_valid(_digits(m.group())):
                add("card", m.start(), m.end())
    if "ip" in kinds:
        for m in IPV4_RE.finditer(text):
            if looks_like_ip(m.group()):
                add("ip", m.start(), m.end())
        for m in IPV6_RE.finditer(text):
            if looks_like_ip(m.group()):
                add("ip", m.start(), m.end())
    if "phone" in kinds:
        for m in PHONE_RE.finditer(text):
            if looks_like_phone(m.group()):
                add("phone", m.start(), m.end())
    return sorted(found, key=lambda m: m.start)


def scrub_text(text: str, kinds: tuple[str, ...] = KINDS) -> str:
    """Replace every match with a token such as ``[EMAIL]``."""
    out: list[str] = []
    pos = 0
    for m in find_pii(text, kinds):
        out.append(text[pos : m.start])
        out.append(TOKENS[m.kind])
        pos = m.end
    out.append(text[pos:])
    return "".join(out)
