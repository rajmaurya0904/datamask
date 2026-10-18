"""Seeded generator for synthetic people.

Every value is invented. Identifiers are chosen so they cannot belong to a real person
where a reserved range exists (documentation IP addresses, ``.example`` mail domains,
fictional phone ranges, a never-issued UK National Insurance prefix) and are only
checksum-valid, never registered, where one does not (IBAN, card number).
"""

from __future__ import annotations

import random
import unicodedata
import uuid
from collections.abc import Iterator, Sequence
from datetime import date, timedelta
from typing import Any

from .checks import iban_check_digits, luhn_check_digit
from .data import DOC_IPV4_PREFIXES, EMAIL_DOMAINS, LOCALES, OCCUPATIONS, Locale
from .errors import DatamaskError

ALL_FIELDS: tuple[str, ...] = (
    "id", "first_name", "last_name", "full_name", "email", "phone", "dob", "street", "city",
    "postcode", "country", "national_id", "iban", "card_number", "ip_address", "occupation",
    "signup_date", "marketing_consent", "consent_date",
)
DEFAULT_FIELDS: tuple[str, ...] = tuple(
    f for f in ALL_FIELDS if f not in {"full_name", "occupation"}
)

_TRANSLIT = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss", "æ": "ae", "œ": "oe"}
_UK_INWARD = "ABDEFGHJLNPQRSTUWXYZ"
_DE_ID_CHARS = "CFGHJKLMNPRTVWXYZ0123456789"
_NEVER_NULL = {"id", "marketing_consent"}


def slugify(text: str) -> str:
    """Lowercase ASCII slug used for mail local-parts: 'Müller' -> 'mueller'."""
    lowered = text.lower()
    for src, dst in _TRANSLIT.items():
        lowered = lowered.replace(src, dst)
    folded = unicodedata.normalize("NFKD", lowered).encode("ascii", "ignore").decode()
    return "".join(c for c in folded if c.isalnum())


def parse_locales(spec: str | Sequence[str]) -> list[Locale]:
    names = [s.strip().lower() for s in spec.split(",")] if isinstance(spec, str) else list(spec)
    names = [n for n in names if n]
    if not names:
        raise DatamaskError("at least one locale is required")
    out: list[Locale] = []
    for name in names:
        if name not in LOCALES:
            raise DatamaskError(
                f"unknown locale {name!r} (available: {', '.join(sorted(LOCALES))})"
            )
        out.append(LOCALES[name])
    return out


def parse_fields(spec: str | Sequence[str] | None) -> tuple[str, ...]:
    if spec is None:
        return DEFAULT_FIELDS
    names = [s.strip() for s in spec.split(",")] if isinstance(spec, str) else list(spec)
    names = [n for n in names if n]
    if not names:
        raise DatamaskError("--fields is empty")
    unknown = [n for n in names if n not in ALL_FIELDS]
    if unknown:
        raise DatamaskError(
            f"unknown field(s): {', '.join(unknown)} (available: {', '.join(ALL_FIELDS)})"
        )
    seen: set[str] = set()
    return tuple(n for n in names if not (n in seen or seen.add(n)))


class Generator:
    """Produces reproducible synthetic people from a seed."""

    def __init__(
        self,
        seed: int | None = None,
        locales: str | Sequence[str] = "en",
        as_of: date | None = None,
        null_rate: float = 0.0,
    ) -> None:
        if not 0.0 <= null_rate <= 1.0:
            raise DatamaskError("null rate must be between 0 and 1")
        self.rng = random.Random(seed)
        self.locales = parse_locales(locales)
        self.as_of = as_of or date(2026, 1, 1)
        self.null_rate = null_rate
        self._emails: set[str] = set()

    # -- small building blocks -------------------------------------------------------------
    def _digits(self, n: int) -> str:
        return "".join(self.rng.choice("0123456789") for _ in range(n))

    def uuid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    def first_name(self, loc: Locale | None = None) -> str:
        return self.rng.choice((loc or self.rng.choice(self.locales)).first_names)

    def last_name(self, loc: Locale | None = None) -> str:
        return self.rng.choice((loc or self.rng.choice(self.locales)).last_names)

    def email(self, first: str, last: str) -> str:
        base = f"{slugify(first)}.{slugify(last)}"
        domain = self.rng.choice(EMAIL_DOMAINS)
        candidate = f"{base}@{domain}"
        while candidate in self._emails:
            candidate = f"{base}{self.rng.randint(1, 9999)}@{domain}"
        self._emails.add(candidate)
        return candidate

    def phone(self, loc: Locale) -> str:
        if loc.code == "de":
            return f"+49 30 23125{self._digits(3)}"
        if loc.code == "fr":
            return f"+33 6 39 98 {self._digits(2)} {self._digits(2)}"
        return f"07700 900{self._digits(3)}"

    def dob(self) -> date:
        age_days = self.rng.randint(18 * 365, 85 * 365)
        return self.as_of - timedelta(days=age_days)

    def address(self, loc: Locale) -> tuple[str, str, str]:
        """Return (street line, city, postcode)."""
        street = self.rng.choice(loc.streets)
        number = self.rng.randint(1, 180)
        line = f"{street} {number}" if loc.code == "de" else f"{number} {street}"
        city, prefix = self.rng.choice(loc.cities)
        if loc.code == "en":
            letters = "".join(self.rng.choice(_UK_INWARD) for _ in range(2))
            postcode = f"{prefix}{self.rng.randint(1, 20)} {self.rng.randint(1, 9)}{letters}"
        else:
            postcode = f"{prefix}{self._digits(3)}"
        return line, city, postcode

    def national_id(self, loc: Locale, born: date, postcode: str) -> str:
        if loc.code == "en":
            # "QQ" is a prefix HMRC never issues.
            return f"QQ{self._digits(6)}{self.rng.choice('ABCD')}"
        if loc.code == "de":
            return "T" + "".join(self.rng.choice(_DE_ID_CHARS) for _ in range(8))
        body = f"{self.rng.choice('12')}{born:%y%m}{postcode[:2]}{self._digits(6)}"
        return f"{body}{97 - int(body) % 97:02d}"

    def iban(self, loc: Locale) -> str:
        if loc.code == "en":
            country, bban = "GB", f"ZZZZ{self._digits(14)}"
        elif loc.code == "de":
            country, bban = "DE", f"00000000{self._digits(10)}"
        else:
            country, bban = "FR", f"0000000000{self._digits(13)}"
        return f"{country}{iban_check_digits(country, bban)}{bban}"

    def card_number(self) -> str:
        partial = "400000" + self._digits(9)
        return partial + luhn_check_digit(partial)

    def ip_address(self) -> str:
        return f"{self.rng.choice(DOC_IPV4_PREFIXES)}{self.rng.randint(1, 254)}"

    # -- whole records ---------------------------------------------------------------------
    def person(self) -> dict[str, Any]:
        """Build one fully populated person (all of ``ALL_FIELDS``)."""
        loc = self.rng.choice(self.locales)
        first, last = self.first_name(loc), self.last_name(loc)
        street, city, postcode = self.address(loc)
        born = self.dob()
        start = date(2018, 1, 1)
        signup = start + timedelta(days=self.rng.randint(0, (self.as_of - start).days))
        consent = self.rng.random() < 0.55
        consent_date: date | None = None
        if consent:
            consent_date = min(signup + timedelta(days=self.rng.randint(0, 3)), self.as_of)
        return {
            "id": self.uuid(),
            "first_name": first,
            "last_name": last,
            "full_name": f"{first} {last}",
            "email": self.email(first, last),
            "phone": self.phone(loc),
            "dob": born.isoformat(),
            "street": street,
            "city": city,
            "postcode": postcode,
            "country": loc.country,
            "national_id": self.national_id(loc, born, postcode),
            "iban": self.iban(loc),
            "card_number": self.card_number(),
            "ip_address": self.ip_address(),
            "occupation": self.rng.choice(OCCUPATIONS),
            "signup_date": signup.isoformat(),
            "marketing_consent": consent,
            "consent_date": consent_date.isoformat() if consent_date else None,
        }

    def rows(self, count: int, fields: Sequence[str] = DEFAULT_FIELDS) -> Iterator[dict[str, Any]]:
        if count < 0:
            raise DatamaskError("row count must not be negative")
        for _ in range(count):
            full = self.person()
            row: dict[str, Any] = {}
            for name in fields:
                value = full[name]
                if (
                    self.null_rate
                    and name not in _NEVER_NULL
                    and self.rng.random() < self.null_rate
                ):
                    value = None
                row[name] = value
            yield row


def generate(
    count: int,
    fields: str | Sequence[str] | None = None,
    seed: int | None = None,
    locales: str | Sequence[str] = "en",
    null_rate: float = 0.0,
    as_of: date | None = None,
) -> list[dict[str, Any]]:
    """Convenience wrapper returning ``count`` rows as a list of dicts."""
    gen = Generator(seed=seed, locales=locales, as_of=as_of, null_rate=null_rate)
    return list(gen.rows(count, parse_fields(fields)))
