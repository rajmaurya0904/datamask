"""Find columns that probably hold personal data, from their names and their values."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from .checks import iban_valid, luhn_valid
from .patterns import (
    EMAIL_RE,
    find_pii,
    looks_like_ip,
    looks_like_phone,
)
from .strategies import is_empty, parse_date, text_of
from .tableio import Table

SAMPLE_LIMIT = 2000
APPLY_THRESHOLD = 0.6

# kind -> suggested strategy spec
SUGGESTED: dict[str, str] = {
    "email": "pseudonym:kind=email",
    "phone": "partial:keep_last=3",
    "card": "partial:keep_last=4",
    "iban": "partial:keep_first=2,keep_last=4",
    "ip": "subnet",
    "dob": "date:to=year",
    "national_id": "hash",
    "first_name": "pseudonym:kind=first_name",
    "last_name": "pseudonym:kind=last_name",
    "full_name": "pseudonym:kind=full_name",
    "street": "pseudonym:kind=street",
    "postcode": "prefix:keep=3",
    "age": "bucket:width=5",
    "salary": "noise:pct=10",
    "free_text": "scrub",
}

# Header words (split on non-alphanumerics and camelCase) that point at a kind.
_HEADER_WORDS: dict[str, set[str]] = {
    "email": {"email", "emails", "mail", "emailaddress"},
    "phone": {"phone", "tel", "telephone", "mobile", "cell", "fax", "msisdn"},
    "card": {"card", "cc", "pan", "creditcard"},
    "iban": {"iban"},
    "ip": {"ip", "ipaddress", "ipv4", "ipv6"},
    "dob": {"dob", "birth", "birthday", "birthdate", "born"},
    "national_id": {"ssn", "nino", "nin", "passport", "insee", "tin", "taxid", "nationalid"},
    "first_name": {"firstname", "fname", "forename", "given", "givenname"},
    "last_name": {"lastname", "lname", "surname", "family", "familyname"},
    "full_name": {"fullname", "name", "customername"},
    "street": {"street", "address", "addr", "address1", "address2"},
    "postcode": {"postcode", "zip", "zipcode", "postal", "plz"},
    "age": {"age"},
    "salary": {"salary", "income", "wage", "earnings"},
    "free_text": {"notes", "note", "comment", "comments", "message", "description", "remarks"},
}

_NINO = re.compile(r"[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]", re.I)
_SSN = re.compile(r"\d{3}-\d{2}-\d{4}")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass
class Finding:
    column: str
    kind: str
    confidence: float
    strategy: str
    evidence: str

    @property
    def applied_by_default(self) -> bool:
        return self.confidence >= APPLY_THRESHOLD


def header_tokens(name: str) -> list[str]:
    spaced = _CAMEL.sub("_", name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def header_kind(name: str) -> str | None:
    tokens = header_tokens(name)
    joined = "".join(tokens)
    candidates = [*tokens, joined]
    # Two-token names such as first_name / date_of_birth match on the joined form too.
    for pair in zip(tokens, tokens[1:], strict=False):
        candidates.append("".join(pair))
    for kind, words in _HEADER_WORDS.items():
        if kind == "full_name":
            continue
        if any(c in words for c in candidates):
            return kind
    if "dateofbirth" in joined:
        return "dob"
    if any(c in _HEADER_WORDS["full_name"] for c in candidates):
        return "full_name"
    return None


def _value_test(kind: str):
    """Return a predicate for ``kind`` or None when values cannot confirm it."""
    if kind == "email":
        return lambda v: bool(EMAIL_RE.fullmatch(v.strip()))
    if kind == "phone":
        return looks_like_phone
    if kind == "card":
        def card(v: str) -> bool:
            digits = re.sub(r"[ -]", "", v.strip())
            return digits.isdigit() and 13 <= len(digits) <= 19 and luhn_valid(digits)

        return card
    if kind == "iban":
        return iban_valid
    if kind == "ip":
        return looks_like_ip
    if kind == "dob":
        def date_like(v: str) -> bool:
            try:
                parse_date(v)
            except ValueError:
                return False
            return True

        return date_like
    if kind == "national_id":
        return lambda v: bool(_NINO.fullmatch(v.strip()) or _SSN.fullmatch(v.strip()))
    if kind in {"age", "salary"}:
        def numeric(v: str) -> bool:
            try:
                float(v.replace(",", "."))
            except ValueError:
                return False
            return True

        return numeric
    return None


def _sample(values: list[Any]) -> list[str]:
    texts = [text_of(v) for v in values if not is_empty(v)]
    if len(texts) <= SAMPLE_LIMIT:
        return texts
    step = len(texts) / SAMPLE_LIMIT
    return [texts[int(i * step)] for i in range(SAMPLE_LIMIT)]


def _kind_from_values(sample: list[str]) -> tuple[str, float] | None:
    """Identify a column by its values alone (no help from the header)."""
    for kind in ("email", "card", "iban", "ip", "national_id", "phone"):
        test = _value_test(kind)
        assert test is not None
        if kind == "phone":
            # Without a header hint, a bare run of digits is more likely an order number.
            def test(v: str) -> bool:
                return looks_like_phone(v) and bool(re.search(r"[+\s().\-]", v.strip()))
        hits = sum(1 for v in sample if test(v))
        if sample and hits / len(sample) >= 0.8:
            return kind, hits / len(sample)
    return None


def classify_column(name: str, values: list[Any]) -> Finding | None:
    sample = _sample(values)
    if not sample:
        return None
    hinted = header_kind(name)
    if hinted == "free_text":
        return _free_text_finding(name, sample, hinted_by_name=True)
    if hinted is not None:
        test = _value_test(hinted)
        if test is None:
            evidence = f"column name looks like {hinted.replace('_', ' ')}"
            return Finding(name, hinted, 0.7, SUGGESTED[hinted], evidence)
        share = sum(1 for v in sample if test(v)) / len(sample)
        if share >= 0.8:
            label = hinted.replace("_", " ")
            evidence = f"column name and {share:.0%} of values look like {label}"
            return Finding(name, hinted, 0.95, SUGGESTED[hinted], evidence)
        if share >= 0.5:
            evidence = f"column name matches; {share:.0%} of values look like {hinted}"
            return Finding(name, hinted, 0.75, SUGGESTED[hinted], evidence)
        evidence = f"column name looks like {hinted} but only {share:.0%} of values do"
        return Finding(name, hinted, 0.5, SUGGESTED[hinted], evidence)
    from_values = _kind_from_values(sample)
    if from_values is not None:
        kind, share = from_values
        label = kind.replace("_", " ")
        evidence = f"{share:.0%} of values look like {label} (name gives no hint)"
        return Finding(name, kind, 0.85, SUGGESTED[kind], evidence)
    prose = [text for text in sample if " " in text.strip()]
    if len(prose) >= max(1, len(sample) // 2):
        return _free_text_finding(name, prose, hinted_by_name=False)
    return None


def _free_text_finding(name: str, sample: list[str], hinted_by_name: bool) -> Finding | None:
    embedded = Counter(m.kind for text in sample for m in find_pii(text))
    if embedded:
        rows_hit = sum(1 for text in sample if find_pii(text))
        parts = ", ".join(f"{n} {k}" for k, n in embedded.most_common())
        evidence = (
            f"free text with embedded PII in {rows_hit} of {len(sample)} sampled values ({parts})"
        )
        return Finding(name, "free_text", 0.8, SUGGESTED["free_text"], evidence)
    if hinted_by_name:
        evidence = (
            "free-text column: no emails, phones, cards, IBANs or IPs found, "
            "but names in prose cannot be detected"
        )
        return Finding(name, "free_text", 0.5, SUGGESTED["free_text"], evidence)
    return None


def scan_table(table: Table) -> list[Finding]:
    """Classify every column; returns findings in column order."""
    findings: list[Finding] = []
    for column in table.columns:
        found = classify_column(column, table.column(column))
        if found is not None:
            findings.append(found)
    names = [
        f.column for f in findings
        if f.kind in {"first_name", "last_name", "full_name"} and f.confidence >= APPLY_THRESHOLD
    ]
    if names:
        # Prose often repeats the person's name; tell scrub to strip this row's own values.
        for f in findings:
            if f.kind == "free_text":
                f.strategy = f"scrub:also={'+'.join(names)}"
    return findings


def suggest_rules(table: Table, threshold: float = APPLY_THRESHOLD) -> dict[str, str]:
    """Strategy specs for findings at or above ``threshold``."""
    return {f.column: f.strategy for f in scan_table(table) if f.confidence >= threshold}
