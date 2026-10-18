"""Checksum helpers: Luhn (cards) and ISO 7064 mod-97 (IBAN)."""

from __future__ import annotations


def luhn_valid(digits: str) -> bool:
    """Return True if ``digits`` (digits only) passes the Luhn check."""
    if not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_check_digit(partial: str) -> str:
    """Return the digit that makes ``partial + digit`` pass the Luhn check."""
    if not partial.isdigit():
        raise ValueError("luhn_check_digit needs a string of digits")
    for candidate in "0123456789":
        if luhn_valid(partial + candidate):
            return candidate
    raise AssertionError("unreachable: some digit always satisfies Luhn")  # pragma: no cover


def _iban_numeric(text: str) -> int:
    return int("".join(str(int(c, 36)) for c in text))


def iban_valid(iban: str) -> bool:
    """Return True if ``iban`` (spaces allowed) has a correct mod-97 checksum."""
    compact = iban.replace(" ", "").upper()
    if not (15 <= len(compact) <= 34) or not compact.isalnum():
        return False
    if not (compact[:2].isalpha() and compact[2:4].isdigit()):
        return False
    rearranged = compact[4:] + compact[:4]
    return _iban_numeric(rearranged) % 97 == 1


def iban_check_digits(country: str, bban: str) -> str:
    """Compute the two IBAN check digits for ``country`` and ``bban``."""
    rearranged = bban.upper() + country.upper() + "00"
    return f"{98 - _iban_numeric(rearranged) % 97:02d}"
