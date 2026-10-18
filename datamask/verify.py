"""Checks on masked output: did original values survive, and how identifiable are the rows."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from .errors import DatamaskError
from .strategies import is_empty, text_of
from .tableio import Table

MIN_VALUE_LENGTH = 4
SUBSTRING_MIN_LENGTH = 6
MAX_LOCATIONS = 20


@dataclass
class Leak:
    kind: str  # "unchanged" (same cell) or "reappears" (own value found in another column)
    source_column: str
    output_column: str
    data_row: int  # 1-based, header not counted


@dataclass
class LeakReport:
    checked_columns: list[str]
    values_checked: int = 0
    unchanged: int = 0
    reappearing: int = 0
    leaks: list[Leak] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.unchanged == 0 and self.reappearing == 0


def check_leaks(
    original: Table,
    masked: Table,
    columns: Iterable[str],
    min_length: int = MIN_VALUE_LENGTH,
) -> LeakReport:
    """Look for each row's own original values of ``columns`` in the same masked row.

    A value counts as surviving if its masked cell is identical (``unchanged``) or if it
    appears whole, or as a substring when it has at least ``SUBSTRING_MIN_LENGTH``
    characters, inside another cell of the same row (``reappears``), which is how a name
    typically leaks through a free-text column. Comparison ignores case. Values shorter
    than ``min_length`` are skipped because short strings occur by chance. Rows are
    compared by position, so both tables must keep their row order. A value that merely
    equals some *other* person's original value is not a leak and is not reported.
    """
    wanted = list(dict.fromkeys(columns))
    missing = [c for c in wanted if c not in original.columns]
    if missing:
        raise DatamaskError(f"column(s) not in the original file: {', '.join(missing)}")
    if len(original.rows) != len(masked.rows):
        raise DatamaskError(
            f"row counts differ ({len(original.rows)} original, {len(masked.rows)} masked); "
            "verify compares rows by position"
        )
    report = LeakReport(checked_columns=wanted)
    for index, (before, after) in enumerate(zip(original.rows, masked.rows, strict=True), start=1):
        out_text = {
            col: text_of(after[col]).casefold()
            for col in masked.columns
            if col in after and not is_empty(after[col])
        }
        for source in wanted:
            raw = before.get(source)
            if is_empty(raw) or len(text_of(raw)) < min_length:
                continue
            needle = text_of(raw).casefold()
            report.values_checked += 1
            for out_col, cell in out_text.items():
                same_cell = out_col == source
                if same_cell:
                    hit = cell == needle
                else:
                    hit = cell == needle or (
                        len(needle) >= SUBSTRING_MIN_LENGTH and needle in cell
                    )
                if not hit:
                    continue
                if same_cell:
                    report.unchanged += 1
                else:
                    report.reappearing += 1
                if len(report.leaks) < MAX_LOCATIONS:
                    kind = "unchanged" if same_cell else "reappears"
                    report.leaks.append(Leak(kind, source, out_col, index))
    return report


@dataclass
class KAnonReport:
    quasi_identifiers: list[str]
    k_target: int
    rows: int
    classes: int
    min_k: int
    unique_rows: int
    rows_below_k: int
    classes_below_k: int
    size_histogram: dict[int, int]

    @property
    def ok(self) -> bool:
        return self.rows_below_k == 0


def check_k_anonymity(table: Table, quasi: list[str], k: int) -> KAnonReport:
    """Group rows by their quasi-identifier values and report class sizes."""
    if k < 1:
        raise DatamaskError("k must be at least 1")
    if not quasi:
        raise DatamaskError("at least one quasi-identifier column is required")
    missing = [c for c in quasi if c not in table.columns]
    if missing:
        raise DatamaskError(
            f"column(s) not found: {', '.join(missing)} (columns are: {', '.join(table.columns)})"
        )
    if not table.rows:
        raise DatamaskError("the table has no rows")
    groups = Counter(tuple(text_of(row.get(c)) if row.get(c) is not None else "" for c in quasi)
                     for row in table.rows)
    sizes = Counter(groups.values())
    below = {key: n for key, n in groups.items() if n < k}
    return KAnonReport(
        quasi_identifiers=list(quasi),
        k_target=k,
        rows=len(table.rows),
        classes=len(groups),
        min_k=min(groups.values()),
        unique_rows=sizes.get(1, 0),
        rows_below_k=sum(below.values()),
        classes_below_k=len(below),
        size_histogram=dict(sorted(sizes.items())),
    )
