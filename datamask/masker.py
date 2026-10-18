"""Apply a set of per-column masking rules to a table."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from .errors import DatamaskError
from .strategies import Context, Drop, Strategy, is_empty
from .tableio import Table

ON_ERROR = ("null", "fail")


@dataclass
class ColumnReport:
    column: str
    strategy: str
    changed: int = 0
    empty: int = 0
    failed: int = 0


@dataclass
class MaskReport:
    rows: int = 0
    columns: list[ColumnReport] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    untouched: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def failed_cells(self) -> int:
        return sum(c.failed for c in self.columns)


class Masker:
    """Holds the rules, the secret salt and the error policy for one run."""

    def __init__(
        self,
        rules: Mapping[str, Strategy],
        salt: bytes | None = None,
        seed: int = 0,
        on_error: str = "null",
        default: Strategy | None = None,
        allow_missing: bool = False,
    ) -> None:
        if on_error not in ON_ERROR:
            raise DatamaskError(f"on_error must be one of {', '.join(ON_ERROR)}")
        self.rules = dict(rules)
        self.default = default
        self.on_error = on_error
        self.allow_missing = allow_missing
        self.warnings: list[str] = []
        if salt is None:
            salt = os.urandom(32)
            self.warnings.append(
                "no salt supplied: a random one-off salt was used, so hashes and pseudonyms "
                "will differ on the next run (set DATAMASK_SALT to make them repeatable)"
            )
        self.ctx = Context(salt=salt, seed=seed)

    def _rules_for(self, table: Table) -> dict[str, Strategy]:
        missing = [c for c in self.rules if c not in table.columns]
        if missing and not self.allow_missing:
            raise DatamaskError(
                f"column(s) not found in the input: {', '.join(missing)} "
                f"(columns are: {', '.join(table.columns)})"
            )
        if missing:
            self.warnings.append(f"rule(s) for missing column(s) skipped: {', '.join(missing)}")
        resolved: dict[str, Strategy] = {}
        for column in table.columns:
            rule = self.rules.get(column, self.default)
            if rule is not None:
                resolved[column] = rule
        return resolved

    def mask(self, table: Table) -> tuple[Table, MaskReport]:
        """Return a new masked table and a report. The input table is not modified."""
        resolved = self._rules_for(table)
        report = MaskReport(rows=len(table.rows), warnings=list(self.warnings))
        out_rows = [dict(row) for row in table.rows]
        kept_columns: list[str] = []
        for column in table.columns:
            strategy = resolved.get(column)
            if strategy is None:
                kept_columns.append(column)
                report.untouched.append(column)
                continue
            if isinstance(strategy, Drop):
                report.dropped.append(column)
                for row in out_rows:
                    row.pop(column, None)
                continue
            kept_columns.append(column)
            if strategy.name == "keep":
                report.untouched.append(column)
                continue
            originals = [row.get(column) for row in out_rows]
            col_report = ColumnReport(column, strategy.name)
            masked = self._apply(strategy, originals, col_report)
            for row, new in zip(out_rows, masked, strict=True):
                row[column] = new
            report.columns.append(col_report)
        return Table(kept_columns, out_rows), report

    def _apply(
        self, strategy: Strategy, originals: list[object], col: ColumnReport
    ) -> list[object]:
        if strategy.column_wise:
            result = strategy.apply_column(list(originals), self.ctx)
            for before, after in zip(originals, result, strict=True):
                if is_empty(before):
                    col.empty += 1
                elif before != after:
                    col.changed += 1
            return result
        out: list[object] = []
        for index, value in enumerate(originals, start=1):
            if is_empty(value):
                col.empty += 1
                out.append(value)
                continue
            try:
                new = strategy.apply(value, self.ctx)
            except (ValueError, TypeError) as exc:
                if self.on_error == "fail":
                    raise DatamaskError(
                        f"column {col.column!r}, data row {index}: the {strategy.name} "
                        f"strategy cannot handle this value ({exc}); value not shown"
                    ) from None
                col.failed += 1
                out.append(None)
                continue
            if new != value:
                col.changed += 1
            out.append(new)
        return out
