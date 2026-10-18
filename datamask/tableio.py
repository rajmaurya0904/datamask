"""Read and write tables as CSV, JSON Lines or a JSON array of objects."""

from __future__ import annotations

import csv
import io
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import DatamaskError

FORMATS = ("csv", "jsonl", "json")
_EXTENSIONS = {
    ".csv": "csv",
    ".tsv": "csv",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".json": "json",
}


@dataclass
class Table:
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)

    def column(self, name: str) -> list[Any]:
        return [row.get(name) for row in self.rows]


def detect_format(path: str, explicit: str | None = None) -> str:
    """Pick a format from ``--format`` or the file extension (stdin/stdout default to csv)."""
    if explicit:
        if explicit not in FORMATS:
            raise DatamaskError(f"unknown format {explicit!r} (choose from {', '.join(FORMATS)})")
        return explicit
    if path == "-":
        return "csv"
    suffix = Path(path).suffix.lower()
    if suffix not in _EXTENSIONS:
        raise DatamaskError(
            f"cannot infer the format of {path!r}; use --format csv|jsonl|json"
        )
    return _EXTENSIONS[suffix]


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    try:
        return Path(path).read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise DatamaskError(f"file not found: {path}") from None
    except UnicodeDecodeError as exc:
        raise DatamaskError(f"{path} is not valid UTF-8 ({exc.reason})") from None
    except OSError as exc:
        raise DatamaskError(f"cannot read {path}: {exc.strerror or exc}") from None


def _read_csv(text: str, delimiter: str, source: str) -> Table:
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    try:
        header = next(reader)
    except StopIteration:
        raise DatamaskError(f"{source} is empty") from None
    header = [h.strip() for h in header]
    if not any(header):
        raise DatamaskError(f"{source} has an empty header row")
    if "" in header:
        raise DatamaskError(f"{source} has a blank column name in its header")
    dupes = sorted({h for h in header if header.count(h) > 1})
    if dupes:
        raise DatamaskError(f"{source} has duplicate column names: {', '.join(dupes)}")
    rows: list[dict[str, Any]] = []
    for record in reader:
        if not record:
            continue  # blank line
        if len(record) != len(header):
            raise DatamaskError(
                f"{source} line {reader.line_num}: expected {len(header)} fields, got {len(record)}"
            )
        rows.append(dict(zip(header, record, strict=True)))
    return Table(header, rows)


def _columns_of(rows: list[dict[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}
    for row in rows:
        for key in row:
            seen.setdefault(key, None)
    return list(seen)


def _read_jsonl(text: str, source: str) -> Table:
    rows: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DatamaskError(f"{source} line {lineno}: invalid JSON ({exc.msg})") from None
        if not isinstance(obj, dict):
            raise DatamaskError(f"{source} line {lineno}: expected a JSON object")
        rows.append(obj)
    return Table(_columns_of(rows), rows)


def _read_json(text: str, source: str) -> Table:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DatamaskError(
            f"{source}: invalid JSON at line {exc.lineno} column {exc.colno} ({exc.msg})"
        ) from None
    if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
        raise DatamaskError(f"{source}: expected a JSON array of objects")
    return Table(_columns_of(data), data)


def read_table(path: str, fmt: str | None = None) -> Table:
    """Load a whole table into memory. ``path`` may be ``-`` for stdin."""
    kind = detect_format(path, fmt)
    text = _read_text(path)
    source = "stdin" if path == "-" else path
    if kind == "csv":
        delimiter = "\t" if path.lower().endswith(".tsv") else ","
        return _read_csv(text, delimiter, source)
    if kind == "jsonl":
        return _read_jsonl(text, source)
    return _read_json(text, source)


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def render_table(table: Table, fmt: str, delimiter: str = ",") -> str:
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=delimiter, lineterminator="\n")
        writer.writerow(table.columns)
        for row in table.rows:
            writer.writerow([_csv_cell(row.get(c)) for c in table.columns])
        return buf.getvalue()
    projected = [{c: row.get(c) for c in table.columns} for row in table.rows]
    if fmt == "jsonl":
        return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in projected)
    if fmt == "json":
        return json.dumps(projected, ensure_ascii=False, indent=2) + "\n"
    raise DatamaskError(f"unknown format {fmt!r}")


def write_table(table: Table, path: str, fmt: str | None = None) -> None:
    """Write ``table`` to ``path`` (``-`` means stdout)."""
    kind = detect_format(path, fmt)
    delimiter = "\t" if path.lower().endswith(".tsv") else ","
    text = render_table(table, kind, delimiter)
    if path == "-":
        sys.stdout.write(text)
        return
    try:
        Path(path).write_text(text, encoding="utf-8", newline="")
    except OSError as exc:
        raise DatamaskError(f"cannot write {path}: {exc.strerror or exc}") from None
