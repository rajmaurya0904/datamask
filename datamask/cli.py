"""Command line interface: generate, mask, scan, verify, kcheck, strategies."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import date

from . import __version__
from .config import (
    DEFAULT_SALT_ENV,
    Config,
    load_config,
    parse_rule_args,
    render_config,
    resolve_salt,
)
from .detect import APPLY_THRESHOLD, scan_table, suggest_rules
from .errors import DatamaskError
from .generate import ALL_FIELDS, Generator, parse_fields
from .masker import Masker, MaskReport
from .strategies import REGISTRY, Strategy, build_strategy
from .tableio import FORMATS, Table, detect_format, read_table, write_table
from .verify import check_k_anonymity, check_leaks

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _fmt_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    def line(cells: Sequence[str]) -> str:
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths, strict=True)).rstrip()
    out = [line(headers), line(["-" * w for w in widths])]
    out.extend(line(r) for r in rows)
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="datamask",
        description="Generate synthetic user data and mask personal data in real files.",
    )
    parser.add_argument("--version", action="version", version=f"datamask {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    gen = sub.add_parser("generate", help="write a synthetic user dataset")
    gen.add_argument("-n", "--rows", type=int, default=100, help="number of rows (default 100)")
    gen.add_argument("--seed", type=int, default=None, help="seed for reproducible output")
    gen.add_argument("--locale", default="en", help="comma-separated: en, de, fr (default en)")
    gen.add_argument(
        "--fields", default=None,
        help="comma-separated; default is every field except full_name and occupation",
    )
    gen.add_argument("--null-rate", type=float, default=0.0, help="share of blank cells, 0-1")
    gen.add_argument("--as-of", default=None, help="reference date for ages, YYYY-MM-DD")
    gen.add_argument("--format", choices=FORMATS, default=None, help="output format")
    gen.add_argument("-o", "--output", default="-", help="output file (default stdout)")

    mask = sub.add_parser("mask", help="mask personal data in a CSV, JSON Lines or JSON file")
    mask.add_argument("input", help="input file, or - for stdin")
    mask.add_argument("-o", "--output", default="-", help="output file (default stdout)")
    mask.add_argument("-c", "--config", help="TOML file with the masking rules")
    mask.add_argument("-r", "--rule", action="append", default=[], metavar="COL=STRATEGY",
                      help="masking rule, repeatable, e.g. -r phone=partial:keep_last=4")
    mask.add_argument("--auto", action="store_true",
                      help="also mask the columns that scan detects (explicit rules win)")
    mask.add_argument("--default", metavar="STRATEGY",
                      help="strategy for every column without a rule (e.g. redact)")
    mask.add_argument("--salt-file", help="file holding the secret salt")
    mask.add_argument("--salt-env", default=DEFAULT_SALT_ENV, help="env var holding the salt")
    mask.add_argument("--seed", type=int, default=None, help="seed for shuffle (overrides config)")
    mask.add_argument("--on-error", choices=("null", "fail"), default=None,
                      help="what to do with a value a strategy cannot handle (default null)")
    mask.add_argument("--allow-missing", action="store_true",
                      help="skip rules whose column is not in the input")
    mask.add_argument("--format", choices=FORMATS, default=None, help="input format")
    mask.add_argument("--out-format", choices=FORMATS, default=None, help="output format")
    mask.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")

    scan = sub.add_parser("scan", help="report which columns look like personal data")
    scan.add_argument("input", help="input file, or - for stdin")
    scan.add_argument("--format", choices=FORMATS, default=None, help="input format")
    scan.add_argument("--threshold", type=float, default=APPLY_THRESHOLD,
                      help=f"confidence needed to count as PII (default {APPLY_THRESHOLD})")
    scan.add_argument("--write-config", metavar="FILE", help="write a starter TOML config")
    scan.add_argument("--fail-on-pii", action="store_true",
                      help="exit 1 if any column reaches the threshold (for CI)")

    ver = sub.add_parser("verify", help="check that masked output no longer contains the originals")
    ver.add_argument("original", help="the original file")
    ver.add_argument("masked", help="the masked file")
    ver.add_argument("-c", "--config", help="TOML masking config; its masked columns are checked")
    ver.add_argument("-r", "--rule", action="append", default=[], metavar="COL=STRATEGY")
    ver.add_argument("--columns", help="comma-separated columns to check")
    ver.add_argument("--auto", action="store_true", help="check the columns scan detects")
    ver.add_argument("--min-length", type=int, default=4, help="ignore shorter values (default 4)")
    ver.add_argument("--common-threshold", type=int, default=20,
                     help="values in more rows than this are too common to count as "
                          "reappearing (default 20)")
    ver.add_argument("--format", choices=FORMATS, default=None, help="format of both files")

    kc = sub.add_parser("kcheck", help="k-anonymity of a file over quasi-identifier columns")
    kc.add_argument("input", help="input file, or - for stdin")
    kc.add_argument("--quasi", required=True, help="comma-separated quasi-identifier columns")
    kc.add_argument("-k", type=int, default=5, help="required class size (default 5)")
    kc.add_argument("--format", choices=FORMATS, default=None, help="input format")

    sub.add_parser("strategies", help="list the masking strategies and their options")
    return parser


# -- commands -------------------------------------------------------------------------------


def cmd_generate(args: argparse.Namespace) -> int:
    fields = parse_fields(args.fields)
    as_of = None
    if args.as_of:
        try:
            as_of = date.fromisoformat(args.as_of)
        except ValueError:
            raise DatamaskError(f"--as-of must be YYYY-MM-DD, got {args.as_of!r}") from None
    gen = Generator(seed=args.seed, locales=args.locale, as_of=as_of, null_rate=args.null_rate)
    rows = list(gen.rows(args.rows, fields))
    write_table(Table(list(fields), rows), args.output, args.format)
    return EXIT_OK


def _collect_rules(args: argparse.Namespace) -> Config:
    config = load_config(args.config) if getattr(args, "config", None) else Config()
    config.rules.update(parse_rule_args(args.rule))
    return config


def _print_mask_report(report: MaskReport, destination: str) -> None:
    where = "stdout" if destination == "-" else destination
    print(f"masked {report.rows} rows -> {where}", file=sys.stderr)
    if report.columns:
        rows = [
            [c.column, c.strategy, str(c.changed), str(c.empty), str(c.failed)]
            for c in report.columns
        ]
        print(
            _fmt_table(["column", "strategy", "changed", "empty", "unparseable"], rows),
            file=sys.stderr,
        )
    if report.dropped:
        print(f"dropped: {', '.join(report.dropped)}", file=sys.stderr)
    if report.untouched:
        print(f"left as-is: {', '.join(report.untouched)}", file=sys.stderr)
    if report.failed_cells:
        print(
            f"{report.failed_cells} value(s) could not be parsed and were replaced with "
            "empty cells (use --on-error fail to stop instead)",
            file=sys.stderr,
        )
    for warning in report.warnings:
        print(f"warning: {warning}", file=sys.stderr)


def cmd_mask(args: argparse.Namespace) -> int:
    config = _collect_rules(args)
    table = read_table(args.input, args.format)
    if args.auto:
        for column, spec in suggest_rules(table).items():
            config.rules.setdefault(column, build_strategy(spec))
    default: Strategy | None = config.default
    if args.default:
        default = build_strategy(args.default)
    if not config.rules and default is None:
        raise DatamaskError(
            "no masking rules: pass --config, --rule COL=STRATEGY, --auto or --default"
        )
    masker = Masker(
        config.rules,
        salt=resolve_salt(config.salt, args.salt_env, args.salt_file),
        seed=args.seed if args.seed is not None else config.seed,
        on_error=args.on_error or config.on_error,
        default=default,
        allow_missing=args.allow_missing,
    )
    masked, report = masker.mask(table)
    out_fmt = args.out_format
    if out_fmt is None:
        out_fmt = (
            detect_format(args.output) if args.output != "-"
            else detect_format(args.input, args.format)
        )
    write_table(masked, args.output, out_fmt)
    if not args.quiet:
        _print_mask_report(report, args.output)
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    table = read_table(args.input, args.format)
    findings = scan_table(table)
    flagged = [f for f in findings if f.confidence >= args.threshold]
    name = "stdin" if args.input == "-" else args.input
    print(f"{name}: {len(table.rows)} rows, {len(table.columns)} columns")
    if findings:
        rows = [
            [f.column, f.kind, f"{f.confidence:.2f}", f.strategy if f in flagged else "(review)",
             f.evidence]
            for f in findings
        ]
        print()
        print(_fmt_table(["column", "kind", "conf", "suggested", "why"], rows))
    clean = [c for c in table.columns if c not in {f.column for f in findings}]
    if clean:
        print(f"\nno PII signal: {', '.join(clean)}")
    print(f"\n{len(flagged)} of {len(table.columns)} columns look like personal data")
    if args.write_config:
        text = render_config(
            {f.column: f.strategy for f in flagged},
            header="# Starter config written by `datamask scan`. Review before relying on it.",
        )
        try:
            with open(args.write_config, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as exc:
            reason = exc.strerror or exc
            raise DatamaskError(f"cannot write {args.write_config}: {reason}") from None
        print(f"wrote {args.write_config}")
    return EXIT_FINDINGS if (args.fail_on_pii and flagged) else EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    original = read_table(args.original, args.format)
    masked = read_table(args.masked, args.format)
    config = _collect_rules(args)
    columns: list[str] = []
    if args.columns:
        columns.extend(c.strip() for c in args.columns.split(",") if c.strip())
    # keep/shuffle leave values in place on purpose; scrub columns hold prose, not identifiers.
    skipped = {"keep", "shuffle", "scrub"}
    columns.extend(c for c, s in config.rules.items() if s.name not in skipped)
    if args.auto:
        columns.extend(
            c for c, spec in suggest_rules(original).items()
            if build_strategy(spec).name not in skipped
        )
    columns = list(dict.fromkeys(columns))
    if not columns:
        raise DatamaskError("nothing to verify: pass --columns, --config, --rule or --auto")
    report = check_leaks(
        original, masked, columns, min_length=args.min_length,
        common_threshold=args.common_threshold,
    )
    print(f"checked {len(report.checked_columns)} column(s): {', '.join(report.checked_columns)}")
    print(f"original values checked (per row): {report.values_checked}")
    print(f"cells left unchanged:            {report.unchanged}")
    print(f"values reappearing in the row:   {report.reappearing}")
    for leak in report.leaks:
        where = f"column {leak.output_column!r}"
        if leak.kind == "reappears":
            where += f" (originally from {leak.source_column!r})"
        print(f"  data row {leak.data_row}: {leak.kind} in {where}")
    for note in report.notes:
        print(f"note: {note}")
    print("PASS: no original values found" if report.ok else "FAIL: original values survived")
    return EXIT_OK if report.ok else EXIT_FINDINGS


def cmd_kcheck(args: argparse.Namespace) -> int:
    table = read_table(args.input, args.format)
    quasi = [c.strip() for c in args.quasi.split(",") if c.strip()]
    report = check_k_anonymity(table, quasi, args.k)
    print(f"quasi-identifiers: {', '.join(report.quasi_identifiers)}")
    print(f"rows: {report.rows}   equivalence classes: {report.classes}")
    print(f"smallest class (k): {report.min_k}   unique rows: {report.unique_rows}")
    hist = "  ".join(f"{size}:{n}" for size, n in list(report.size_histogram.items())[:10])
    print(f"class sizes (size:count): {hist}")
    if report.ok:
        print(f"PASS: every class has at least {report.k_target} rows")
        return EXIT_OK
    print(
        f"FAIL: {report.rows_below_k} rows in {report.classes_below_k} classes "
        f"are below k={report.k_target}"
    )
    return EXIT_FINDINGS


def cmd_strategies(_: argparse.Namespace) -> int:
    rows = []
    for name, cls in REGISTRY.items():
        params = ", ".join(
            f"{key}={default!r}" if default != "" else key
            for key, (_, default) in cls.params.items()
        )
        rows.append([name, cls.summary, params])
    print(_fmt_table(["strategy", "what it does", "options"], rows))
    print("\nusage: name or name:key=value,key=value   e.g. partial:keep_last=4")
    print(f"pseudonym kinds: {', '.join(ALL_FIELDS)}")
    return EXIT_OK


_COMMANDS = {
    "generate": cmd_generate,
    "mask": cmd_mask,
    "scan": cmd_scan,
    "verify": cmd_verify,
    "kcheck": cmd_kcheck,
    "strategies": cmd_strategies,
}


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except DatamaskError as exc:
        print(f"datamask: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except BrokenPipeError:
        return EXIT_OK
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
