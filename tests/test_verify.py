import pytest

from datamask.errors import DatamaskError
from datamask.masker import Masker
from datamask.strategies import build_strategy
from datamask.tableio import Table
from datamask.verify import check_k_anonymity, check_leaks

ORIGINAL = Table(
    ["id", "email", "note"],
    [
        {"id": "1", "email": "ann@corp.com", "note": "ok"},
        {"id": "2", "email": "bob@corp.com", "note": "mail bob@corp.com later"},
        {"id": "3", "email": "", "note": "fine"},
    ],
)


def masked_with(**specs: str) -> Table:
    rules = {col: build_strategy(spec) for col, spec in specs.items()}
    out, _ = Masker(rules, salt=b"s").mask(ORIGINAL)
    return out


def test_clean_masking_reports_no_leaks() -> None:
    masked = masked_with(email="hash", note="scrub")
    report = check_leaks(ORIGINAL, masked, ["email"])
    assert report.ok and report.unchanged == 0 and report.reappearing == 0
    assert report.values_checked == 2


def test_unmasked_column_is_reported_as_unchanged() -> None:
    masked = masked_with(note="scrub")
    report = check_leaks(ORIGINAL, masked, ["email"])
    assert not report.ok and report.unchanged == 2
    assert {leak.kind for leak in report.leaks} == {"unchanged"}
    assert [leak.data_row for leak in report.leaks] == [1, 2]


def test_value_surviving_inside_another_column_is_reported() -> None:
    masked = masked_with(email="hash")
    report = check_leaks(ORIGINAL, masked, ["email"])
    assert report.reappearing == 1 and report.unchanged == 0
    leak = report.leaks[0]
    assert (leak.kind, leak.source_column, leak.output_column, leak.data_row) == (
        "reappears", "email", "note", 2,
    )


def test_exact_value_moved_to_another_column_is_reported() -> None:
    masked = Table(["id", "email", "note"], [
        {"id": "1", "email": "x", "note": "ann@corp.com"},
        {"id": "2", "email": "y", "note": "z"},
        {"id": "3", "email": "", "note": ""},
    ])
    assert check_leaks(ORIGINAL, masked, ["email"]).reappearing == 1


def test_short_values_are_ignored() -> None:
    original = Table(["a"], [{"a": "yes"}, {"a": "no"}])
    assert check_leaks(original, original, ["a"]).ok


def test_row_count_mismatch_and_unknown_column() -> None:
    with pytest.raises(DatamaskError, match="row counts differ"):
        check_leaks(ORIGINAL, Table(["email"], []), ["email"])
    with pytest.raises(DatamaskError, match="not in the original"):
        check_leaks(ORIGINAL, ORIGINAL, ["nope"])


def test_report_never_contains_the_values() -> None:
    report = check_leaks(ORIGINAL, masked_with(note="scrub"), ["email"])
    assert "ann@corp.com" not in repr(report)


def test_another_persons_value_is_not_a_leak() -> None:
    original = Table(["name", "note"], [
        {"name": "Oliver Smith", "note": "a"},
        {"name": "Grace Hall", "note": "b"},
    ])
    masked = Table(["name", "note"], [
        {"name": "Grace Hall", "note": "a"},  # pseudonym that equals another row's original
        {"name": "Oliver Smith", "note": "b"},
    ])
    assert check_leaks(original, masked, ["name"]).ok


def test_comparison_ignores_case() -> None:
    original = Table(["name", "note"], [{"name": "Oliver Smith", "note": "x"}])
    masked = Table(["name", "note"], [{"name": "h1", "note": "ask OLIVER SMITH"}])
    assert check_leaks(original, masked, ["name"]).reappearing == 1


def test_values_are_counted_per_row() -> None:
    table = Table(["v"], [{"v": f"value-{i:05d}"} for i in range(50)])
    report = check_leaks(table, table, ["v"])
    assert report.values_checked == 50 and report.unchanged == 50


PEOPLE = Table(
    ["year", "zip"],
    [{"year": "1990", "zip": "EC1"}] * 3
    + [{"year": "1991", "zip": "EC1"}] * 2
    + [{"year": "1985", "zip": "M1"}],
)


def test_k_anonymity_counts_classes_and_violations() -> None:
    report = check_k_anonymity(PEOPLE, ["year", "zip"], k=3)
    assert (report.rows, report.classes, report.min_k) == (6, 3, 1)
    assert report.unique_rows == 1
    assert (report.rows_below_k, report.classes_below_k) == (3, 2)
    assert report.size_histogram == {1: 1, 2: 1, 3: 1}
    assert not report.ok


def test_k_anonymity_passes_when_every_class_is_big_enough() -> None:
    assert check_k_anonymity(PEOPLE, ["zip"], k=1).ok
    assert check_k_anonymity(PEOPLE, ["zip"], k=2).rows_below_k == 1


def test_k_anonymity_treats_nulls_as_a_value() -> None:
    table = Table(["a"], [{"a": None}, {"a": ""}, {"a": "x"}])
    report = check_k_anonymity(table, ["a"], k=2)
    assert report.classes == 2 and report.rows_below_k == 1


def test_k_anonymity_input_validation() -> None:
    with pytest.raises(DatamaskError, match="at least 1"):
        check_k_anonymity(PEOPLE, ["zip"], k=0)
    with pytest.raises(DatamaskError, match="quasi-identifier"):
        check_k_anonymity(PEOPLE, [], k=2)
    with pytest.raises(DatamaskError, match="not found"):
        check_k_anonymity(PEOPLE, ["nope"], k=2)
    with pytest.raises(DatamaskError, match="no rows"):
        check_k_anonymity(Table(["a"], []), ["a"], k=2)


def test_common_values_are_not_reported_as_reappearing() -> None:
    names = ["Johnson"] * 30 + ["Rareson"]
    original = Table(["surname", "email"], [{"surname": n, "email": "x"} for n in names])
    masked = Table(
        ["surname", "email"],
        [{"surname": "h", "email": f"{n.lower()}.a@mail.example"} for n in names],
    )
    report = check_leaks(original, masked, ["surname"])
    assert report.reappearing == 1  # only the rare surname
    assert any("occur in more than 20 rows" in note for note in report.notes)
    strict = check_leaks(original, masked, ["surname"], common_threshold=1000)
    assert strict.reappearing == 31


def test_common_values_are_still_checked_for_being_unchanged() -> None:
    table = Table(["surname"], [{"surname": "Johnson"}] * 30)
    assert check_leaks(table, table, ["surname"]).unchanged == 30
