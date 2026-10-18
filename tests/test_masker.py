import pytest

from datamask.errors import DatamaskError
from datamask.masker import Masker
from datamask.strategies import build_strategy
from datamask.tableio import Table

SALT = b"test-salt"


def sample() -> Table:
    rows = [
        {"id": "1", "email": "ann@corp.com", "phone": "07700 900111", "dob": "1990-02-03",
         "note": "x"},
        {"id": "2", "email": "bob@corp.com", "phone": "", "dob": "1985-12-31", "note": "y"},
        {"id": "3", "email": "cy@corp.com", "phone": "07700 900333", "dob": "not a date",
         "note": "z"},
    ]
    return Table(["id", "email", "phone", "dob", "note"], rows)


def rules(**specs: str):
    return {col: build_strategy(spec) for col, spec in specs.items()}


def test_masks_only_listed_columns_and_reports_untouched() -> None:
    out, report = Masker(rules(email="hash"), salt=SALT).mask(sample())
    assert [r["id"] for r in out.rows] == ["1", "2", "3"]
    assert [r["note"] for r in out.rows] == ["x", "y", "z"]
    assert all("@" not in r["email"] for r in out.rows)
    assert report.untouched == ["id", "phone", "dob", "note"]
    assert report.rows == 3


def test_input_table_is_not_modified() -> None:
    table = sample()
    Masker(rules(email="redact"), salt=SALT).mask(table)
    assert table.rows[0]["email"] == "ann@corp.com"


def test_empty_cells_stay_empty_and_are_counted() -> None:
    out, report = Masker(rules(phone="partial:keep_last=3"), salt=SALT).mask(sample())
    assert out.rows[1]["phone"] == ""
    (col,) = report.columns
    assert (col.changed, col.empty, col.failed) == (2, 1, 0)


def test_unparseable_value_becomes_null_never_the_original() -> None:
    out, report = Masker(rules(dob="date:to=year"), salt=SALT).mask(sample())
    assert [r["dob"] for r in out.rows] == ["1990", "1985", None]
    assert report.columns[0].failed == 1
    assert report.failed_cells == 1


def test_on_error_fail_raises_without_echoing_the_value() -> None:
    masker = Masker(rules(dob="date:to=year"), salt=SALT, on_error="fail")
    with pytest.raises(DatamaskError) as info:
        masker.mask(sample())
    message = str(info.value)
    assert "'dob'" in message and "data row 3" in message
    assert "not a date" not in message


def test_bad_on_error_value() -> None:
    with pytest.raises(DatamaskError):
        Masker({}, salt=SALT, on_error="ignore")


def test_drop_removes_the_column() -> None:
    out, report = Masker(rules(note="drop"), salt=SALT).mask(sample())
    assert "note" not in out.columns and all("note" not in r for r in out.rows)
    assert report.dropped == ["note"]


def test_missing_column_is_an_error_by_default() -> None:
    with pytest.raises(DatamaskError, match="not found.*emial"):
        Masker(rules(emial="hash"), salt=SALT).mask(sample())


def test_allow_missing_skips_with_a_warning() -> None:
    _, report = Masker(rules(emial="hash"), salt=SALT, allow_missing=True).mask(sample())
    assert any("emial" in w for w in report.warnings)


def test_default_rule_covers_unlisted_columns() -> None:
    masker = Masker(rules(id="keep"), salt=SALT, default=build_strategy("redact"))
    out, report = masker.mask(sample())
    assert [r["id"] for r in out.rows] == ["1", "2", "3"]
    assert out.rows[0]["email"] == "[REDACTED]" and out.rows[0]["note"] == "[REDACTED]"
    assert report.untouched == ["id"]


def test_same_salt_same_output_different_salt_different_output() -> None:
    a, _ = Masker(rules(email="hash"), salt=b"one").mask(sample())
    b, _ = Masker(rules(email="hash"), salt=b"one").mask(sample())
    c, _ = Masker(rules(email="hash"), salt=b"two").mask(sample())
    assert a.rows == b.rows and a.rows != c.rows


def test_missing_salt_warns_and_uses_random_salt() -> None:
    out1, report = Masker(rules(email="hash")).mask(sample())
    out2, _ = Masker(rules(email="hash")).mask(sample())
    assert any("no salt" in w for w in report.warnings)
    assert out1.rows != out2.rows


def test_shuffle_keeps_the_multiset_of_values() -> None:
    table = Table(["n"], [{"n": str(i)} for i in range(20)])
    out, report = Masker(rules(n="shuffle"), salt=SALT, seed=3).mask(table)
    assert sorted(r["n"] for r in out.rows) == sorted(r["n"] for r in table.rows)
    assert [r["n"] for r in out.rows] != [r["n"] for r in table.rows]
    assert report.columns[0].changed > 10


def test_pseudonyms_are_consistent_across_rows() -> None:
    table = Table(["email"], [{"email": "a@x.org"}, {"email": "b@x.org"}, {"email": "a@x.org"}])
    out, _ = Masker(rules(email="pseudonym:kind=email"), salt=SALT).mask(table)
    assert out.rows[0]["email"] == out.rows[2]["email"] != out.rows[1]["email"]


def test_keep_is_reported_as_untouched() -> None:
    _, report = Masker(rules(id="keep"), salt=SALT).mask(sample())
    assert "id" in report.untouched and not report.columns


def test_non_string_json_values_are_masked() -> None:
    table = Table(["n", "flag"], [{"n": 42, "flag": True}])
    out, _ = Masker(rules(n="bucket:width=10", flag="hash"), salt=SALT).mask(table)
    assert out.rows[0]["n"] == "40-49"
    assert isinstance(out.rows[0]["flag"], str)
