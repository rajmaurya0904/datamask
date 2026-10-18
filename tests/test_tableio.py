import json
from pathlib import Path

import pytest

from datamask.errors import DatamaskError
from datamask.tableio import Table, detect_format, read_table, render_table, write_table


def test_detect_format_from_extension_and_override() -> None:
    assert detect_format("a.csv") == "csv"
    assert detect_format("a.NDJSON") == "jsonl"
    assert detect_format("a.json") == "json"
    assert detect_format("-") == "csv"
    assert detect_format("a.dat", "json") == "json"


def test_detect_format_rejects_unknown() -> None:
    with pytest.raises(DatamaskError, match="cannot infer"):
        detect_format("a.dat")
    with pytest.raises(DatamaskError, match="unknown format"):
        detect_format("a.csv", "xml")


def test_csv_round_trip_with_quotes_and_unicode(tmp_path: Path) -> None:
    table = Table(["a", "b"], [{"a": 'say "hi", ok', "b": "Müller"}, {"a": "x\ny", "b": ""}])
    path = tmp_path / "t.csv"
    write_table(table, str(path))
    assert read_table(str(path)).rows == table.rows


def test_csv_reader_strips_bom_and_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "t.csv"
    path.write_bytes(b"\xef\xbb\xbfid,name\n1,Ann\n\n2,Bob\n")
    table = read_table(str(path))
    assert table.columns == ["id", "name"]
    assert [r["name"] for r in table.rows] == ["Ann", "Bob"]


def test_csv_ragged_row_reports_the_line(tmp_path: Path) -> None:
    path = tmp_path / "t.csv"
    path.write_text("a,b\n1,2\n3\n", encoding="utf-8")
    with pytest.raises(DatamaskError, match="line 3: expected 2 fields, got 1"):
        read_table(str(path))


def test_csv_duplicate_and_blank_headers_rejected(tmp_path: Path) -> None:
    dup = tmp_path / "d.csv"
    dup.write_text("a,a\n1,2\n", encoding="utf-8")
    with pytest.raises(DatamaskError, match="duplicate column"):
        read_table(str(dup))
    blank = tmp_path / "b.csv"
    blank.write_text("a,,c\n1,2,3\n", encoding="utf-8")
    with pytest.raises(DatamaskError, match="blank column"):
        read_table(str(blank))


def test_empty_file_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "e.csv"
    path.write_text("", encoding="utf-8")
    with pytest.raises(DatamaskError, match="is empty"):
        read_table(str(path))


def test_missing_file_is_a_clean_error(tmp_path: Path) -> None:
    with pytest.raises(DatamaskError, match="file not found"):
        read_table(str(tmp_path / "nope.csv"))


def test_non_utf8_file_is_a_clean_error(tmp_path: Path) -> None:
    path = tmp_path / "l.csv"
    path.write_bytes(b"a\n\xff\xfe\n")
    with pytest.raises(DatamaskError, match="not valid UTF-8"):
        read_table(str(path))


def test_jsonl_round_trip_keeps_types(tmp_path: Path) -> None:
    rows = [{"id": 1, "ok": True, "n": None}, {"id": 2, "ok": False, "n": 3.5}]
    table = Table(["id", "ok", "n"], rows)
    path = tmp_path / "t.jsonl"
    write_table(table, str(path))
    assert read_table(str(path)).rows == table.rows


def test_jsonl_columns_are_the_union_of_keys(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_text('{"a":1}\n{"b":2,"a":3}\n', encoding="utf-8")
    assert read_table(str(path)).columns == ["a", "b"]


def test_jsonl_bad_line_reports_the_line(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_text('{"a":1}\n{oops\n', encoding="utf-8")
    with pytest.raises(DatamaskError, match="line 2: invalid JSON"):
        read_table(str(path))


def test_jsonl_non_object_rejected(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_text("[1,2]\n", encoding="utf-8")
    with pytest.raises(DatamaskError, match="expected a JSON object"):
        read_table(str(path))


def test_json_array_round_trip(tmp_path: Path) -> None:
    table = Table(["a"], [{"a": "é"}])
    path = tmp_path / "t.json"
    write_table(table, str(path))
    assert json.loads(path.read_text(encoding="utf-8")) == [{"a": "é"}]
    assert read_table(str(path)).rows == table.rows


def test_json_must_be_array_of_objects(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text('{"a": 1}', encoding="utf-8")
    with pytest.raises(DatamaskError, match="array of objects"):
        read_table(str(path))


def test_csv_rendering_of_none_bool_and_containers() -> None:
    table = Table(["a", "b", "c", "d"], [{"a": None, "b": True, "c": {"x": 1}, "d": 2}])
    assert render_table(table, "csv") == 'a,b,c,d\n,true,"{""x"": 1}",2\n'


def test_tsv_uses_tabs(tmp_path: Path) -> None:
    path = tmp_path / "t.tsv"
    write_table(Table(["a", "b"], [{"a": "1", "b": "2"}]), str(path))
    assert path.read_text(encoding="utf-8") == "a\tb\n1\t2\n"
    assert read_table(str(path)).rows == [{"a": "1", "b": "2"}]
