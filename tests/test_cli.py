import json
import subprocess
import sys
from pathlib import Path

import pytest

from datamask import __version__
from datamask.cli import main
from datamask.tableio import read_table

PEOPLE_CSV = (
    "id,name,email,phone,dob,notes\n"
    "1,Ann Lee,ann.lee@corp.com,+44 7700 900111,1990-02-03,Rang ann.lee@corp.com about Ann Lee\n"
    "2,Bob Ray,bob.ray@corp.com,+44 7700 900222,1985-12-31,renewal due\n"
    "3,Cy Doe,cy.doe@corp.com,,1979-06-30,\n"
)


@pytest.fixture
def people(tmp_path: Path) -> Path:
    path = tmp_path / "people.csv"
    path.write_text(PEOPLE_CSV, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def fixed_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATAMASK_SALT", "cli-test-salt")


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as info:
        main([])
    assert info.value.code == 2


def test_generate_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "-n", "3", "--seed", "1", "--fields", "id,email"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert lines[0] == "id,email" and len(lines) == 4


def test_generate_is_reproducible(tmp_path: Path) -> None:
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    for target in (a, b):
        assert main(["generate", "-n", "25", "--seed", "9", "--locale", "en,de,fr",
                     "-o", str(target)]) == 0
    assert a.read_bytes() == b.read_bytes()
    assert len(read_table(str(a)).rows) == 25


def test_generate_jsonl_and_null_rate(tmp_path: Path) -> None:
    out = tmp_path / "g.jsonl"
    assert main(["generate", "-n", "200", "--seed", "2", "--null-rate", "0.5", "-o", str(out)]) == 0
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 200 and any(r["phone"] is None for r in rows)


def test_generate_errors(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "--fields", "nope"]) == 2
    assert "unknown field" in capsys.readouterr().err
    assert main(["generate", "--as-of", "yesterday"]) == 2
    assert main(["generate", "--locale", "xx"]) == 2
    assert main(["generate", "-n", "-3"]) == 2


def test_mask_with_rules(people: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "out.csv"
    code = main(["mask", str(people), "-o", str(out), "-r", "email=hash",
                 "-r", "phone=partial:keep_last=3", "-r", "dob=date:to=year"])
    assert code == 0
    table = read_table(str(out))
    assert table.rows[0]["dob"] == "1990"
    assert table.rows[0]["phone"].endswith("111") and "7700" not in table.rows[0]["phone"]
    assert table.rows[2]["phone"] == ""
    assert "@" not in table.rows[0]["email"]
    err = capsys.readouterr().err
    assert "masked 3 rows" in err and "left as-is: id, name, notes" in err


def test_mask_is_repeatable_with_a_salt(people: Path, tmp_path: Path) -> None:
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    for target in (a, b):
        assert main(["mask", str(people), "-o", str(target), "-q",
                     "-r", "email=pseudonym:kind=email", "-r", "name=hash"]) == 0
    assert a.read_bytes() == b.read_bytes()


def test_mask_without_salt_warns(
    people: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("DATAMASK_SALT")
    assert main(["mask", str(people), "-o", str(tmp_path / "o.csv"), "-r", "email=hash"]) == 0
    assert "warning: no salt supplied" in capsys.readouterr().err


def test_mask_with_salt_file(people: Path, tmp_path: Path) -> None:
    salt = tmp_path / "salt.txt"
    salt.write_text("file-salt\n", encoding="utf-8")
    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    main(["mask", str(people), "-o", str(a), "-q", "-r", "email=hash", "--salt-file", str(salt)])
    main(["mask", str(people), "-o", str(b), "-q", "-r", "email=hash"])  # env salt instead
    assert a.read_bytes() != b.read_bytes()


def test_mask_with_config_file(people: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "m.toml"
    cfg.write_text(
        '[columns]\nemail = "email"\nnotes = "scrub:also=name"\nid = "drop"\n', encoding="utf-8"
    )
    out = tmp_path / "o.json"
    assert main(["mask", str(people), "-c", str(cfg), "-o", str(out), "-q"]) == 0
    rows = json.loads(out.read_text(encoding="utf-8"))
    assert "id" not in rows[0]
    assert rows[0]["email"].startswith("a") and rows[0]["email"].endswith("@corp.com")
    assert rows[0]["notes"] == "Rang [EMAIL] about [NAME]"


def test_cli_rule_overrides_config(people: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "m.toml"
    cfg.write_text('[columns]\nemail = "redact"\n', encoding="utf-8")
    out = tmp_path / "o.csv"
    main(["mask", str(people), "-c", str(cfg), "-r", "email=redact:text=GONE", "-o", str(out),
          "-q"])
    assert read_table(str(out)).rows[0]["email"] == "GONE"


def test_mask_auto_detects_columns(people: Path, tmp_path: Path) -> None:
    out = tmp_path / "o.csv"
    assert main(["mask", str(people), "--auto", "-o", str(out), "-q"]) == 0
    table = read_table(str(out))
    assert table.rows[0]["email"] != "ann.lee@corp.com"
    assert table.rows[0]["dob"] == "1990"
    assert "ann.lee" not in table.rows[0]["notes"] and "Ann" not in table.rows[0]["notes"]
    assert table.rows[0]["id"] == "1"


def test_mask_default_covers_everything_else(people: Path, tmp_path: Path) -> None:
    out = tmp_path / "o.csv"
    assert main(["mask", str(people), "--default", "redact", "-r", "id=keep", "-o", str(out),
                 "-q"]) == 0
    row = read_table(str(out)).rows[0]
    assert row["id"] == "1" and row["name"] == "[REDACTED]"


def test_mask_needs_rules(people: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["mask", str(people)]) == 2
    assert "no masking rules" in capsys.readouterr().err


def test_mask_unknown_column_and_allow_missing(
    people: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = str(tmp_path / "o.csv")
    assert main(["mask", str(people), "-o", out, "-r", "emial=hash"]) == 2
    assert "emial" in capsys.readouterr().err
    assert main(["mask", str(people), "-o", out, "-r", "emial=hash", "-r", "name=hash",
                 "--allow-missing"]) == 0


def test_mask_on_error_fail_exits_2(
    people: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["mask", str(people), "-o", str(tmp_path / "o.csv"), "-r", "name=date",
                 "--on-error", "fail"])
    assert code == 2
    err = capsys.readouterr().err
    assert "'name'" in err and "Ann Lee" not in err


def test_mask_on_error_null_reports_unparseable(
    people: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "o.csv"
    assert main(["mask", str(people), "-o", str(out), "-r", "name=date"]) == 0
    assert read_table(str(out)).rows[0]["name"] == ""
    assert "could not be parsed" in capsys.readouterr().err


def test_mask_missing_input_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["mask", str(tmp_path / "none.csv"), "-r", "a=hash"]) == 2
    assert "file not found" in capsys.readouterr().err


def test_mask_via_stdin_and_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("name,email\nAnn,a@b.org\n"))
    assert main(["mask", "-", "-q", "-r", "email=redact"]) == 0
    assert capsys.readouterr().out == "name,email\nAnn,[REDACTED]\n"


def test_mask_converts_formats(people: Path, tmp_path: Path) -> None:
    out = tmp_path / "o.out"
    assert main(["mask", str(people), "-o", str(out), "--out-format", "jsonl", "-q",
                 "-r", "name=hash"]) == 0
    first = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
    assert set(first) == {"id", "name", "email", "phone", "dob", "notes"}


def test_scan_prints_findings(people: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(people)]) == 0
    out = capsys.readouterr().out
    assert "email" in out and "pseudonym:kind=email" in out
    assert "no PII signal: id" in out


def test_scan_fail_on_pii_and_write_config(
    people: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "starter.toml"
    assert main(["scan", str(people), "--fail-on-pii", "--write-config", str(cfg)]) == 1
    assert "wrote" in capsys.readouterr().out
    out = tmp_path / "o.csv"
    assert main(["mask", str(people), "-c", str(cfg), "-o", str(out), "-q"]) == 0


def test_scan_clean_file_exits_zero_even_with_fail_on_pii(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "c.csv"
    path.write_text("colour,size\nred,3\nblue,4\n", encoding="utf-8")
    assert main(["scan", str(path), "--fail-on-pii"]) == 0
    assert "0 of 2 columns" in capsys.readouterr().out


def test_verify_pass_and_fail(
    people: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = tmp_path / "good.csv"
    main(["mask", str(people), "--auto", "-o", str(good), "-q"])
    assert main(["verify", str(people), str(good), "--auto"]) == 0
    assert "PASS" in capsys.readouterr().out
    bad = tmp_path / "bad.csv"
    main(["mask", str(people), "-r", "email=hash", "-o", str(bad), "-q"])
    assert main(["verify", str(people), str(bad), "--columns", "email,name"]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "unchanged in column 'name'" in out
    assert "ann.lee" not in out


def test_verify_finds_a_name_left_in_notes(
    people: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "o.csv"
    main(["mask", str(people), "-r", "name=hash", "-r", "notes=scrub", "-o", str(out), "-q"])
    assert main(["verify", str(people), str(out), "--columns", "name"]) == 1
    assert "reappears in column 'notes'" in capsys.readouterr().out


def test_verify_requires_something_to_check(
    people: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["verify", str(people), str(people)]) == 2
    assert "nothing to verify" in capsys.readouterr().err


def test_kcheck(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "k.csv"
    rows = ["yob,zip"] + ["1990,EC1"] * 5 + ["1991,EC1"] * 2 + ["1985,M1"]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert main(["kcheck", str(path), "--quasi", "yob,zip", "-k", "5"]) == 1
    out = capsys.readouterr().out
    assert "FAIL: 3 rows in 2 classes are below k=5" in out
    assert main(["kcheck", str(path), "--quasi", "zip", "-k", "1"]) == 0
    assert main(["kcheck", str(path), "--quasi", "nope"]) == 2


def test_strategies_listing(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["strategies"]) == 0
    out = capsys.readouterr().out
    for name in ("hash", "partial", "pseudonym", "scrub", "shuffle", "subnet"):
        assert name in out


def test_module_entry_point_runs(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "datamask", "generate", "-n", "2", "--seed", "1",
         "--fields", "id"],
        capture_output=True, text=True, encoding="utf-8", check=False,
    )
    assert result.returncode == 0
    assert len(result.stdout.strip().splitlines()) == 3
