from pathlib import Path

import pytest

from datamask.config import (
    config_from_dict,
    load_config,
    parse_rule_args,
    render_config,
    resolve_salt,
)
from datamask.errors import DatamaskError


def write(tmp_path: Path, text: str) -> str:
    path = tmp_path / "mask.toml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_load_full_config(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        'seed = 5\non_error = "fail"\ndefault = "redact"\n'
        '[columns]\nemail = "hash:length=12"\n'
        'phone = { strategy = "partial", keep_last = 4 }\n',
    )
    cfg = load_config(path)
    assert cfg.seed == 5 and cfg.on_error == "fail" and cfg.default.name == "redact"
    assert cfg.rules["email"].options["length"] == 12
    assert cfg.rules["phone"].options["keep_last"] == 4


def test_missing_config_file(tmp_path: Path) -> None:
    with pytest.raises(DatamaskError, match="config file not found"):
        load_config(str(tmp_path / "nope.toml"))


def test_invalid_toml(tmp_path: Path) -> None:
    with pytest.raises(DatamaskError, match="invalid TOML"):
        load_config(write(tmp_path, "[columns\nx = 1"))


def test_unknown_top_level_key(tmp_path: Path) -> None:
    with pytest.raises(DatamaskError, match="unknown key.*colums"):
        load_config(write(tmp_path, '[colums]\nemail = "hash"\n'))


def test_bad_rule_names_the_column(tmp_path: Path) -> None:
    with pytest.raises(DatamaskError, match="rule for 'email'.*unknown strategy"):
        load_config(write(tmp_path, '[columns]\nemail = "scramble"\n'))


@pytest.mark.parametrize(
    "data",
    [{"seed": "x"}, {"seed": True}, {"on_error": "ignore"}, {"salt": ""}, {"columns": 3}],
)
def test_bad_scalar_values(data: dict) -> None:
    with pytest.raises(DatamaskError):
        config_from_dict(data)


def test_parse_rule_args() -> None:
    rules = parse_rule_args(["email=hash", "card=partial:keep_last=4"])
    assert rules["card"].options["keep_last"] == 4


@pytest.mark.parametrize("bad", ["email", "=hash", "email="])
def test_parse_rule_args_rejects_malformed(bad: str) -> None:
    with pytest.raises(DatamaskError, match="--rule expects"):
        parse_rule_args([bad])


def test_parse_rule_args_names_column_on_bad_spec() -> None:
    with pytest.raises(DatamaskError, match="--rule email: unknown strategy"):
        parse_rule_args(["email=wat"])


def test_salt_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    salt_file = tmp_path / "salt.txt"
    salt_file.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("DATAMASK_SALT", "from-env")
    assert resolve_salt("from-config", salt_file=str(salt_file)) == b"from-file"
    assert resolve_salt("from-config") == b"from-env"
    monkeypatch.delenv("DATAMASK_SALT")
    assert resolve_salt("from-config") == b"from-config"
    assert resolve_salt() is None


def test_custom_salt_env_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SALT", "abc")
    assert resolve_salt(env_name="MY_SALT") == b"abc"


def test_salt_file_errors(tmp_path: Path) -> None:
    with pytest.raises(DatamaskError, match="cannot read salt file"):
        resolve_salt(salt_file=str(tmp_path / "missing"))
    empty = tmp_path / "empty"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(DatamaskError, match="empty"):
        resolve_salt(salt_file=str(empty))


def test_render_config_round_trips(tmp_path: Path) -> None:
    text = render_config({"e-mail": "pseudonym:kind=email", 'we"ird': "hash"}, header="# hi")
    cfg = load_config(write(tmp_path, text))
    assert set(cfg.rules) == {"e-mail", 'we"ird'}
    assert text.startswith("# hi\n")
