import pytest

from datamask.errors import DatamaskError
from datamask.strategies import Context, build_strategy, is_empty, parse_date, text_of

CTX = Context(salt=b"unit-test-salt", seed=42)


def run(spec: str, value):
    return build_strategy(spec).apply(value, CTX)


def test_keep_and_nullify_and_redact() -> None:
    assert run("keep", "x") == "x"
    assert run("nullify", "x") is None
    assert run("redact", "x") == "[REDACTED]"
    assert run("redact:text=GONE", "x") == "GONE"


def test_hash_is_deterministic_and_salted() -> None:
    a = run("hash", "ann@example.org")
    assert a == run("hash", "ann@example.org")
    assert a != run("hash", "bob@example.org")
    other = build_strategy("hash").apply("ann@example.org", Context(salt=b"different"))
    assert a != other


def test_hash_length_and_fold() -> None:
    assert len(run("hash:length=24", "x")) == 24
    assert run("hash:fold=true", " ANN@x.org ") == run("hash:fold=true", "ann@x.org")
    assert run("hash", " ANN@x.org ") != run("hash", "ann@x.org")


def test_hash_length_bounds() -> None:
    with pytest.raises(DatamaskError, match="between 8 and 64"):
        build_strategy("hash:length=4")


def test_partial_keeps_last_digits_and_separators() -> None:
    assert run("partial:keep_last=4", "4000 0040 6812 4159") == "**** **** **** 4159"


def test_partial_keep_first_and_last() -> None:
    assert run("partial:keep_first=2,keep_last=2", "ABCDEFGH") == "AB****GH"


def test_partial_masks_everything_when_value_is_too_short() -> None:
    assert run("partial:keep_first=3,keep_last=3", "abcd") == "****"


def test_partial_custom_char() -> None:
    assert run("partial:keep_last=1,char=#", "abc") == "##c"


def test_partial_rejects_bad_options() -> None:
    with pytest.raises(DatamaskError):
        build_strategy("partial:keep_last=-1")
    with pytest.raises(DatamaskError):
        build_strategy("partial:char=ab")


def test_email_masks_local_part_and_keeps_domain() -> None:
    out = run("email", "john.smith@mail.example")
    assert out.startswith("j") and out.endswith("@mail.example")
    assert "john" not in out and "smith" not in out


def test_email_can_replace_the_domain() -> None:
    assert run("email:keep_domain=false", "a@real-company.com").endswith("@masked.invalid")


def test_email_rejects_non_addresses() -> None:
    with pytest.raises(ValueError):
        run("email", "not-an-email")


def test_pseudonym_is_consistent_per_input() -> None:
    assert run("pseudonym:kind=full_name", "Ann Lee") == run("pseudonym:kind=full_name", "Ann Lee")


def test_pseudonym_changes_with_input_and_salt() -> None:
    values = {run("pseudonym:kind=email", f"user{i}@x.org") for i in range(50)}
    assert len(values) == 50
    other = build_strategy("pseudonym:kind=email").apply("user1@x.org", Context(salt=b"zzz"))
    assert other != run("pseudonym:kind=email", "user1@x.org")


@pytest.mark.parametrize("kind", ["first_name", "last_name", "phone", "iban", "card_number", "dob"])
def test_pseudonym_supports_many_kinds(kind: str) -> None:
    assert run(f"pseudonym:kind={kind}", "original")


def test_pseudonym_email_never_echoes_the_original() -> None:
    out = run("pseudonym:kind=email,locale=de", "real.person@company.com")
    assert "real.person" not in out
    assert "company.com" not in out
    assert out.split("@")[1] in {"mail.example", "inbox.example", "post.example",
                                 "example.org", "example.net"}


def test_pseudonym_requires_a_valid_kind_and_locale() -> None:
    with pytest.raises(DatamaskError, match="needs kind"):
        build_strategy("pseudonym")
    with pytest.raises(DatamaskError, match="unknown kind"):
        build_strategy("pseudonym:kind=shoe")
    with pytest.raises(DatamaskError, match="unknown locale"):
        build_strategy("pseudonym:kind=email,locale=xx")


def test_pseudonym_name_is_an_alias_for_full_name() -> None:
    assert " " in run("pseudonym:kind=name", "Ann")


@pytest.mark.parametrize(
    ("to", "expected"),
    [("year", "1999"), ("month", "1999-08"), ("decade", "1990s")],
)
def test_date_generalisation(to: str, expected: str) -> None:
    assert run(f"date:to={to}", "1999-08-06") == expected


def test_date_accepts_common_formats_and_rejects_garbage() -> None:
    assert parse_date("06/08/1999").year == 1999
    assert parse_date("06.08.1999").month == 8
    assert parse_date("1999-08-06T10:30:00").day == 6
    with pytest.raises(ValueError):
        run("date", "last tuesday")


def test_date_rejects_unknown_granularity() -> None:
    with pytest.raises(DatamaskError):
        build_strategy("date:to=week")


def test_bucket() -> None:
    assert run("bucket:width=10", "34") == "30-39"
    assert run("bucket:width=5", 34) == "30-34"
    assert run("bucket", "0") == "0-9"
    with pytest.raises(ValueError):
        run("bucket", "abc")


def test_prefix_drops_the_rest_and_spaces() -> None:
    assert run("prefix:keep=3", "EC1A 1BB") == "EC1"


def test_subnet_v4_and_v6() -> None:
    assert run("subnet", "203.0.113.77") == "203.0.113.0/24"
    assert run("subnet:v4=16", "203.0.113.77") == "203.0.0.0/16"
    assert run("subnet", "2001:db8:1:2:3:4:5:6") == "2001:db8:1::/48"
    with pytest.raises(ValueError):
        run("subnet", "999.1.1.1")


def test_noise_is_bounded_and_deterministic() -> None:
    out = [run("noise:pct=10", str(v)) for v in range(1000, 1200)]
    assert all(900 <= x <= 1320 for x in out)
    assert run("noise", "1000") == run("noise", "1000")
    assert len(set(out)) > 100


def test_noise_keeps_integers_integral_and_honours_decimals() -> None:
    assert isinstance(run("noise", "500"), int)
    assert isinstance(run("noise", "12.5"), float)
    assert run("noise:decimals=0", "12.5") == round(run("noise:decimals=0", "12.5"))


def test_noise_rejects_bad_pct() -> None:
    with pytest.raises(DatamaskError):
        build_strategy("noise:pct=0")


def test_shuffle_is_a_permutation_and_seeded() -> None:
    values = list(range(30))
    s = build_strategy("shuffle")
    out = s.apply_column(values, CTX)
    assert sorted(out) == values and out != values
    assert out == s.apply_column(values, CTX)


def test_empty_cells_pass_through_column_application() -> None:
    s = build_strategy("hash")
    assert s.apply_column(["a", "", None], CTX)[1:] == ["", None]


def test_spec_parsing_errors() -> None:
    with pytest.raises(DatamaskError, match="unknown strategy"):
        build_strategy("scramble")
    with pytest.raises(DatamaskError, match="unknown parameter"):
        build_strategy("partial:keeplast=4")
    with pytest.raises(DatamaskError, match="key=value"):
        build_strategy("partial:4")
    with pytest.raises(DatamaskError, match="must be int"):
        build_strategy("partial:keep_last=four")


def test_table_style_spec_and_type_checks() -> None:
    s = build_strategy({"strategy": "partial", "keep_last": 2})
    assert s.apply("abcd", CTX) == "**cd"
    with pytest.raises(DatamaskError, match="must be int"):
        build_strategy({"strategy": "partial", "keep_last": "x1"})
    with pytest.raises(DatamaskError, match="strategy"):
        build_strategy({"keep_last": 2})
    with pytest.raises(DatamaskError):
        build_strategy(5)  # type: ignore[arg-type]


def test_text_of_and_is_empty() -> None:
    assert text_of(True) == "true"
    assert text_of({"b": 1, "a": 2}) == '{"a": 2, "b": 1}'
    assert is_empty(None) and is_empty("") and not is_empty(0)


def test_scrub_replaces_embedded_pii_and_keeps_the_rest() -> None:
    out = run("scrub", "Customer ann@mail.example called from +44 7700 900123 about order 42")
    assert out == "Customer [EMAIL] called from [PHONE] about order 42"


def test_scrub_kinds_subset() -> None:
    out = run("scrub:kinds=email", "ann@mail.example from 203.0.113.9")
    assert out == "[EMAIL] from 203.0.113.9"


def test_scrub_rejects_unknown_kinds() -> None:
    with pytest.raises(DatamaskError, match="scrub"):
        build_strategy("scrub:kinds=email+dna")


def test_drop_is_registered() -> None:
    assert build_strategy("drop").name == "drop"


@pytest.mark.parametrize("kind", ["first_name", "last_name", "country", "occupation"])
def test_pseudonym_never_maps_a_value_to_itself(kind: str) -> None:
    from datamask.generate import Generator

    spec = build_strategy(f"pseudonym:kind={kind}")
    # Feed the strategy its own possible outputs: small vocabularies would collide often.
    pool = {Generator(seed=i).field(kind) for i in range(300)}
    assert all(spec.apply(v, CTX) != v for v in pool)
