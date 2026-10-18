import re
from datetime import date

import pytest

from datamask.checks import iban_valid, luhn_valid
from datamask.errors import DatamaskError
from datamask.generate import (
    ALL_FIELDS,
    DEFAULT_FIELDS,
    Generator,
    generate,
    parse_fields,
    parse_locales,
    slugify,
)


def test_same_seed_gives_same_rows() -> None:
    assert generate(20, seed=7, locales="en,de,fr") == generate(20, seed=7, locales="en,de,fr")


def test_different_seed_gives_different_rows() -> None:
    assert generate(5, seed=1) != generate(5, seed=2)


def test_row_count_and_default_fields() -> None:
    rows = generate(12, seed=3)
    assert len(rows) == 12
    assert tuple(rows[0]) == DEFAULT_FIELDS


def test_field_selection_keeps_requested_order() -> None:
    rows = generate(2, fields="email,id", seed=1)
    assert list(rows[0]) == ["email", "id"]


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(DatamaskError, match="unknown field"):
        parse_fields("email,shoe_size")


def test_unknown_locale_is_rejected() -> None:
    with pytest.raises(DatamaskError, match="unknown locale"):
        parse_locales("xx")


def test_zero_rows_is_fine_and_negative_is_not() -> None:
    assert generate(0, seed=1) == []
    with pytest.raises(DatamaskError):
        generate(-1, seed=1)


def test_emails_are_unique_and_use_reserved_domains() -> None:
    rows = generate(400, seed=5, locales="en,de,fr")
    emails = [r["email"] for r in rows]
    assert len(set(emails)) == len(emails)
    domains = {e.rsplit("@", 1)[1] for e in emails}
    assert all(d.endswith("example") or d.startswith("example.") for d in domains)


def test_ids_are_unique_uuids() -> None:
    rows = generate(200, seed=9)
    ids = [r["id"] for r in rows]
    assert len(set(ids)) == 200
    assert all(re.fullmatch(r"[0-9a-f-]{36}", i) for i in ids)


def test_cards_and_ibans_pass_their_checksums() -> None:
    for row in generate(150, seed=11, locales="en,de,fr"):
        assert luhn_valid(row["card_number"])
        assert iban_valid(row["iban"])


def test_ip_addresses_are_documentation_ranges() -> None:
    for row in generate(100, seed=2):
        assert row["ip_address"].startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_phone_numbers_use_fictional_ranges() -> None:
    for row in generate(60, seed=4, locales="en,de,fr"):
        assert row["phone"].startswith(("07700 900", "+49 30 23125", "+33 6 39 98"))


def test_uk_national_id_uses_unissued_prefix() -> None:
    for row in generate(30, seed=6, locales="en"):
        assert re.fullmatch(r"QQ\d{6}[A-D]", row["national_id"])


def test_french_national_id_key_is_consistent() -> None:
    for row in generate(30, seed=6, locales="fr"):
        nid = row["national_id"]
        assert len(nid) == 15
        assert int(nid[:13]) % 97 + int(nid[13:]) == 97


def test_ages_are_between_18_and_85_at_the_reference_date() -> None:
    as_of = date(2026, 1, 1)
    for row in generate(200, seed=8, as_of=as_of):
        age_days = (as_of - date.fromisoformat(row["dob"])).days
        assert 18 * 365 <= age_days <= 85 * 365


def test_consent_date_present_only_with_consent() -> None:
    for row in generate(200, seed=10):
        if row["marketing_consent"]:
            assert row["consent_date"] >= row["signup_date"]
        else:
            assert row["consent_date"] is None


def test_country_matches_requested_locale() -> None:
    rows = generate(30, seed=1, locales="de")
    assert {r["country"] for r in rows} == {"Germany"}


def test_null_rate_blanks_some_values_but_never_the_id() -> None:
    rows = generate(400, seed=1, null_rate=0.3)
    assert all(r["id"] for r in rows)
    nulls = sum(r["phone"] is None for r in rows)
    assert 60 < nulls < 180


def test_null_rate_must_be_a_probability() -> None:
    with pytest.raises(DatamaskError):
        Generator(null_rate=1.5)


def test_every_field_is_producible() -> None:
    rows = generate(3, fields=",".join(ALL_FIELDS), seed=1)
    assert set(rows[0]) == set(ALL_FIELDS)


def test_slugify_transliterates_umlauts_and_accents() -> None:
    assert slugify("Müller") == "mueller"
    assert slugify("Éloïse") == "eloise"
    assert slugify("Straße") == "strasse"


def test_field_generates_every_kind_with_the_right_shape() -> None:
    gen = Generator(seed=5, locales="en,de,fr")
    for name in ALL_FIELDS:
        value = gen.field(name)
        if name == "consent_date":
            assert value is None or isinstance(value, str)
        else:
            assert value not in ("", None), name
    assert luhn_valid(gen.field("card_number"))
    assert iban_valid(gen.field("iban"))
    assert "@" in gen.field("email")
    assert " " in gen.field("full_name")


def test_field_is_reproducible() -> None:
    a = [Generator(seed=3).field("last_name") for _ in range(3)]
    assert a[0] == a[1] == a[2]
