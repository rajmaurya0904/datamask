import pytest

from datamask.detect import (
    APPLY_THRESHOLD,
    classify_column,
    header_kind,
    header_tokens,
    scan_table,
    suggest_rules,
)
from datamask.generate import generate
from datamask.tableio import Table


@pytest.mark.parametrize(
    ("header", "kind"),
    [
        ("email", "email"),
        ("Email Address", "email"),
        ("contactEmail", "email"),
        ("phone_number", "phone"),
        ("mobile", "phone"),
        ("date_of_birth", "dob"),
        ("DOB", "dob"),
        ("birthDate", "dob"),
        ("first_name", "first_name"),
        ("FirstName", "first_name"),
        ("surname", "last_name"),
        ("name", "full_name"),
        ("ip_address", "ip"),
        ("last_login_ip", "ip"),
        ("street_address", "street"),
        ("zip", "postcode"),
        ("card_number", "card"),
        ("iban", "iban"),
        ("ssn", "national_id"),
        ("age", "age"),
        ("salary", "salary"),
        ("comments", "free_text"),
    ],
)
def test_header_kinds(header: str, kind: str) -> None:
    assert header_kind(header) == kind


@pytest.mark.parametrize("header", ["id", "order_total", "country", "page", "status", "created_at"])
def test_headers_that_are_not_pii(header: str) -> None:
    assert header_kind(header) is None


def test_header_tokens_split_camel_case_and_separators() -> None:
    assert header_tokens("userEmail_address") == ["user", "email", "address"]


def test_values_confirm_the_header() -> None:
    f = classify_column("email", ["a@x.org", "b@y.com", "c@z.net"])
    assert f.kind == "email" and f.confidence >= 0.9
    assert f.strategy == "pseudonym:kind=email"
    assert "100%" in f.evidence


def test_header_without_matching_values_is_low_confidence() -> None:
    f = classify_column("email", ["call me", "n/a", "tbd"])
    assert f.kind == "email" and f.confidence < APPLY_THRESHOLD
    assert not f.applied_by_default


def test_values_alone_can_identify_a_column() -> None:
    f = classify_column("c7", ["4111 1111 1111 1111", "5500 0000 0000 0004"])
    assert f.kind == "card" and "name gives no hint" in f.evidence
    f = classify_column("x", ["203.0.113.5", "198.51.100.77"])
    assert f.kind == "ip"
    f = classify_column("acct", ["GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"])
    assert f.kind == "iban"


def test_bare_digit_runs_are_not_phones_without_a_header() -> None:
    assert classify_column("ref", ["1234567890", "9876543210"]) is None
    assert classify_column("ref", ["+44 7700 900123", "+49 30 23125625"]).kind == "phone"


def test_dates_need_a_birth_header_to_count_as_dob() -> None:
    assert classify_column("signup_date", ["2020-01-02", "2021-03-04"]) is None
    assert classify_column("dob", ["2020-01-02", "2021-03-04"]).kind == "dob"


def test_free_text_with_embedded_pii_is_flagged_and_suggests_scrub() -> None:
    values = ["called from 203.0.113.9", "email ann@mail.example please", "all fine"]
    f = classify_column("body", values)
    assert f.kind == "free_text" and f.strategy == "scrub"
    assert "2 of 3" in f.evidence


def test_notes_column_without_pii_is_a_weak_finding() -> None:
    f = classify_column("notes", ["met at the fair", "prefers mornings"])
    assert f.confidence < APPLY_THRESHOLD and "names in prose" in f.evidence


def test_clean_column_and_empty_column_give_nothing() -> None:
    assert classify_column("colour", ["red", "green", "blue"]) is None
    assert classify_column("email", ["", None, ""]) is None


def test_scan_of_generated_people_finds_the_obvious_columns() -> None:
    rows = generate(150, seed=21, locales="en,de,fr", fields="id,first_name,email,phone,dob,"
                    "postcode,iban,card_number,ip_address,signup_date")
    table = Table(list(rows[0]), rows)
    kinds = {f.column: f.kind for f in scan_table(table)}
    assert kinds == {
        "first_name": "first_name",
        "email": "email",
        "phone": "phone",
        "dob": "dob",
        "postcode": "postcode",
        "iban": "iban",
        "card_number": "card",
        "ip_address": "ip",
    }


def test_suggest_rules_applies_threshold() -> None:
    table = Table(["email", "notes"], [{"email": "a@b.org", "notes": "hello"}])
    assert suggest_rules(table) == {"email": "pseudonym:kind=email"}
    assert set(suggest_rules(table, threshold=0.4)) == {"email", "notes"}


def test_sampling_handles_large_columns() -> None:
    values = [f"user{i}@x.org" for i in range(5000)]
    assert classify_column("email", values).kind == "email"


def test_scan_points_scrub_at_the_name_columns() -> None:
    table = Table(
        ["full_name", "notes"],
        [{"full_name": "Ann Lee", "notes": "ring ann@mail.example today"}],
    )
    by_col = {f.column: f for f in scan_table(table)}
    assert by_col["notes"].strategy == "scrub:also=full_name"
