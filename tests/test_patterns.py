import pytest

from datamask.patterns import find_pii, looks_like_ip, looks_like_phone, scrub_text


def kinds(text: str) -> list[str]:
    return [m.kind for m in find_pii(text)]


def test_finds_email_in_sentence() -> None:
    text = "Please write to ann.lee@mail.example about it."
    (m,) = find_pii(text)
    assert m.kind == "email" and text[m.start : m.end] == "ann.lee@mail.example"


def test_finds_ipv4_and_ipv6_but_not_version_numbers() -> None:
    assert kinds("from 203.0.113.9 today") == ["ip"]
    assert kinds("from 2001:db8::ff00:42:8329 today") == ["ip"]
    assert kinds("release 1.2.3 and 10.0.0.999") == []


def test_finds_luhn_valid_cards_only() -> None:
    assert kinds("card 4111 1111 1111 1111 on file") == ["card"]
    assert kinds("card 4111 1111 1111 1112 on file") == []


def test_finds_valid_iban_with_spaces() -> None:
    assert kinds("pay to GB82 WEST 1234 5698 7654 32 please") == ["iban"]
    assert "iban" not in kinds("pay to GB00 WEST 1234 5698 7654 32 please")


def test_finds_phone_numbers_with_plus_or_grouping() -> None:
    assert kinds("call +44 7700 900123 now") == ["phone"]
    assert kinds("call 07700 900123 now") == ["phone"]
    assert kinds("call (030) 23125 625") == ["phone"]


def test_dates_and_short_numbers_are_not_phones() -> None:
    assert kinds("signed on 2023-06-22 10:30") == []
    assert kinds("signed 22/06/2023") == []
    assert kinds("order 12345") == []


def test_matches_do_not_overlap_and_are_ordered() -> None:
    text = "a@b.org then 4111 1111 1111 1111 then 203.0.113.1"
    assert kinds(text) == ["email", "card", "ip"]


def test_kind_filter() -> None:
    assert kinds("a@b.org 203.0.113.1") == ["email", "ip"]
    assert [m.kind for m in find_pii("a@b.org 203.0.113.1", ("ip",))] == ["ip"]


def test_scrub_text_replaces_with_tokens() -> None:
    out = scrub_text("Mail ann@mail.example or ring +44 7700 900123 from 203.0.113.9.")
    assert out == "Mail [EMAIL] or ring [PHONE] from [IP]."


def test_scrub_text_leaves_clean_text_alone() -> None:
    assert scrub_text("nothing personal here, order 42") == "nothing personal here, order 42"


@pytest.mark.parametrize("text", ["203.0.113.9", "::1", "2001:db8::1"])
def test_looks_like_ip_true(text: str) -> None:
    assert looks_like_ip(text)


@pytest.mark.parametrize("text", ["300.1.1.1", "abc", "1.2.3"])
def test_looks_like_ip_false(text: str) -> None:
    assert not looks_like_ip(text)


def test_looks_like_phone_bounds() -> None:
    assert looks_like_phone("+49 30 23125625")
    assert not looks_like_phone("1234567")
    assert not looks_like_phone("+1234567890123456")
