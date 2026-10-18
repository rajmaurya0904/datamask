import pytest

from datamask.checks import iban_check_digits, iban_valid, luhn_check_digit, luhn_valid


@pytest.mark.parametrize("number", ["4539578763621486", "79927398713", "4111111111111111"])
def test_luhn_accepts_valid_numbers(number: str) -> None:
    assert luhn_valid(number)


@pytest.mark.parametrize("number", ["4539578763621487", "79927398710", "abc", "1", ""])
def test_luhn_rejects_invalid_numbers(number: str) -> None:
    assert not luhn_valid(number)


def test_luhn_check_digit_completes_number() -> None:
    assert luhn_check_digit("7992739871") == "3"


def test_luhn_check_digit_rejects_non_digits() -> None:
    with pytest.raises(ValueError):
        luhn_check_digit("12ab")


@pytest.mark.parametrize(
    "iban",
    ["GB82 WEST 1234 5698 7654 32", "DE89370400440532013000", "FR1420041010050500013M02606"],
)
def test_iban_accepts_published_examples(iban: str) -> None:
    assert iban_valid(iban)


@pytest.mark.parametrize("iban", ["GB82WEST12345698765433", "DE00370400440532013000", "xx", ""])
def test_iban_rejects_bad_checksums(iban: str) -> None:
    assert not iban_valid(iban)


def test_iban_check_digits_match_known_example() -> None:
    assert iban_check_digits("DE", "370400440532013000") == "89"
