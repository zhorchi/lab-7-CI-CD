from app.utils import is_prime, is_even


def test_prime_number():
    assert is_prime(7) is True


def test_composite_number():
    assert is_prime(10) is False


def test_one_is_not_prime():
    assert is_prime(1) is False


def test_negative_number_is_not_prime():
    assert is_prime(-5) is False


def test_even_number():
    assert is_even(10) is True
    assert is_even(7) is False
