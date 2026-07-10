import pytest

from securevault.passwordgen import (
    AMBIGUOUS,
    DIGITS,
    LOWER,
    SYMBOLS,
    UPPER,
    PasswordPolicy,
    estimate_entropy_bits,
    generate_password,
)


def test_default_policy_produces_default_length():
    assert len(generate_password()) == 20


@pytest.mark.parametrize("length", [8, 12, 64, 256])
def test_length_is_respected(length):
    policy = PasswordPolicy(length=length)
    assert len(generate_password(policy)) == length


def test_passwords_are_not_repeated():
    passwords = {generate_password() for _ in range(200)}
    assert len(passwords) == 200


def test_each_selected_category_is_represented():
    policy = PasswordPolicy(length=64, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    pw = generate_password(policy)
    assert any(c in UPPER for c in pw)
    assert any(c in LOWER for c in pw)
    assert any(c in DIGITS for c in pw)
    assert any(c in SYMBOLS for c in pw)


def test_disabled_categories_are_excluded():
    policy = PasswordPolicy(length=32, use_upper=False, use_symbols=False)
    pw = generate_password(policy)
    assert not any(c in UPPER for c in pw)
    assert not any(c in SYMBOLS for c in pw)


def test_exclude_ambiguous_removes_confusable_characters():
    policy = PasswordPolicy(length=64, exclude_ambiguous=True)
    pw = generate_password(policy)
    assert not any(c in AMBIGUOUS for c in pw)


def test_no_categories_selected_raises():
    policy = PasswordPolicy(use_upper=False, use_lower=False, use_digits=False, use_symbols=False)
    with pytest.raises(ValueError):
        generate_password(policy)


def test_length_shorter_than_category_count_raises():
    policy = PasswordPolicy(length=2, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    with pytest.raises(ValueError):
        generate_password(policy)


def test_length_out_of_bounds_raises():
    with pytest.raises(ValueError):
        generate_password(PasswordPolicy(length=4))
    with pytest.raises(ValueError):
        generate_password(PasswordPolicy(length=1000))


def test_entropy_estimate_zero_for_empty_string():
    assert estimate_entropy_bits("") == 0.0


def test_entropy_estimate_increases_with_length():
    assert estimate_entropy_bits("aaaaaaaaaa") > estimate_entropy_bits("aaa")


def test_entropy_estimate_increases_with_pool_diversity():
    same_pool = estimate_entropy_bits("aaaaaaaa")
    mixed_pool = estimate_entropy_bits("aA1!aA1!")
    assert mixed_pool > same_pool
