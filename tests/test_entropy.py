"""
Unit tests for entropy functions.
"""

import pytest
from secret_leak_guard.entropy import (
    calculate_entropy,
    get_character_diversity,
    is_high_entropy,
    is_repetitive,
)


def test_calculate_entropy_empty():
    assert calculate_entropy("") == 0.0


def test_calculate_entropy_uniform():
    # All same characters -> entropy 0
    assert calculate_entropy("aaaaaaa") == 0.0


def test_calculate_entropy_high():
    # Random base64 string
    sample = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    ent = calculate_entropy(sample)
    assert ent > 4.0


def test_get_character_diversity():
    assert get_character_diversity("aaaa") == 1
    assert get_character_diversity("aaaaBB") == 2
    assert get_character_diversity("aaaaBB123") == 3
    assert get_character_diversity("aaaaBB123!@#") == 4


def test_is_repetitive():
    assert is_repetitive("aaaaaaaaaaaaaaaa") is True
    assert is_repetitive("abababababababab") is True
    assert is_repetitive("K8d$zP9#mQ2!vL5*") is False


def test_is_high_entropy_true_positives():
    # High entropy realistic API keys/secrets
    assert is_high_entropy("v8N4x7kL2mP9qZ0wR3tY6uI1") is True
    assert is_high_entropy("cGFzc3dvcmRfZXhhbXBsZV9rZXlfMTIzNA==") is True


def test_is_high_entropy_false_positives():
    # Short string
    assert is_high_entropy("short") is False
    # Known placeholder
    assert is_high_entropy("your_api_key_here") is False
    assert is_high_entropy("dummy_token") is False
    # Low diversity
    assert is_high_entropy("1111111111111111") is False
    assert is_high_entropy("abcdefghijklmnopqrst") is False
