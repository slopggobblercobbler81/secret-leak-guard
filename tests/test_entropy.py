"""
Unit tests for entropy functions.
"""

import math
import pytest
from secret_leak_guard.entropy import (
    calculate_entropy,
    calculate_normalized_entropy,
    calculate_sliding_entropy,
    get_character_diversity,
    is_high_entropy,
    is_repetitive,
)


def test_calculate_entropy_empty():
    assert calculate_entropy("") == 0.0


def test_calculate_entropy_uniform():
    assert calculate_entropy("aaaaaaa") == 0.0


def test_calculate_entropy_high():
    sample = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    ent = calculate_entropy(sample)
    assert ent > 4.0


def test_calculate_normalized_entropy(monkeypatch):
    assert calculate_normalized_entropy("") == 0.0
    assert calculate_normalized_entropy("a") == 0.0
    assert calculate_normalized_entropy("aaaaaaa") == 0.0
    assert calculate_normalized_entropy("abcdefgh") == 1.0

    sample = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    norm_ent = calculate_normalized_entropy(sample)
    assert 0.0 < norm_ent <= 1.0

    # Test edge branch where max_entropy <= 0
    monkeypatch.setattr(math, "log2", lambda x: 0.0)
    assert calculate_normalized_entropy("abcdef") == 0.0


def test_calculate_sliding_entropy():
    assert calculate_sliding_entropy("") == []
    assert calculate_sliding_entropy("abc", window_size=10) == []
    assert calculate_sliding_entropy("abcdef", window_size=0) == []
    assert calculate_sliding_entropy("abcdef", step=0) == []

    uniform = calculate_sliding_entropy("aaaaaaaa", window_size=4, step=1)
    assert len(uniform) == 5
    assert all(val == 0.0 for val in uniform)

    mixed = "aaaa" + "K8d$zP9#mQ2!vL5*"
    sliding = calculate_sliding_entropy(mixed, window_size=8, step=4)
    assert len(sliding) == 4
    assert sliding[-1] > sliding[0]


def test_get_character_diversity():
    assert get_character_diversity("aaaa") == 1
    assert get_character_diversity("aaaaBB") == 2
    assert get_character_diversity("aaaaBB123") == 3
    assert get_character_diversity("aaaaBB123!@#") == 4


def test_is_repetitive():
    assert is_repetitive("ab") is False
    assert is_repetitive("aaaaaaaaaaaaaaaa") is True
    assert is_repetitive("abababababababab") is True
    assert is_repetitive("K8d$zP9#mQ2!vL5*") is False


def test_is_high_entropy_true_positives():
    assert is_high_entropy("v8N4x7kL2mP9qZ0wR3tY6uI1") is True
    assert is_high_entropy("cGFzc3dvcmRfZXhhbXBsZV9rZXlfMTIzNA==") is True


def test_is_high_entropy_false_positives():
    assert is_high_entropy("short") is False
    assert is_high_entropy("   " + "a" * 10 + "   ", min_length=16) is False
    assert is_high_entropy("your_api_key_here") is False
    assert is_high_entropy("your_token_1234567890abcdef") is False
    assert is_high_entropy("dummy_token") is False
    assert is_high_entropy("1111111111111111") is False
    assert is_high_entropy("abcdefghijklmnopqrst") is False
