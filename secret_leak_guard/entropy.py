"""
Entropy calculation and heuristics for secret detection.
"""

import math
from collections import Counter
from typing import List, Set

BENIGN_PLACEHOLDERS: Set[str] = {
    "your_api_key_here",
    "your_secret_key_here",
    "insert_token_here",
    "replace_with_your_key",
    "replace_me",
    "example_api_key",
    "example_token",
    "test_api_key",
    "test_secret_key",
    "dummy_api_key",
    "dummy_token",
    "changeme",
    "password123",
    "secret123",
    "admin123",
    "xxxxxxxxxxxxxxxx",
    "0000000000000000",
}

BASE58_ALPHABET: str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_CHARSET: Set[str] = set(BASE58_ALPHABET)


def calculate_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string in bits per character.
    Returns 0.0 for empty strings.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_normalized_entropy(data: str) -> float:
    """
    Calculate the normalized Shannon entropy (metric entropy) of a string,
    scaled between 0.0 and 1.0 relative to maximum theoretical entropy log2(len(data)).
    Returns 0.0 for strings of length <= 1.
    """
    if not data or len(data) <= 1:
        return 0.0
    raw_entropy = calculate_entropy(data)
    max_entropy = math.log2(len(data))
    if max_entropy <= 0:
        return 0.0
    return round(min(1.0, raw_entropy / max_entropy), 4)


def calculate_sliding_entropy(data: str, window_size: int = 16, step: int = 1) -> List[float]:
    """
    Calculate Shannon entropy across sliding windows of a given size.
    Returns an empty list if data length is less than window_size or if window_size/step is non-positive.
    """
    if not data or len(data) < window_size or window_size <= 0 or step <= 0:
        return []
    results: List[float] = []
    for i in range(0, len(data) - window_size + 1, step):
        window = data[i : i + window_size]
        results.append(calculate_entropy(window))
    return results


def is_base58(data: str) -> bool:
    """
    Check if a string consists exclusively of valid Base58 characters
    (Bitcoin/IPFS/Solana alphabet: no 0, O, I, or l).
    Returns False for empty strings or strings with invalid characters.
    """
    if not data:
        return False
    return set(data).issubset(BASE58_CHARSET)


def calculate_base58_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a Base58 string.
    Returns 0.0 if data is empty or contains non-Base58 characters.
    """
    if not data or not is_base58(data):
        return 0.0
    return calculate_entropy(data)


def get_character_diversity(data: str) -> int:
    """
    Counts how many distinct character classes are represented:
    1. Lowercase letters (a-z)
    2. Uppercase letters (A-Z)
    3. Digits (0-9)
    4. Special symbols / punctuation
    """
    has_lower = any(c.islower() for c in data)
    has_upper = any(c.isupper() for c in data)
    has_digit = any(c.isdigit() for c in data)
    has_symbol = any(not c.isalnum() for c in data)
    return sum([has_lower, has_upper, has_digit, has_symbol])


def is_repetitive(data: str) -> bool:
    """
    Check if string is overly repetitive (e.g. 'aaaaaaaa', 'abcabcabc').
    """
    if len(data) < 4:
        return False
    counts = Counter(data)
    if counts.most_common(1)[0][1] / len(data) > 0.6:
        return True
    if len(set(data)) <= 3 and len(data) >= 12:
        return True
    return False


def is_high_entropy(
    data: str,
    threshold: float = 3.6,
    min_length: int = 16,
    min_diversity: int = 2,
) -> bool:
    """
    Determines if candidate string exhibits high entropy consistent with API keys,
    secrets, or cryptographic tokens.
    """
    if not data or len(data) < min_length:
        return False

    cleaned = data.strip().strip("'\"`")
    if len(cleaned) < min_length:
        return False

    lower_val = cleaned.lower()
    if lower_val in BENIGN_PLACEHOLDERS:
        return False
    if any(p in lower_val for p in ["your_token", "your_api", "insert_key", "replace_with"]):
        return False

    if is_repetitive(cleaned):
        return False

    if get_character_diversity(cleaned) < min_diversity:
        return False

    ent = calculate_entropy(cleaned)
    return ent >= threshold


def is_high_entropy_base58(
    data: str,
    threshold: float = 4.0,
    min_length: int = 32,
) -> bool:
    """
    Determines if candidate string exhibits high entropy consistent with Base58 / Solana private keys.
    Checks Base58 alphabet validity, minimum length, non-repetitiveness,
    and Shannon entropy threshold.
    """
    if not data or len(data) < min_length:
        return False

    cleaned = data.strip().strip("'\"`")
    if len(cleaned) < min_length:
        return False

    if not is_base58(cleaned):
        return False

    if is_repetitive(cleaned):
        return False

    return calculate_entropy(cleaned) >= threshold
