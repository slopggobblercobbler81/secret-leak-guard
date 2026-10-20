"""
Entropy calculation and heuristics for secret detection.
"""

import math
from collections import Counter
from typing import Set

# Known benign placeholders often found in templates, mocks, or documentation
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
    # If the most common character makes up > 60% of the string
    counts = Counter(data)
    if counts.most_common(1)[0][1] / len(data) > 0.6:
        return True
    # If unique character count is very low compared to length
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

    # Check benign placeholders
    lower_val = cleaned.lower()
    if lower_val in BENIGN_PLACEHOLDERS:
        return False
    if any(p in lower_val for p in ["your_token", "your_api", "insert_key", "replace_with"]):
        return False

    # Filter out repetitive sequences
    if is_repetitive(cleaned):
        return False

    # Filter out low diversity
    if get_character_diversity(cleaned) < min_diversity:
        return False

    ent = calculate_entropy(cleaned)
    return ent >= threshold
