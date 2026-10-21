"""
secret-leak-guard: High-performance CLI regex & entropy scanner for accidental secrets in git diffs and codebases.
"""

__version__ = "1.0.0"
__author__ = "slopggobblercobbler81"
__license__ = "MIT"

from secret_leak_guard.scanner import SecretScanner, Finding
from secret_leak_guard.entropy import (
    calculate_entropy,
    calculate_normalized_entropy,
    calculate_sliding_entropy,
    is_high_entropy,
)
from secret_leak_guard.rules import get_default_rules, SecretRule

__all__ = [
    "SecretScanner",
    "Finding",
    "calculate_entropy",
    "calculate_normalized_entropy",
    "calculate_sliding_entropy",
    "is_high_entropy",
    "get_default_rules",
    "SecretRule",
    "__version__",
]
