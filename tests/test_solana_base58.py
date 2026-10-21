"""
Unit tests for high-entropy Base58 and Solana private key detection patterns.
"""

import pytest
from secret_leak_guard.entropy import (
    BASE58_ALPHABET,
    BASE58_CHARSET,
    calculate_base58_entropy,
    is_base58,
    is_high_entropy_base58,
)
from secret_leak_guard.rules import get_default_rules
from secret_leak_guard.scanner import SecretScanner


def _make_mock_solana_base58(length: int = 88) -> str:
    """Generate a high-entropy mock Base58 string without forbidden characters (0, O, I, l)."""
    # Deterministic high-entropy sequence using valid Base58 characters
    charset = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    chars = []
    state = 42
    for _ in range(length):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        chars.append(charset[state % len(charset)])
    return "".join(chars)


def test_base58_alphabet_and_charset():
    assert len(BASE58_ALPHABET) == 58
    assert len(BASE58_CHARSET) == 58
    # Ensure zero, capital O, capital I, lowercase l are NOT in Base58
    for forbidden in ["0", "O", "I", "l"]:
        assert forbidden not in BASE58_CHARSET
        assert forbidden not in BASE58_ALPHABET


def test_is_base58_validation():
    assert is_base58("") is False
    assert is_base58("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ") is True
    assert is_base58("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") is True

    # Reject forbidden characters
    assert is_base58("contains0zero") is False
    assert is_base58("containsOcapitalO") is False
    assert is_base58("containsIcapitalI") is False
    assert is_base58("containslsmallL") is False
    assert is_base58("abc+def") is False
    assert is_base58("abc/def") is False
    assert is_base58("abc=def") is False
    assert is_base58("abc-def") is False


def test_calculate_base58_entropy():
    assert calculate_base58_entropy("") == 0.0
    assert calculate_base58_entropy("invalid+chars") == 0.0

    valid_base58 = _make_mock_solana_base58(88)
    entropy = calculate_base58_entropy(valid_base58)
    assert entropy > 4.5


def test_is_high_entropy_base58():
    # Empty or short strings
    assert is_high_entropy_base58("") is False
    assert is_high_entropy_base58("abc") is False
    assert is_high_entropy_base58("   ") is False
    assert is_high_entropy_base58("   " + "1" * 10 + "   ", min_length=32) is False
    assert is_high_entropy_base58(" " * 40, min_length=32) is False

    # High entropy 88-char Solana keypair
    key_88 = _make_mock_solana_base58(88)
    assert is_high_entropy_base58(key_88) is True
    assert is_high_entropy_base58(f"'{key_88}'") is True

    # High entropy 44-char Solana seed
    key_44 = _make_mock_solana_base58(44)
    assert is_high_entropy_base58(key_44) is True

    # Low entropy repetitive Base58 string
    repetitive = "1" * 88
    assert is_high_entropy_base58(repetitive) is False

    # String with non-base58 character
    invalid_char_string = key_88[:40] + "0" + key_88[41:]
    assert is_high_entropy_base58(invalid_char_string) is False


def test_solana_private_key_rule_assignment():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG020"]
    assert rule.name == "Solana Private Key"
    assert rule.severity == "CRITICAL"
    assert "solana" in rule.tags
    assert "base58" in rule.tags

    mock_key = _make_mock_solana_base58(88)

    # Various assignment formats
    samples = [
        f'SOLANA_PRIVATE_KEY="{mock_key}"',
        f"solana_secret_key = '{mock_key}'",
        f'sol_private_key: "{mock_key}"',
        f'phantom_key = "{mock_key}"',
        f"SOLANA_KEY={mock_key}",
    ]

    for sample in samples:
        match = rule.pattern.search(sample)
        assert match is not None, f"Failed to match: {sample}"
        assert match.group(1) == mock_key

    # Scanner detection with entropy evaluation
    scanner = SecretScanner(rules=[rule])
    findings = scanner.scan_text(f'solana_private_key = "{mock_key}"', file_path="wallet.env")
    assert len(findings) == 1
    assert findings[0].rule_id == "SLG020"
    assert findings[0].matched_text == mock_key
    assert findings[0].severity == "CRITICAL"

    # Reject repetitive / low-entropy assignment
    low_entropy_sample = f'solana_private_key = "{"1" * 88}"'
    assert len(scanner.scan_text(low_entropy_sample)) == 0


def test_solana_private_key_32byte_seed():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG020"]
    mock_key_44 = _make_mock_solana_base58(44)
    sample = f'solana_private_key = "{mock_key_44}"'

    scanner = SecretScanner(rules=[rule])
    findings = scanner.scan_text(sample, file_path="config.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "SLG020"
    assert findings[0].matched_text == mock_key_44


def test_high_entropy_base58_standalone_rule():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG021"]
    assert rule.name == "High-Entropy Base58 Private Key"
    assert rule.severity == "CRITICAL"
    assert "base58" in rule.tags

    mock_key_88 = _make_mock_solana_base58(88)
    mock_key_87 = _make_mock_solana_base58(87)

    # Standalone match 88 and 87 characters
    assert rule.pattern.search(f"token: {mock_key_88}") is not None
    assert rule.pattern.search(f"export KEY={mock_key_87}") is not None

    scanner = SecretScanner(rules=[rule])
    findings = scanner.scan_text(mock_key_88, file_path="key.txt")
    assert len(findings) == 1
    assert findings[0].rule_id == "SLG021"
    assert findings[0].matched_text == mock_key_88

    # Reject non-base58 strings (containing 0 or O)
    non_b58 = mock_key_88[:40] + "0" + mock_key_88[41:]
    assert rule.pattern.search(non_b58) is None


def test_solana_scanner_full_integration():
    mock_key = _make_mock_solana_base58(88)
    content = f"""
    # Safe configuration
    CLUSTER_URL = "https://api.mainnet-beta.solana.com"
    PUBLIC_WALLET = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"

    # Leaked private key
    SOLANA_PRIVATE_KEY = "{mock_key}"

    # Suppressed line
    # nosecret
    SUPPRESSED_SOLANA_KEY = "{mock_key}"
    """

    scanner = SecretScanner()
    findings = scanner.scan_text(content, file_path="deploy_solana.py")

    # Should detect unsuppressed key
    matched_ids = [f.rule_id for f in findings]
    assert "SLG020" in matched_ids
    detected = [f for f in findings if f.rule_id == "SLG020"][0]
    assert detected.matched_text == mock_key
    assert detected.redacted_text != mock_key
    assert detected.redacted_text.startswith(mock_key[:4])
