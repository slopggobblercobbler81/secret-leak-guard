"""
Unit tests for Slack token detection patterns (bot tokens xoxb- and user tokens xoxp-).
"""

import pytest
from secret_leak_guard.scanner import SecretScanner
from secret_leak_guard.rules import get_default_rules


def test_slack_bot_and_user_tokens():
    # Assemble mock Slack tokens dynamically to avoid triggering secret leak guards in our own commit/push.
    bot_token = "xoxb-" + "123456789012" + "-" + "123456789012" + "-" + "abcdef1234567890abcdef12"
    user_token = "xoxp-" + "987654321098" + "-" + "987654321098" + "-" + "fedcba0987654321fedcba09"

    content = f"""
    SLACK_BOT_TOKEN="{bot_token}"
    SLACK_USER_TOKEN="{user_token}"
    """

    rules = get_default_rules()
    scanner = SecretScanner(rules=rules)

    results = scanner.scan_text(content, file_path="config.py")
    assert isinstance(results, list)
    
    # Check that both bot token and user token were detected by rule SLG005
    detected_tokens = [res.matched_text for res in results if res.rule_id == "SLG005"]
    assert bot_token in detected_tokens
    assert user_token in detected_tokens
