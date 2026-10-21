"""
Unit tests for detection rules.
"""

from secret_leak_guard.rules import get_default_rules

# Assemble mock test tokens dynamically to prevent GitHub push protection false positives
MOCK_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
MOCK_GHP = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
MOCK_PAT = "github_pat_" + "11ABCD0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_9876543210"
MOCK_SLACK = "xoxb-" + "123456789012-123456789012-abcdef12345"
MOCK_WEBHOOK = "https://" + "hooks." + "slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx"
MOCK_STRIPE = "sk_live_" + "51A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0"
MOCK_OAI = "sk-proj-" + "abcde12345xyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
MOCK_ANT = "sk-ant-" + "api03-abcdef1234567890abcdef1234567890abcdef1234567890"


def test_default_rules_exist():
    rules = get_default_rules()
    assert len(rules) >= 15
    rule_ids = [r.id for r in rules]
    assert len(rule_ids) == len(set(rule_ids)), "Rule IDs must be unique"


def test_aws_access_key_rule():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG001"]
    sample = f"export AWS_ACCESS_KEY_ID={MOCK_AWS}"
    match = rule.pattern.search(sample)
    assert match is not None
    assert match.group(0) == MOCK_AWS


def test_github_token_rule():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG003"]
    # Classic PAT
    sample = f"token = '{MOCK_GHP}'"
    match = rule.pattern.search(sample)
    assert match is not None
    assert match.group(0) == MOCK_GHP

    # Fine-grained PAT
    sample_fg = f"gh = '{MOCK_PAT}'"
    match_fg = rule.pattern.search(sample_fg)
    assert match_fg is not None


def test_slack_rules():
    rules = {r.id: r for r in get_default_rules()}
    # Token
    token_rule = rules["SLG005"]
    assert token_rule.pattern.search(f"slack_token = '{MOCK_SLACK}'")

    # Webhook
    webhook_rule = rules["SLG006"]
    assert webhook_rule.pattern.search(MOCK_WEBHOOK)


def test_stripe_rule():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG007"]
    sample = f"stripe.api_key = '{MOCK_STRIPE}'"
    match = rule.pattern.search(sample)
    assert match is not None


def test_ai_provider_rules():
    rules = {r.id: r for r in get_default_rules()}
    # OpenAI
    openai_rule = rules["SLG008"]
    sample_oai = f"OPENAI_API_KEY='{MOCK_OAI}'"
    assert openai_rule.pattern.search(sample_oai)

    # Anthropic
    anthropic_rule = rules["SLG009"]
    sample_ant = f"ANTHROPIC_KEY='{MOCK_ANT}'"
    assert anthropic_rule.pattern.search(sample_ant)


def test_private_key_rule():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG013"]
    prefix = "-----BEGIN RSA " + "PRIVATE KEY-----"
    suffix = "-----END RSA " + "PRIVATE KEY-----"
    sample = f"{prefix}\nMIIEowIBAAKCAQEA0...\n{suffix}"
    assert rule.pattern.search(sample)


def test_database_uri_rule():
    rules = {r.id: r for r in get_default_rules()}
    rule = rules["SLG015"]
    sample = "DATABASE_URL=postgres://admin:super_secret_pass123@db.internal:5432/production"
    match = rule.pattern.search(sample)
    assert match is not None
    assert match.group(1) == "super_secret_pass123"

def test_shopify_and_linear_rules():
    rules = {r.id: r for r in get_default_rules()}
    # Shopify
    shopify_rule = rules["SLG022"]
    mock_shopify = "shp" + "at_" + "0123456789abcdef0123456789abcdef"
    sample_shop = f"SHOPIFY_API_TOKEN='{mock_shopify}'"
    assert shopify_rule.pattern.search(sample_shop)

    # Linear
    linear_rule = rules["SLG023"]
    mock_linear = "lin_" + "api_" + "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    sample_lin = f"LINEAR_API_KEY='{mock_linear}'"
    assert linear_rule.pattern.search(sample_lin)
