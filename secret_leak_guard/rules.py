"""
Predefined detection rules and patterns for API keys, tokens, and private secrets.
"""

from dataclasses import dataclass, field
import re
from typing import List, Optional, Pattern


@dataclass
class SecretRule:
    """Represents a rule for detecting specific secrets or leaked tokens."""
    id: str
    name: str
    description: str
    severity: str
    pattern: Pattern[str]
    min_entropy: float = 0.0
    group_index: int = 0
    tags: List[str] = field(default_factory=list)


def get_default_rules() -> List[SecretRule]:
    """Returns the list of production-grade default detection rules."""
    return [
        SecretRule(
            id="SLG001",
            name="AWS Access Key ID",
            description="Detected an AWS Access Key ID (AKIA format).",
            severity="CRITICAL",
            pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
            tags=["aws", "cloud", "credentials"],
        ),
        SecretRule(
            id="SLG002",
            name="AWS Secret Access Key",
            description="Detected potential AWS Secret Access Key in variable assignment.",
            severity="CRITICAL",
            pattern=re.compile(
                r"(?i)(?:aws_secret_access_key|aws_secret_key|aws_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
            ),
            group_index=1,
            min_entropy=3.8,
            tags=["aws", "cloud", "credentials"],
        ),
        SecretRule(
            id="SLG003",
            name="GitHub Personal Access Token",
            description="Detected a GitHub Personal Access Token (classic, fine-grained, or oauth).",
            severity="CRITICAL",
            pattern=re.compile(
                r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{50,100}|gho_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36})\b"
            ),
            tags=["github", "git", "token"],
        ),
        SecretRule(
            id="SLG004",
            name="GitLab Personal Access Token",
            description="Detected a GitLab Personal Access Token.",
            severity="HIGH",
            pattern=re.compile(r"\b(glpat-[0-9a-zA-Z\-_]{20,32})\b"),
            tags=["gitlab", "git", "token"],
        ),
        SecretRule(
            id="SLG005",
            name="Slack Token",
            description="Detected a Slack bot, user, or app token.",
            severity="HIGH",
            pattern=re.compile(r"\b(xox[baprs]-[0-9]{10,14}-[0-9]{10,14}[a-zA-Z0-9-]*)\b"),
            tags=["slack", "chat", "token"],
        ),
        SecretRule(
            id="SLG006",
            name="Slack Incoming Webhook",
            description="Detected a Slack incoming webhook URL.",
            severity="HIGH",
            pattern=re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,12}/B[0-9A-Z]{8,12}/[0-9A-Za-z]{24}"),
            tags=["slack", "webhook"],
        ),
        SecretRule(
            id="SLG007",
            name="Stripe API Key",
            description="Detected a Stripe live or test secret/restricted key.",
            severity="CRITICAL",
            pattern=re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b"),
            tags=["stripe", "payment", "token"],
        ),
        SecretRule(
            id="SLG008",
            name="OpenAI API Key",
            description="Detected an OpenAI API Key (standard or project-scoped).",
            severity="CRITICAL",
            pattern=re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{40,})\b"),
            min_entropy=3.4,
            tags=["openai", "ai", "token"],
        ),
        SecretRule(
            id="SLG009",
            name="Anthropic API Key",
            description="Detected an Anthropic Claude API Key.",
            severity="CRITICAL",
            pattern=re.compile(r"\b(sk-ant-[a-zA-Z0-9_-]{40,})\b"),
            tags=["anthropic", "ai", "token"],
        ),
        SecretRule(
            id="SLG010",
            name="Google / Firebase API Key",
            description="Detected a Google Cloud or Firebase API Key.",
            severity="HIGH",
            pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
            tags=["google", "cloud", "firebase"],
        ),
        SecretRule(
            id="SLG011",
            name="Hugging Face Token",
            description="Detected a Hugging Face user access token.",
            severity="HIGH",
            pattern=re.compile(r"\b(hf_[a-zA-Z0-9]{34})\b"),
            tags=["huggingface", "ai", "token"],
        ),
        SecretRule(
            id="SLG012",
            name="SendGrid API Key",
            description="Detected a SendGrid API Key.",
            severity="HIGH",
            pattern=re.compile(r"\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b"),
            tags=["sendgrid", "email", "token"],
        ),
        SecretRule(
            id="SLG013",
            name="Asymmetric Private Key",
            description="Detected an unencrypted private RSA, DSA, EC, or OpenSSH key.",
            severity="CRITICAL",
            pattern=re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s?PRIVATE KEY-----"),
            tags=["crypto", "ssh", "pki"],
        ),
        SecretRule(
            id="SLG014",
            name="JSON Web Token (JWT)",
            description="Detected a JSON Web Token with claims and signature.",
            severity="MEDIUM",
            pattern=re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
            tags=["jwt", "auth"],
        ),
        SecretRule(
            id="SLG015",
            name="Database URI Password",
            description="Detected database connection string containing plaintext credentials.",
            severity="HIGH",
            pattern=re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:([^@\s]+)@[^:\s]+"),
            group_index=1,
            tags=["database", "credentials"],
        ),
        SecretRule(
            id="SLG016",
            name="High-Entropy Generic Secret",
            description="Detected high-entropy credential or secret assigned in code.",
            severity="HIGH",
            pattern=re.compile(
                r"(?i)(?:api[_\-]?key|auth[_\-]?token|access[_\-]?token|secret[_\-]?key|client[_\-]?secret|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.\/+=]{16,80})['\"]"
            ),
            group_index=1,
            min_entropy=3.7,
            tags=["generic", "entropy"],
        ),
        SecretRule(
            id="SLG017",
            name="PyPI API Token",
            description="Detected a PyPI API upload token.",
            severity="CRITICAL",
            pattern=re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})\b"),
            tags=["pypi", "python", "package", "token"],
        ),
        SecretRule(
            id="SLG018",
            name="npm Access Token",
            description="Detected an npm automation or publish access token.",
            severity="CRITICAL",
            pattern=re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
            tags=["npm", "javascript", "package", "token"],
        ),
        SecretRule(
            id="SLG019",
            name="Discord Bot Token",
            description="Detected a Discord bot token.",
            severity="HIGH",
            pattern=re.compile(r"\b([MN][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b"),
            tags=["discord", "chat", "token"],
        ),
        SecretRule(
            id="SLG020",
            name="Solana Private Key",
            description="Detected a base58-encoded Solana private key assignment.",
            severity="CRITICAL",
            pattern=re.compile(
                r"(?i)(?:solana[_\-]?private[_\-]?key|solana[_\-]?secret[_\-]?key|solana[_\-]?key|sol[_\-]?privkey|sol[_\-]?private[_\-]?key|phantom[_\-]?key)\s*[:=]\s*['\"]?([1-9A-HJ-NP-Za-km-z]{43,88})['\"]?"
            ),
            group_index=1,
            min_entropy=4.0,
            tags=["solana", "crypto", "blockchain", "private-key", "base58"],
        ),
        SecretRule(
            id="SLG021",
            name="High-Entropy Base58 Private Key",
            description="Detected an unlabelled raw high-entropy Base58 private key or keypair.",
            severity="CRITICAL",
            pattern=re.compile(r"\b([1-9A-HJ-NP-Za-km-z]{87,88})\b"),
            min_entropy=4.5,
            tags=["base58", "solana", "crypto", "private-key"],
        ),
        SecretRule(
            id="SLG022",
            name="Shopify Access Token",
            description="Detected a Shopify admin, user, or partner API access token.",
            severity="CRITICAL",
            pattern=re.compile(r"\b(shp(?:at|ua|pa)_[a-fA-F0-9]{32})\b"),
            tags=["shopify", "ecommerce", "api", "token"],
        ),
        SecretRule(
            id="SLG023",
            name="Linear API Key",
            description="Detected a Linear personal or workspace API key.",
            severity="HIGH",
            pattern=re.compile(r"\b(lin_api_[A-Za-z0-9]{40})\b"),
            tags=["linear", "api", "key", "issue-tracker"],
        ),
    ]
