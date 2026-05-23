"""Regex pattern definitions for secrets detection (gitleaks / truffleHog inspired).

This module defines the ``SECRET_PATTERNS`` registry — an ordered list of
``SecretPattern`` rules that the detector engine applies against every line of
content collected from a Git repository.

Design decisions
----------------
* **Rules are ordered by severity then specificity.** CRITICAL rules run first
  so the detector can short-circuit on high-confidence matches.
* **Patterns use non-capturing groups where possible** to keep ``re.findall``
  output clean — the outer-most capture group (group 0 / full match) is the
  secret value itself.
* **Each rule declares ``can_validate``** to tell the downstream validator
  module whether a liveness check is feasible for this secret type.
* **Keywords** provide contextual boosters — if surrounding text contains these
  words the scorer increases confidence.

References
----------
* gitleaks rules: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
* truffleHog patterns: https://github.com/truffleHog/truffleHog
* AWS credential format: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
"""

from __future__ import annotations

import re
from typing import List

from .models import SecretPattern, SecretType, Severity


# ---------------------------------------------------------------------------
# Helper — compile with common flags
# ---------------------------------------------------------------------------

def _compile(pattern: str, flags: int = 0) -> re.Pattern:
    """Compile a regex pattern with optional flags.

    All patterns are compiled once at import time for performance.
    """
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# AWS Patterns
# ---------------------------------------------------------------------------

AWS_ACCESS_KEY_ID = SecretPattern(
    id="aws-access-key-id",
    name="AWS Access Key ID",
    pattern=_compile(r"(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)"),
    severity=Severity.CRITICAL,
    secret_type=SecretType.AWS_ACCESS_KEY,
    description=(
        "AWS IAM access key ID. Always starts with 'AKIA' followed by "
        "16 uppercase alphanumeric characters. A leaked key pair grants "
        "full access to the associated IAM user's permissions."
    ),
    can_validate=True,
    keywords=["aws", "access", "key", "iam", "amazon"],
)

AWS_SECRET_ACCESS_KEY = SecretPattern(
    id="aws-secret-access-key",
    name="AWS Secret Access Key",
    pattern=_compile(
        r"(?i)"
        r"(?:aws[_\s]*secret[_\s]*access[_\s]*key|aws[_\s]*secret[_\s]*key)"
        r"\s*[=:]\s*"
        r"['\"]?"
        r"([A-Za-z0-9/+=]{40})"
        r"['\"]?"
    ),
    severity=Severity.CRITICAL,
    secret_type=SecretType.AWS_SECRET_KEY,
    description=(
        "AWS IAM secret access key — the private half of an AWS key pair. "
        "40-character base64 string. Paired with an access key ID to "
        "authenticate API requests."
    ),
    can_validate=True,
    keywords=["aws", "secret", "key", "iam", "amazon"],
)

AWS_SESSION_TOKEN = SecretPattern(
    id="aws-session-token",
    name="AWS Session Token",
    pattern=_compile(
        r"(?i)"
        r"(?:aws[_\s]*session[_\s]*token)"
        r"\s*[=:]\s*"
        r"['\"]?"
        r"([A-Za-z0-9/+=]{100,})"
        r"['\"]?"
    ),
    severity=Severity.CRITICAL,
    secret_type=SecretType.CLOUD_CREDENTIAL,
    description="AWS STS session token — temporary credential from AssumeRole.",
    can_validate=True,
    keywords=["aws", "session", "token", "sts"],
)


# ---------------------------------------------------------------------------
# Private Keys (PEM-encoded)
# ---------------------------------------------------------------------------

RSA_PRIVATE_KEY = SecretPattern(
    id="rsa-private-key",
    name="RSA Private Key",
    pattern=_compile(
        r"(-----BEGIN RSA PRIVATE KEY-----"
        r"[\s\S]*?"
        r"-----END RSA PRIVATE KEY-----)"
    ),
    severity=Severity.CRITICAL,
    secret_type=SecretType.PRIVATE_KEY,
    description=(
        "PEM-encoded RSA private key. Can be used for TLS impersonation, "
        "SSH access, or signing malicious artifacts."
    ),
    can_validate=True,
    keywords=["rsa", "private", "key", "pem", "cert", "ssl", "tls"],
)

GENERIC_PRIVATE_KEY = SecretPattern(
    id="generic-private-key",
    name="Private Key (EC/DSA/OpenSSH)",
    pattern=_compile(
        r"(-----BEGIN (?:EC|DSA|OPENSSH|ENCRYPTED) PRIVATE KEY-----"
        r"[\s\S]*?"
        r"-----END (?:EC|DSA|OPENSSH|ENCRYPTED) PRIVATE KEY-----)"
    ),
    severity=Severity.CRITICAL,
    secret_type=SecretType.PRIVATE_KEY,
    description="PEM-encoded EC, DSA, or OpenSSH private key.",
    can_validate=True,
    keywords=["private", "key", "pem", "ec", "dsa", "openssh"],
)

PGP_PRIVATE_KEY = SecretPattern(
    id="pgp-private-key",
    name="PGP Private Key Block",
    pattern=_compile(
        r"(-----BEGIN PGP PRIVATE KEY BLOCK-----"
        r"[\s\S]*?"
        r"-----END PGP PRIVATE KEY BLOCK-----)"
    ),
    severity=Severity.CRITICAL,
    secret_type=SecretType.PRIVATE_KEY,
    description="PGP private key block — used for GPG signing and encryption.",
    can_validate=False,
    keywords=["pgp", "gpg", "private", "key"],
)


# ---------------------------------------------------------------------------
# Payment / SaaS API Keys
# ---------------------------------------------------------------------------

STRIPE_SECRET_KEY = SecretPattern(
    id="stripe-secret-key",
    name="Stripe Secret Key",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"((?:sk_live|sk_test)_[A-Za-z0-9]{24,})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.CRITICAL,
    secret_type=SecretType.API_KEY,
    description=(
        "Stripe secret API key. 'sk_live_' keys can charge real credit cards "
        "and access customer PII. Even 'sk_test_' keys should not be in repos."
    ),
    can_validate=False,
    keywords=["stripe", "payment", "sk_live", "sk_test"],
)

STRIPE_RESTRICTED_KEY = SecretPattern(
    id="stripe-restricted-key",
    name="Stripe Restricted API Key",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"(rk_live_[A-Za-z0-9]{24,})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.API_KEY,
    description="Stripe restricted API key with limited permissions.",
    can_validate=False,
    keywords=["stripe", "restricted"],
)


# ---------------------------------------------------------------------------
# GitHub Tokens
# ---------------------------------------------------------------------------

GITHUB_PAT = SecretPattern(
    id="github-pat",
    name="GitHub Personal Access Token",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"(ghp_[A-Za-z0-9]{36})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.TOKEN,
    description=(
        "GitHub classic personal access token. Grants API access to repos, "
        "gists, and org resources depending on scopes."
    ),
    can_validate=False,
    keywords=["github", "token", "ghp", "pat"],
)

GITHUB_FINE_GRAINED_TOKEN = SecretPattern(
    id="github-fine-grained-token",
    name="GitHub Fine-Grained PAT",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"(github_pat_[A-Za-z0-9_]{22,})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.TOKEN,
    description="GitHub fine-grained personal access token (new format).",
    can_validate=False,
    keywords=["github", "token", "pat", "fine_grained"],
)

GITHUB_OAUTH = SecretPattern(
    id="github-oauth",
    name="GitHub OAuth Access Token",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"(gho_[A-Za-z0-9]{36})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.TOKEN,
    description="GitHub OAuth access token.",
    can_validate=False,
    keywords=["github", "oauth"],
)

GITHUB_APP_TOKEN = SecretPattern(
    id="github-app-token",
    name="GitHub App Token",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"((?:ghu|ghs)_[A-Za-z0-9]{36})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.TOKEN,
    description="GitHub App user-to-server or installation token.",
    can_validate=False,
    keywords=["github", "app", "token"],
)


# ---------------------------------------------------------------------------
# Slack Tokens
# ---------------------------------------------------------------------------

SLACK_TOKEN = SecretPattern(
    id="slack-token",
    name="Slack Token",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"(xox[baprs]-[A-Za-z0-9\-]{10,250})"
        r"(?:[^A-Za-z0-9\-]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.TOKEN,
    description=(
        "Slack bot, app, or user token. Can post messages, read channels, "
        "and access workspace data."
    ),
    can_validate=False,
    keywords=["slack", "xoxb", "xoxp", "bot", "token"],
)

SLACK_WEBHOOK = SecretPattern(
    id="slack-webhook-url",
    name="Slack Webhook URL",
    pattern=_compile(
        r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)"
    ),
    severity=Severity.MEDIUM,
    secret_type=SecretType.TOKEN,
    description="Slack incoming webhook URL — can post messages to a channel.",
    can_validate=False,
    keywords=["slack", "webhook", "hooks"],
)


# ---------------------------------------------------------------------------
# JWT / Signing Keys
# ---------------------------------------------------------------------------

JWT_SECRET = SecretPattern(
    id="jwt-secret",
    name="JWT Signing Key/Secret",
    pattern=_compile(
        r"(?i)"
        r"(?:jwt[_\-]?secret|jwt[_\-]?key|signing[_\-]?key|signing[_\-]?secret)"
        r"\s*[=:]\s*"
        r"['\"]"
        r"([^'\"]{8,})"
        r"['\"]"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.SIGNING_KEY,
    description=(
        "JWT signing secret or HMAC key. An attacker with this value can "
        "forge valid authentication tokens for any user."
    ),
    can_validate=True,
    keywords=["jwt", "secret", "signing", "key", "token", "hmac"],
)


# ---------------------------------------------------------------------------
# Database Credentials
# ---------------------------------------------------------------------------

DATABASE_URL = SecretPattern(
    id="database-url",
    name="Database Connection String",
    pattern=_compile(
        r"(?i)"
        r"((?:mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp)"
        r"://[^\s'\"<>]{10,})"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.CONNECTION_STRING,
    description=(
        "Database connection URI with embedded credentials. Grants direct "
        "access to the database — read, write, and potentially admin."
    ),
    can_validate=False,
    keywords=["database", "db", "mysql", "postgres", "mongodb", "redis", "connection"],
)

GENERIC_PASSWORD = SecretPattern(
    id="generic-password",
    name="Generic Password Assignment",
    pattern=_compile(
        r"(?i)"
        r"(?:password|passwd|pwd|pass)"
        r"\s*[=:]\s*"
        r"['\"]"
        r"([^'\"]{6,})"
        r"['\"]"
    ),
    severity=Severity.MEDIUM,
    secret_type=SecretType.PASSWORD,
    description=(
        "Password assigned in configuration. Severity depends on whether "
        "this is a production credential or a test/placeholder value."
    ),
    can_validate=False,
    keywords=["password", "passwd", "pwd", "credential"],
)

DB_PASSWORD_YAML = SecretPattern(
    id="db-password-yaml",
    name="Database Password (YAML)",
    pattern=_compile(
        r"(?i)"
        r"(?:password|passwd|db_password|POSTGRES_PASSWORD|MYSQL_PASSWORD|MYSQL_ROOT_PASSWORD)"
        r"\s*:\s*"
        r"['\"]?"
        r"([^\s'\"#]{6,})"
        r"['\"]?"
    ),
    severity=Severity.MEDIUM,
    secret_type=SecretType.PASSWORD,
    description="Database password in a YAML/Docker Compose configuration file.",
    can_validate=False,
    keywords=["password", "db", "postgres", "mysql", "docker", "compose"],
)


# ---------------------------------------------------------------------------
# Generic API Keys
# ---------------------------------------------------------------------------

GENERIC_API_KEY = SecretPattern(
    id="generic-api-key",
    name="Generic API Key Assignment",
    pattern=_compile(
        r"(?i)"
        r"(?:api[_\-]?key|apikey|api[_\-]?secret)"
        r"\s*[=:]\s*"
        r"['\"]"
        r"([A-Za-z0-9\-_/+=]{16,})"
        r"['\"]"
    ),
    severity=Severity.MEDIUM,
    secret_type=SecretType.API_KEY,
    description="Generic API key or API secret assignment in code or config.",
    can_validate=False,
    keywords=["api", "key", "secret", "apikey"],
)

GENERIC_SECRET = SecretPattern(
    id="generic-secret",
    name="Generic Secret Assignment",
    pattern=_compile(
        r"(?i)"
        r"(?:secret|secret[_\-]?key|auth[_\-]?token|access[_\-]?token|bearer)"
        r"\s*[=:]\s*"
        r"['\"]"
        r"([A-Za-z0-9\-_/+=]{16,})"
        r"['\"]"
    ),
    severity=Severity.MEDIUM,
    secret_type=SecretType.GENERIC,
    description="Generic secret or token assignment — needs manual review.",
    can_validate=False,
    keywords=["secret", "token", "auth", "bearer"],
)


# ---------------------------------------------------------------------------
# .env File Secrets
# ---------------------------------------------------------------------------

ENV_FILE_SECRET = SecretPattern(
    id="env-file-secret",
    name=".env File Secret",
    pattern=_compile(
        r"^([A-Z][A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|AUTH)[A-Z0-9_]*)"
        r"\s*=\s*"
        r"(.{8,})\s*$",
        re.MULTILINE,
    ),
    severity=Severity.MEDIUM,
    secret_type=SecretType.GENERIC,
    description="Secret-looking variable in a .env file (uppercase name containing SECRET/KEY/TOKEN/PASSWORD).",
    can_validate=False,
    keywords=["env", "secret", "key", "token", "password"],
)


# ---------------------------------------------------------------------------
# Google / GCP
# ---------------------------------------------------------------------------

GOOGLE_API_KEY = SecretPattern(
    id="google-api-key",
    name="Google API Key",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"(AIza[A-Za-z0-9\-_]{35})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.API_KEY,
    description="Google Cloud Platform API key.",
    can_validate=False,
    keywords=["google", "gcp", "api", "key"],
)

GCP_SERVICE_ACCOUNT = SecretPattern(
    id="gcp-service-account",
    name="GCP Service Account Key",
    pattern=_compile(
        r'"type"\s*:\s*"service_account"'
    ),
    severity=Severity.CRITICAL,
    secret_type=SecretType.CLOUD_CREDENTIAL,
    description="Google Cloud service account JSON key file — grants programmatic access to GCP resources.",
    can_validate=False,
    keywords=["google", "gcp", "service_account", "iam"],
)


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------

AZURE_STORAGE_KEY = SecretPattern(
    id="azure-storage-key",
    name="Azure Storage Account Key",
    pattern=_compile(
        r"(?i)"
        r"(?:AccountKey|azure[_\s]*storage[_\s]*key)"
        r"\s*[=:]\s*"
        r"['\"]?"
        r"([A-Za-z0-9/+=]{86,88})"
        r"['\"]?"
    ),
    severity=Severity.CRITICAL,
    secret_type=SecretType.CLOUD_CREDENTIAL,
    description="Azure Storage account access key (base64-encoded 512-bit key).",
    can_validate=False,
    keywords=["azure", "storage", "account", "key"],
)


# ---------------------------------------------------------------------------
# SendGrid / Twilio / Mailgun
# ---------------------------------------------------------------------------

SENDGRID_API_KEY = SecretPattern(
    id="sendgrid-api-key",
    name="SendGrid API Key",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"(SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.API_KEY,
    description="SendGrid email API key.",
    can_validate=False,
    keywords=["sendgrid", "email", "api"],
)

TWILIO_API_KEY = SecretPattern(
    id="twilio-api-key",
    name="Twilio API Key",
    pattern=_compile(
        r"(?:^|[^A-Za-z0-9])"
        r"(SK[A-Za-z0-9]{32})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.API_KEY,
    description="Twilio API key SID.",
    can_validate=False,
    keywords=["twilio", "sms", "api"],
)

MAILGUN_API_KEY = SecretPattern(
    id="mailgun-api-key",
    name="Mailgun API Key",
    pattern=_compile(
        r"(?i)"
        r"(?:^|[^A-Za-z0-9])"
        r"(key-[A-Za-z0-9]{32})"
        r"(?:[^A-Za-z0-9]|$)"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.API_KEY,
    description="Mailgun private API key.",
    can_validate=False,
    keywords=["mailgun", "email", "api"],
)


# ---------------------------------------------------------------------------
# Heroku
# ---------------------------------------------------------------------------

HEROKU_API_KEY = SecretPattern(
    id="heroku-api-key",
    name="Heroku API Key",
    pattern=_compile(
        r"(?i)"
        r"(?:heroku[_\s]*api[_\s]*key)"
        r"\s*[=:]\s*"
        r"['\"]?"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"['\"]?"
    ),
    severity=Severity.HIGH,
    secret_type=SecretType.API_KEY,
    description="Heroku platform API key (UUID format).",
    can_validate=False,
    keywords=["heroku", "api", "key"],
)


# =========================================================================
# SECRET_PATTERNS — The ordered registry
# =========================================================================
# Rules are evaluated top-down.  CRITICAL rules first, then HIGH, then MEDIUM.
# This lets the detector short-circuit on high-confidence matches.

SECRET_PATTERNS: List[SecretPattern] = [
    # --- CRITICAL ---
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_SESSION_TOKEN,
    RSA_PRIVATE_KEY,
    GENERIC_PRIVATE_KEY,
    PGP_PRIVATE_KEY,
    STRIPE_SECRET_KEY,
    GCP_SERVICE_ACCOUNT,
    AZURE_STORAGE_KEY,

    # --- HIGH ---
    GITHUB_PAT,
    GITHUB_FINE_GRAINED_TOKEN,
    GITHUB_OAUTH,
    GITHUB_APP_TOKEN,
    SLACK_TOKEN,
    JWT_SECRET,
    DATABASE_URL,
    GOOGLE_API_KEY,
    STRIPE_RESTRICTED_KEY,
    SENDGRID_API_KEY,
    TWILIO_API_KEY,
    MAILGUN_API_KEY,
    HEROKU_API_KEY,

    # --- MEDIUM ---
    GENERIC_PASSWORD,
    DB_PASSWORD_YAML,
    GENERIC_API_KEY,
    GENERIC_SECRET,
    ENV_FILE_SECRET,
    SLACK_WEBHOOK,
]


# ---------------------------------------------------------------------------
# Public API — convenience accessors
# ---------------------------------------------------------------------------

def get_all_patterns() -> List[SecretPattern]:
    """Return the full ordered list of secret detection patterns."""
    return list(SECRET_PATTERNS)


def get_patterns_by_severity(severity: Severity) -> List[SecretPattern]:
    """Return patterns filtered by a specific severity level."""
    return [p for p in SECRET_PATTERNS if p.severity == severity]


def get_pattern_by_id(pattern_id: str) -> SecretPattern | None:
    """Look up a single pattern by its stable ``id`` string."""
    for p in SECRET_PATTERNS:
        if p.id == pattern_id:
            return p
    return None


def get_validatable_patterns() -> List[SecretPattern]:
    """Return only patterns whose matches can be validated for liveness."""
    return [p for p in SECRET_PATTERNS if p.can_validate]
