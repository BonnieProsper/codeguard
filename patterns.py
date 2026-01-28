"""
Secret detection patterns for CodeGuard.

This module contains pre-compiled regex patterns for detecting various types
of secrets, API keys, and credentials. Patterns are organized by service
category and compiled once at import time for optimal performance.

Each pattern includes:
- Compiled regex (IGNORECASE for flexibility)
- Human-readable name
- Severity level (critical/high/medium)
- Confidence score (0-100)
- Remediation guidance

Adding new patterns:
1. Add the regex constant with a descriptive name
2. Add a SecretPattern to the appropriate category list
3. Test against real examples and common false positives
"""

import re
from typing import Pattern


class SecretPattern:
    """
    Represents a single secret detection pattern.
    
    Attributes:
        name: Human-readable secret type (e.g., "AWS Access Key")
        pattern: Pre-compiled regex pattern
        severity: Risk level - 'critical', 'high', or 'medium'
        confidence: Detection accuracy from 0-100 (higher = fewer false positives)
        remediation: Step-by-step fix instructions shown to users
    """
    
    __slots__ = ('name', 'pattern', 'severity', 'confidence', 'remediation')
    
    def __init__(
        self, 
        name: str, 
        pattern: Pattern, 
        severity: str,
        confidence: int, 
        remediation: str
    ):
        self.name = name
        self.pattern = pattern
        self.severity = severity
        self.confidence = confidence
        self.remediation = remediation


# =============================================================================
# CLOUD PROVIDERS (AWS, Azure, GCP, DigitalOcean, Cloudflare, Heroku)
# =============================================================================

# AWS patterns - Amazon Web Services
AWS_ACCESS_KEY = re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE)
AWS_SECRET_KEY = re.compile(r'aws[_-]?secret[_-]?access[_-]?key["\s:=]+([A-Za-z0-9/+=]{40})', re.IGNORECASE)
AWS_SESSION_TOKEN = re.compile(r'aws[_-]?session[_-]?token["\s:=]+([A-Za-z0-9/+=]{100,})', re.IGNORECASE)
AWS_ACCOUNT_ID = re.compile(r'aws[_-]?account[_-]?id["\s:=]+(\d{12})', re.IGNORECASE)

# Azure patterns - Microsoft Azure
AZURE_STORAGE_KEY = re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}', re.IGNORECASE)
AZURE_SUBSCRIPTION_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
AZURE_CLIENT_SECRET = re.compile(r'client[_-]?secret["\s:=]+([A-Za-z0-9~._-]{34,})', re.IGNORECASE)

# Google Cloud Platform
GCP_API_KEY = re.compile(r'AIza[0-9A-Za-z_-]{35}', re.IGNORECASE)
GCP_OAUTH = re.compile(r'ya29\.[0-9A-Za-z_-]+', re.IGNORECASE)
GCP_SERVICE_ACCOUNT = re.compile(r'"type":\s*"service_account"', re.IGNORECASE)

# DigitalOcean
DIGITALOCEAN_TOKEN = re.compile(r'dop_v1_[a-f0-9]{64}', re.IGNORECASE)
DIGITALOCEAN_SPACES = re.compile(r'[A-Z0-9]{20}', re.IGNORECASE)  # Lower confidence, needs context

# Cloudflare
CLOUDFLARE_API_KEY = re.compile(r'[a-z0-9]{37}', re.IGNORECASE)  # Needs context
CLOUDFLARE_GLOBAL_API = re.compile(r'cloudflare[_-]?api[_-]?key["\s:=]+([a-z0-9]{37})', re.IGNORECASE)

# Heroku
HEROKU_API_KEY = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)


CLOUD_PATTERNS = [
    # AWS
    SecretPattern(
        'AWS Access Key',
        AWS_ACCESS_KEY,
        'critical',
        100,
        'Rotate immediately at console.aws.amazon.com/iam. Use IAM roles instead of access keys when possible.'
    ),
    SecretPattern(
        'AWS Secret Access Key',
        AWS_SECRET_KEY,
        'critical',
        95,
        'Rotate at console.aws.amazon.com/iam. Never commit AWS credentials. Use environment variables or AWS Secrets Manager.'
    ),
    SecretPattern(
        'AWS Session Token',
        AWS_SESSION_TOKEN,
        'high',
        90,
        'Session tokens are temporary but should not be committed. Regenerate session.'
    ),
    
    # Azure
    SecretPattern(
        'Azure Storage Account Key',
        AZURE_STORAGE_KEY,
        'critical',
        100,
        'Regenerate key at portal.azure.com. Use Azure Key Vault for secrets management.'
    ),
    SecretPattern(
        'Azure Client Secret',
        AZURE_CLIENT_SECRET,
        'critical',
        85,
        'Rotate client secret in Azure AD. Use Managed Identities when possible.'
    ),
    
    # GCP
    SecretPattern(
        'Google Cloud API Key',
        GCP_API_KEY,
        'critical',
        100,
        'Restrict and rotate at console.cloud.google.com/apis/credentials. Add application restrictions.'
    ),
    SecretPattern(
        'Google OAuth Token',
        GCP_OAUTH,
        'critical',
        95,
        'Revoke token in Google Account settings. These tokens are short-lived but should never be committed.'
    ),
    SecretPattern(
        'GCP Service Account Key',
        GCP_SERVICE_ACCOUNT,
        'critical',
        100,
        'Delete service account key at console.cloud.google.com/iam-admin. Create new key if needed.'
    ),
    
    # DigitalOcean
    SecretPattern(
        'DigitalOcean Personal Access Token',
        DIGITALOCEAN_TOKEN,
        'critical',
        100,
        'Revoke at cloud.digitalocean.com/account/api/tokens. Generate new token with minimal scopes needed.'
    ),
]


# =============================================================================
# VERSION CONTROL (GitHub, GitLab, Bitbucket)
# =============================================================================

GITHUB_PAT = re.compile(r'ghp_[a-zA-Z0-9]{36}', re.IGNORECASE)
GITHUB_OAUTH = re.compile(r'gho_[a-zA-Z0-9]{36}', re.IGNORECASE)
GITHUB_APP_TOKEN = re.compile(r'(ghu|ghs)_[a-zA-Z0-9]{36}', re.IGNORECASE)
GITHUB_REFRESH = re.compile(r'ghr_[a-zA-Z0-9]{76}', re.IGNORECASE)

GITLAB_PAT = re.compile(r'glpat-[a-zA-Z0-9_-]{20}', re.IGNORECASE)
GITLAB_RUNNER = re.compile(r'GR1348941[a-zA-Z0-9_-]{20}', re.IGNORECASE)

BITBUCKET_ACCESS = re.compile(r'BITBUCKET_ACCESS_TOKEN', re.IGNORECASE)


VCS_PATTERNS = [
    SecretPattern(
        'GitHub Personal Access Token',
        GITHUB_PAT,
        'critical',
        100,
        'Revoke immediately at github.com/settings/tokens. Rotate all tokens with same scope.'
    ),
    SecretPattern(
        'GitHub OAuth Access Token',
        GITHUB_OAUTH,
        'critical',
        100,
        'Revoke OAuth application access at github.com/settings/applications'
    ),
    SecretPattern(
        'GitHub App Token',
        GITHUB_APP_TOKEN,
        'critical',
        100,
        'Regenerate token in GitHub App settings. Review app permissions.'
    ),
    SecretPattern(
        'GitHub Refresh Token',
        GITHUB_REFRESH,
        'critical',
        100,
        'Revoke refresh token. This allows long-term access and is particularly sensitive.'
    ),
    SecretPattern(
        'GitLab Personal Access Token',
        GITLAB_PAT,
        'critical',
        100,
        'Revoke at gitlab.com/-/profile/personal_access_tokens. Create new token with minimal scope.'
    ),
]


# =============================================================================
# DATABASES (PostgreSQL, MySQL, MongoDB, Redis, Cassandra)
# =============================================================================

POSTGRES_CONN = re.compile(r'postgres(?:ql)?://[^\s:]+:[^\s@]+@[^\s/]+', re.IGNORECASE)
MYSQL_CONN = re.compile(r'mysql://[^\s:]+:[^\s@]+@[^\s/]+', re.IGNORECASE)
MONGODB_CONN = re.compile(r'mongodb(\+srv)?://[^\s:]+:[^\s@]+@[^\s/]+', re.IGNORECASE)
REDIS_URL = re.compile(r'redis://[^\s:]*:[^\s@]+@[^\s:]+:\d+', re.IGNORECASE)

DB_PASSWORD = re.compile(r'(?:db|database)[_-]?(?:pass|password)["\s:=]+["\']([^"\']{8,})["\']', re.IGNORECASE)
DB_USER = re.compile(r'(?:db|database)[_-]?(?:user|username)["\s:=]+["\']([^"\']+)["\']', re.IGNORECASE)


DATABASE_PATTERNS = [
    SecretPattern(
        'PostgreSQL Connection String',
        POSTGRES_CONN,
        'critical',
        95,
        'Remove connection string. Use environment variables. Rotate database password.'
    ),
    SecretPattern(
        'MySQL Connection String',
        MYSQL_CONN,
        'critical',
        95,
        'Remove connection string. Use environment variables. Rotate database password.'
    ),
    SecretPattern(
        'MongoDB Connection String',
        MONGODB_CONN,
        'critical',
        95,
        'Remove connection string. Use environment variables. Rotate database password. Enable IP whitelisting.'
    ),
    SecretPattern(
        'Redis Connection URL',
        REDIS_URL,
        'high',
        90,
        'Remove Redis URL. Use environment variables. Consider Redis ACLs for additional security.'
    ),
    SecretPattern(
        'Database Password',
        DB_PASSWORD,
        'high',
        75,
        'Never hardcode database passwords. Use environment variables or secrets manager.'
    ),
]


# =============================================================================
# PAYMENT PROVIDERS (Stripe, PayPal, Square, Braintree)
# =============================================================================

STRIPE_SECRET = re.compile(r'sk_live_[a-zA-Z0-9]{24,}', re.IGNORECASE)
STRIPE_RESTRICTED = re.compile(r'rk_live_[a-zA-Z0-9]{24,}', re.IGNORECASE)
STRIPE_TEST = re.compile(r'sk_test_[a-zA-Z0-9]{24,}', re.IGNORECASE)

PAYPAL_ACCESS = re.compile(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}', re.IGNORECASE)
SQUARE_ACCESS = re.compile(r'sq0atp-[0-9A-Za-z_-]{22}', re.IGNORECASE)
SQUARE_OAUTH = re.compile(r'sq0csp-[0-9A-Za-z_-]{43}', re.IGNORECASE)

BRAINTREE_ACCESS = re.compile(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}', re.IGNORECASE)


PAYMENT_PATTERNS = [
    SecretPattern(
        'Stripe Live Secret Key',
        STRIPE_SECRET,
        'critical',
        100,
        'URGENT: Rotate immediately at dashboard.stripe.com/apikeys. Audit recent transactions. Use test keys for development.'
    ),
    SecretPattern(
        'Stripe Restricted Key',
        STRIPE_RESTRICTED,
        'critical',
        100,
        'Rotate at dashboard.stripe.com/apikeys. Review key permissions.'
    ),
    SecretPattern(
        'PayPal Access Token',
        PAYPAL_ACCESS,
        'critical',
        95,
        'Revoke at developer.paypal.com. Generate new credentials with minimal permissions.'
    ),
    SecretPattern(
        'Square Access Token',
        SQUARE_ACCESS,
        'critical',
        100,
        'Revoke at developer.squareup.com. Square tokens provide full account access.'
    ),
    SecretPattern(
        'Square OAuth Secret',
        SQUARE_OAUTH,
        'critical',
        100,
        'Regenerate at developer.squareup.com. This is your OAuth secret.'
    ),
]


# =============================================================================
# COMMUNICATION (Twilio, SendGrid, Mailgun, Postmark, Slack)
# =============================================================================

TWILIO_API_KEY = re.compile(r'SK[0-9a-fA-F]{32}', re.IGNORECASE)
TWILIO_ACCOUNT_SID = re.compile(r'AC[a-f0-9]{32}', re.IGNORECASE)

SENDGRID_API = re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', re.IGNORECASE)
MAILGUN_API = re.compile(r'key-[0-9a-f]{32}', re.IGNORECASE)
POSTMARK_TOKEN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)

SLACK_TOKEN = re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}', re.IGNORECASE)
SLACK_WEBHOOK = re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}', re.IGNORECASE)

DISCORD_TOKEN = re.compile(r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}', re.IGNORECASE)
DISCORD_WEBHOOK = re.compile(r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', re.IGNORECASE)


COMMUNICATION_PATTERNS = [
    SecretPattern(
        'Twilio API Key',
        TWILIO_API_KEY,
        'critical',
        100,
        'Delete at twilio.com/console/runtime/api-keys. Create new key with required permissions only.'
    ),
    SecretPattern(
        'SendGrid API Key',
        SENDGRID_API,
        'critical',
        100,
        'Delete at app.sendgrid.com/settings/api_keys. SendGrid keys can send emails on your behalf.'
    ),
    SecretPattern(
        'Mailgun API Key',
        MAILGUN_API,
        'critical',
        90,
        'Regenerate at app.mailgun.com/app/account/security/api_keys'
    ),
    SecretPattern(
        'Slack Token',
        SLACK_TOKEN,
        'critical',
        100,
        'Revoke at api.slack.com/apps. Slack tokens provide workspace access.'
    ),
    SecretPattern(
        'Slack Webhook',
        SLACK_WEBHOOK,
        'high',
        100,
        'Regenerate webhook at api.slack.com/apps. Webhooks can post to channels.'
    ),
    SecretPattern(
        'Discord Bot Token',
        DISCORD_TOKEN,
        'critical',
        95,
        'Regenerate at discord.com/developers/applications. Bot tokens provide full bot access.'
    ),
    SecretPattern(
        'Discord Webhook',
        DISCORD_WEBHOOK,
        'high',
        100,
        'Delete webhook in Discord channel settings. Anyone with webhook can post to channel.'
    ),
]


# =============================================================================
# AI / ML APIs (OpenAI, Anthropic, Hugging Face, Cohere, Replicate)
# =============================================================================

OPENAI_API_KEY = re.compile(r'sk-[a-zA-Z0-9]{48}', re.IGNORECASE)
ANTHROPIC_API_KEY = re.compile(r'sk-ant-[a-zA-Z0-9_-]{95,}', re.IGNORECASE)
HUGGINGFACE_TOKEN = re.compile(r'hf_[a-zA-Z0-9]{32,}', re.IGNORECASE)
COHERE_API_KEY = re.compile(r'[a-zA-Z0-9]{40}', re.IGNORECASE)  # Lower confidence, needs context
REPLICATE_API_TOKEN = re.compile(r'r8_[a-zA-Z0-9]{32,}', re.IGNORECASE)


AI_API_PATTERNS = [
    SecretPattern(
        'OpenAI API Key',
        OPENAI_API_KEY,
        'critical',
        100,
        'Rotate at platform.openai.com/api-keys. OpenAI usage can be expensive if compromised.'
    ),
    SecretPattern(
        'Anthropic API Key',
        ANTHROPIC_API_KEY,
        'critical',
        100,
        'Rotate at console.anthropic.com. Monitor usage for any unauthorized requests.'
    ),
    SecretPattern(
        'Hugging Face Token',
        HUGGINGFACE_TOKEN,
        'high',
        100,
        'Revoke at huggingface.co/settings/tokens. Create new token with minimal scopes.'
    ),
    SecretPattern(
        'Replicate API Token',
        REPLICATE_API_TOKEN,
        'high',
        100,
        'Regenerate at replicate.com/account. Monitor for unauthorized model runs.'
    ),
]


# =============================================================================
# AUTHENTICATION / IDENTITY (Auth0, Okta, Firebase, JWT)
# =============================================================================

AUTH0_DOMAIN = re.compile(r'[a-z0-9-]+\.(?:auth0|eu\.auth0)\.com', re.IGNORECASE)
OKTA_TOKEN = re.compile(r'00[a-zA-Z0-9_-]{40,}', re.IGNORECASE)
FIREBASE_API_KEY = re.compile(r'AIza[0-9A-Za-z_-]{35}', re.IGNORECASE)

JWT_TOKEN = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', re.IGNORECASE)
BASIC_AUTH = re.compile(r'Basic [A-Za-z0-9+/=]{20,}', re.IGNORECASE)
BEARER_TOKEN = re.compile(r'Bearer [a-zA-Z0-9_-]{20,}', re.IGNORECASE)


AUTH_PATTERNS = [
    SecretPattern(
        'Firebase API Key',
        FIREBASE_API_KEY,
        'high',
        85,
        'Restrict key at console.firebase.google.com. Firebase API keys should be restricted by domain/app.'
    ),
    SecretPattern(
        'JWT Token',
        JWT_TOKEN,
        'medium',
        60,
        'JWT tokens should not be committed. Use secure storage and short expiration times.'
    ),
    SecretPattern(
        'Bearer Token',
        BEARER_TOKEN,
        'high',
        75,
        'Remove bearer token. Tokens provide authentication and should never be committed.'
    ),
]


# =============================================================================
# MONITORING / ANALYTICS (Datadog, New Relic, Sentry, Amplitude)
# =============================================================================

DATADOG_API_KEY = re.compile(r'[a-f0-9]{32}', re.IGNORECASE)  # Low confidence
DATADOG_APP_KEY = re.compile(r'[a-f0-9]{40}', re.IGNORECASE)  # Low confidence
NEWRELIC_LICENSE = re.compile(r'[a-f0-9]{40}', re.IGNORECASE)
SENTRY_DSN = re.compile(r'https://[a-f0-9]{32}@[a-z0-9.-]+/\d+', re.IGNORECASE)


MONITORING_PATTERNS = [
    SecretPattern(
        'Sentry DSN',
        SENTRY_DSN,
        'medium',
        90,
        'Sentry DSNs can be public but expose project structure. Consider rate limiting.'
    ),
]


# =============================================================================
# CI/CD (CircleCI, Travis, Jenkins, GitHub Actions)
# =============================================================================

CIRCLECI_TOKEN = re.compile(r'[a-f0-9]{40}', re.IGNORECASE)  # Needs context
TRAVIS_TOKEN = re.compile(r'[a-zA-Z0-9]{22}', re.IGNORECASE)  # Needs context
JENKINS_TOKEN = re.compile(r'[a-f0-9]{34}', re.IGNORECASE)  # Needs context


# =============================================================================
# GENERIC SECRETS (Private keys, certificates, generic tokens)
# =============================================================================

SSH_PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', re.IGNORECASE)
PGP_PRIVATE_KEY = re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', re.IGNORECASE)
CERTIFICATE = re.compile(r'-----BEGIN CERTIFICATE-----', re.IGNORECASE)
PKCS12 = re.compile(r'-----BEGIN ENCRYPTED PRIVATE KEY-----', re.IGNORECASE)

GENERIC_API_KEY = re.compile(r'(?:api[_-]?key|apikey)["\s:=]+["\']([a-zA-Z0-9_\-]{16,})["\']', re.IGNORECASE)
GENERIC_SECRET = re.compile(r'(?:secret|token|password|passwd|pwd)["\s:=]+["\']([a-zA-Z0-9_\-!@#$%^&*]{12,})["\']', re.IGNORECASE)
GENERIC_ACCESS_TOKEN = re.compile(r'access[_-]?token["\s:=]+["\']([a-zA-Z0-9_\-]{20,})["\']', re.IGNORECASE)

PRIVATE_KEY_INLINE = re.compile(r'(?:private[_-]?key|privatekey)["\s:=]+["\']([A-Za-z0-9+/=\n]{100,})["\']', re.IGNORECASE)
PASSWORD_IN_URL = re.compile(r'[a-zA-Z][a-zA-Z0-9+.-]*://[^:]+:([^@\s]+)@', re.IGNORECASE)


GENERIC_PATTERNS = [
    SecretPattern(
        'SSH Private Key',
        SSH_PRIVATE_KEY,
        'critical',
        100,
        'Remove private key immediately. Generate new SSH keypair. Update authorized_keys on servers.'
    ),
    SecretPattern(
        'PGP Private Key',
        PGP_PRIVATE_KEY,
        'critical',
        100,
        'Remove private key. Revoke and generate new PGP key if compromised.'
    ),
    SecretPattern(
        'Private Key (Inline)',
        PRIVATE_KEY_INLINE,
        'critical',
        90,
        'Remove inline private key. Use key management service or environment variables.'
    ),
    SecretPattern(
        'Generic API Key',
        GENERIC_API_KEY,
        'high',
        70,
        'Remove API key. Use environment variables: API_KEY = os.getenv("API_KEY")'
    ),
    SecretPattern(
        'Generic Secret/Token',
        GENERIC_SECRET,
        'high',
        65,
        'Never hardcode secrets. Use environment variables or secrets management service.'
    ),
    SecretPattern(
        'Password in URL',
        PASSWORD_IN_URL,
        'high',
        85,
        'Remove password from URL. Use environment variables for connection strings.'
    ),
]


# =============================================================================
# ALL PATTERNS REGISTRY
# =============================================================================

ALL_PATTERNS = (
    CLOUD_PATTERNS +
    VCS_PATTERNS +
    DATABASE_PATTERNS +
    PAYMENT_PATTERNS +
    COMMUNICATION_PATTERNS +
    AI_API_PATTERNS +
    AUTH_PATTERNS +
    MONITORING_PATTERNS +
    GENERIC_PATTERNS
)


def get_patterns_by_severity(severity: str) -> list:
    """Get all patterns matching a specific severity level"""
    return [p for p in ALL_PATTERNS if p.severity == severity]


def get_high_confidence_patterns(min_confidence: int = 95) -> list:
    """Get patterns with confidence >= threshold"""
    return [p for p in ALL_PATTERNS if p.confidence >= min_confidence]


# Pattern statistics for reporting
PATTERN_COUNT = len(ALL_PATTERNS)
PATTERN_CATEGORIES = {
    'Cloud Providers': len(CLOUD_PATTERNS),
    'Version Control': len(VCS_PATTERNS),
    'Databases': len(DATABASE_PATTERNS),
    'Payment Providers': len(PAYMENT_PATTERNS),
    'Communication': len(COMMUNICATION_PATTERNS),
    'AI/ML APIs': len(AI_API_PATTERNS),
    'Authentication': len(AUTH_PATTERNS),
    'Monitoring': len(MONITORING_PATTERNS),
    'Generic Secrets': len(GENERIC_PATTERNS),
}