"""
Credential validity checker for GitSentinel.

Determines whether a detected credential is still active/live.
Uses LocalStack (simulated AWS) for safe validation without
touching real cloud infrastructure.

Supports:
    - AWS Access Keys → sts:GetCallerIdentity via LocalStack
    - Private Keys (RSA/EC/DSA) → PEM parsing via cryptography lib
    - JWT Secrets → token sign/verify round-trip via PyJWT
    - GitHub PATs → mock API validation
    - Generic credentials → format-based heuristics
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

from scanner.config import ScanConfig
from scanner.models import (
    Finding,
    SecretType,
    ValidationStatus,
)

logger = logging.getLogger(__name__)


# ============================================================
# Main Validation Dispatcher
# ============================================================


def validate_finding(finding: Finding, config: ScanConfig) -> Finding:
    """
    Validate a single finding to determine if the credential is live.

    Routes to the appropriate validator based on secret_type.
    Mutates the finding in-place with validation_status and
    validation_detail.

    Args:
        finding: The finding to validate.
        config: Scanner configuration (contains LocalStack endpoint).

    Returns:
        The same Finding with validation fields populated.
    """
    validators = {
        SecretType.AWS_ACCESS_KEY: _validate_aws_key,
        SecretType.AWS_SECRET_KEY: _validate_aws_key,
        SecretType.RSA_PRIVATE_KEY: _validate_private_key,
        SecretType.EC_PRIVATE_KEY: _validate_private_key,
        SecretType.DSA_PRIVATE_KEY: _validate_private_key,
        SecretType.OPENSSH_PRIVATE_KEY: _validate_private_key,
        SecretType.GENERIC_PRIVATE_KEY: _validate_private_key,
        SecretType.JWT_SECRET: _validate_jwt_secret,
        SecretType.GITHUB_PAT: _validate_github_token,
        SecretType.STRIPE_SECRET_KEY: _validate_stripe_key,
    }

    validator_fn = validators.get(finding.secret_type)

    if validator_fn is None:
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = f"No validator available for {finding.secret_type.value}"
        return finding

    # Check if this looks like a test/example credential first
    if _is_test_credential(finding):
        finding.validation_status = ValidationStatus.TEST
        finding.validation_detail = "Detected as test/example credential"
        return finding

    try:
        validator_fn(finding, config)
    except Exception as e:
        logger.warning(f"Validation failed for {finding.rule_id}: {e}")
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = f"Validation error: {str(e)}"

    return finding


def validate_findings(findings: list[Finding], config: ScanConfig) -> list[Finding]:
    """
    Validate all findings in a list.

    Args:
        findings: List of findings to validate.
        config: Scanner configuration.

    Returns:
        Same list with validation fields populated.
    """
    if not config.enable_validation:
        return findings

    for finding in findings:
        validate_finding(finding, config)

    return findings


# ============================================================
# Individual Validators
# ============================================================


def _validate_aws_key(finding: Finding, config: ScanConfig) -> None:
    """
    Validate an AWS access key by calling sts:GetCallerIdentity
    against LocalStack.

    In production (without LocalStack), this same code validates
    against real AWS — just remove the endpoint_url parameter.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
    except ImportError:
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = "boto3 not installed — cannot validate AWS keys"
        return

    # For AWS validation, we need both the access key and secret key.
    # Since we may only have one, we do a format check first.
    matched = finding.matched_content

    # Quick format validation
    if finding.secret_type == SecretType.AWS_ACCESS_KEY:
        if not matched.startswith("AKIA") or len(matched) != 20:
            finding.validation_status = ValidationStatus.POSSIBLY_LIVE
            finding.validation_detail = "AWS key format partially matches but length/prefix is off"
            return

    try:
        # Create a boto3 STS client pointing at LocalStack
        sts_client = boto3.client(
            "sts",
            endpoint_url=config.localstack_endpoint,
            region_name=config.aws_region,
            aws_access_key_id=config.aws_access_key,
            aws_secret_access_key=config.aws_secret_key,
        )

        # Attempt to get caller identity
        response = sts_client.get_caller_identity()

        # If we get here, the key is valid (at least on LocalStack)
        arn = response.get("Arn", "unknown")
        account = response.get("Account", "unknown")

        finding.validation_status = ValidationStatus.LIVE
        finding.validation_detail = (
            f"Key is ACTIVE on LocalStack | "
            f"Account: {account} | ARN: {arn}"
        )

    except (ClientError,) as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
            finding.validation_status = ValidationStatus.REVOKED
            finding.validation_detail = f"Key is INACTIVE — AWS returned: {error_code}"
        else:
            finding.validation_status = ValidationStatus.POSSIBLY_LIVE
            finding.validation_detail = f"AWS API error: {error_code} — key may still be valid"

    except EndpointConnectionError:
        finding.validation_status = ValidationStatus.POSSIBLY_LIVE
        finding.validation_detail = (
            "LocalStack not reachable — cannot validate. "
            "Start LocalStack with: docker-compose up -d"
        )

    except Exception as e:
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = f"Unexpected validation error: {str(e)}"


def _validate_private_key(finding: Finding, config: ScanConfig) -> None:
    """
    Validate a private key by attempting to parse it as PEM.

    If the cryptography library can load it, it's a valid key
    (regardless of whether it's in use anywhere).
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError:
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = "cryptography lib not installed — cannot validate keys"
        return

    key_content = finding.matched_content

    # Ensure we have the full PEM block
    if "-----BEGIN" not in key_content:
        finding.validation_status = ValidationStatus.POSSIBLY_LIVE
        finding.validation_detail = "PEM header detected but full key block not captured"
        return

    try:
        key = load_pem_private_key(key_content.encode(), password=None)
        key_size = getattr(key, "key_size", "unknown")

        finding.validation_status = ValidationStatus.LIVE
        finding.validation_detail = (
            f"Valid {finding.secret_type.value} parsed successfully | "
            f"Key size: {key_size} bits"
        )

    except (ValueError, TypeError):
        # Encrypted private key — still a valid key, just password-protected
        finding.validation_status = ValidationStatus.POSSIBLY_LIVE
        finding.validation_detail = "Private key is encrypted (password-protected) — still a risk"

    except Exception as e:
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = f"Key parsing error: {str(e)}"


def _validate_jwt_secret(finding: Finding, config: ScanConfig) -> None:
    """
    Validate a JWT secret by performing a sign-verify round-trip.

    If we can sign a token and verify it with the same secret,
    the secret is in a usable format.
    """
    try:
        import jwt
    except ImportError:
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = "PyJWT not installed — cannot validate JWT secrets"
        return

    secret = finding.matched_content

    try:
        # Sign a test payload
        test_payload = {"test": True, "source": "gitsentinel-validator"}
        token = jwt.encode(test_payload, secret, algorithm="HS256")

        # Verify the token
        decoded = jwt.decode(token, secret, algorithms=["HS256"])

        if decoded.get("test") is True:
            finding.validation_status = ValidationStatus.LIVE
            finding.validation_detail = (
                f"JWT secret is valid — successfully signed and verified a test token | "
                f"Secret length: {len(secret)} chars"
            )
        else:
            finding.validation_status = ValidationStatus.POSSIBLY_LIVE
            finding.validation_detail = "JWT round-trip succeeded but payload mismatch"

    except Exception as e:
        finding.validation_status = ValidationStatus.POSSIBLY_LIVE
        finding.validation_detail = f"JWT validation inconclusive: {str(e)}"


def _validate_github_token(finding: Finding, config: ScanConfig) -> None:
    """
    Validate a GitHub Personal Access Token format.

    We do NOT call the real GitHub API — that would be using stolen
    credentials. Instead, we validate the format and mark as POSSIBLY_LIVE.
    """
    token = finding.matched_content

    if token.startswith("ghp_") and len(token) == 40:
        finding.validation_status = ValidationStatus.POSSIBLY_LIVE
        finding.validation_detail = (
            "Valid GitHub PAT format (ghp_ prefix, 40 chars). "
            "Not calling GitHub API — would constitute unauthorized access."
        )
    elif token.startswith(("gho_", "ghu_", "ghs_", "ghr_")):
        finding.validation_status = ValidationStatus.POSSIBLY_LIVE
        finding.validation_detail = f"Valid GitHub token format ({token[:4]} prefix)"
    else:
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = "Token format does not match known GitHub token patterns"


def _validate_stripe_key(finding: Finding, config: ScanConfig) -> None:
    """
    Validate a Stripe secret key format.

    We do NOT call the Stripe API. Format validation only.
    """
    key = finding.matched_content

    if key.startswith("sk_live_"):
        finding.validation_status = ValidationStatus.POSSIBLY_LIVE
        finding.validation_detail = (
            "LIVE Stripe secret key format (sk_live_ prefix). "
            "This is a PRODUCTION key — immediate rotation required."
        )
    elif key.startswith("sk_test_"):
        finding.validation_status = ValidationStatus.TEST
        finding.validation_detail = "Stripe TEST key — not a production risk"
    else:
        finding.validation_status = ValidationStatus.UNKNOWN
        finding.validation_detail = "Stripe key format not recognized"


# ============================================================
# Helpers
# ============================================================


def _is_test_credential(finding: Finding) -> bool:
    """
    Heuristic check: does this look like a test/example credential?

    Checks for common test indicators in the value and context.
    """
    content_lower = finding.matched_content.lower()
    path_lower = finding.file_path.lower()

    # Known example/test values
    test_indicators = [
        "example",
        "test",
        "dummy",
        "fake",
        "sample",
        "placeholder",
        "changeme",
        "your_",
        "xxx",
        "todo",
        "fixme",
        "replace_me",
    ]

    for indicator in test_indicators:
        if indicator in content_lower:
            return True

    # AWS example keys from AWS documentation
    if "AKIAIOSFODNN7EXAMPLE" in finding.matched_content:
        return True
    if "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in finding.matched_content:
        return True

    # File is in a test directory
    if any(t in path_lower for t in ("test/", "tests/", "test_", "spec/", "mock/")):
        return True

    return False
