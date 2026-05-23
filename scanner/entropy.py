"""
Shannon entropy calculator for detecting high-entropy strings
that may be secrets not caught by regex patterns.

Shannon entropy measures the "randomness" of a string.
Typical English text has ~3.5 bits/char. API keys and passwords
tend to have > 4.5 bits/char for base64, > 3.0 bits/char for hex.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass
from typing import Optional

from scanner.models import (
    Finding,
    SecretType,
    Severity,
    SourceType,
    ValidationStatus,
)


# ============================================================
# Configuration
# ============================================================

# Character sets for entropy classification
BASE64_CHARS = string.ascii_letters + string.digits + "+/="
HEX_CHARS = string.hexdigits

# Entropy thresholds (bits per character)
HEX_ENTROPY_THRESHOLD = 3.0
BASE64_ENTROPY_THRESHOLD = 4.5

# Minimum string length to consider for entropy analysis
MIN_TOKEN_LENGTH = 16
MAX_TOKEN_LENGTH = 256

# Variable names that suggest a value might be a secret
SUSPICIOUS_VAR_NAMES = re.compile(
    r"(?i)(secret|token|key|password|passwd|pwd|api_key|apikey|"
    r"access_key|private_key|auth|credential|signing|encrypt|"
    r"salt|hash|bearer|jwt|session|cookie_secret|client_secret|"
    r"db_pass|database_password|connection_string|dsn)",
)

# File extensions that commonly contain configuration/secrets
SENSITIVE_FILE_EXTENSIONS = {
    ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
    ".conf", ".config", ".properties", ".xml", ".pem", ".key",
}

# Patterns to EXCLUDE from entropy analysis (known false positives)
FALSE_POSITIVE_PATTERNS = [
    re.compile(r"^[0-9a-f]{32}$"),              # MD5 hashes (common in lockfiles)
    re.compile(r"^[0-9a-f]{40}$"),              # SHA-1 hashes (git commit hashes)
    re.compile(r"^[0-9a-f]{64}$"),              # SHA-256 hashes (checksums)
    re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$"),  # UUIDs
    re.compile(r"^\$2[aby]\$.+\$"),              # bcrypt hashes
    re.compile(r"^https?://"),                   # URLs
    re.compile(r"^data:"),                       # Data URIs
    re.compile(r"^[A-Za-z0-9+/]{4}={1,2}$"),   # Very short base64 (not secrets)
]


# ============================================================
# Core Functions
# ============================================================


def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string in bits per character.

    H(X) = -Σ p(x) * log2(p(x))

    Args:
        data: Input string to calculate entropy for.

    Returns:
        Entropy value in bits per character. Higher = more random.
        Typical values:
            - English text: ~3.5 bits/char
            - Hex-encoded secrets: ~3.5-4.0 bits/char
            - Base64-encoded secrets: ~5.0-6.0 bits/char
            - Truly random bytes: ~8.0 bits/char
    """
    if not data:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    length = len(data)
    entropy = 0.0

    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def classify_charset(token: str) -> str:
    """
    Determine if a token is primarily hex or base64 encoded.

    Args:
        token: The string to classify.

    Returns:
        "hex", "base64", or "other"
    """
    if not token:
        return "other"

    hex_count = sum(1 for c in token if c in HEX_CHARS)
    b64_count = sum(1 for c in token if c in BASE64_CHARS)

    total = len(token)

    if hex_count / total > 0.95:
        return "hex"
    elif b64_count / total > 0.95:
        return "base64"
    return "other"


def is_false_positive(token: str) -> bool:
    """
    Check if a high-entropy token is a known false positive.

    Args:
        token: The string to check.

    Returns:
        True if the token matches a known false positive pattern.
    """
    for fp_pattern in FALSE_POSITIVE_PATTERNS:
        if fp_pattern.match(token):
            return True
    return False


def extract_tokens(line: str) -> list[tuple[str, str]]:
    """
    Extract potential secret tokens from a line of code.

    Looks for:
      - Quoted strings (single or double quotes)
      - Assignment values (after = or :)
      - Standalone high-entropy words

    Args:
        line: A single line of source code.

    Returns:
        List of (token, context) tuples where context is the
        variable name or surrounding text.
    """
    tokens: list[tuple[str, str]] = []

    # Pattern 1: Quoted strings in assignments
    # e.g., SECRET_KEY = "abc123..."  or  secret: 'xyz789...'
    assignment_pattern = re.compile(
        r"""([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*['"]([^'"]{%d,%d})['"]"""
        % (MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH)
    )
    for match in assignment_pattern.finditer(line):
        var_name, value = match.group(1), match.group(2)
        tokens.append((value, var_name))

    # Pattern 2: Standalone quoted strings (no assignment)
    # e.g., headers = {"Authorization": "Bearer eyJhbG..."}
    standalone_pattern = re.compile(
        r"""['"]([A-Za-z0-9+/=_\-]{%d,%d})['"]"""
        % (MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH)
    )
    for match in standalone_pattern.finditer(line):
        value = match.group(1)
        # Avoid duplicates from assignment pattern
        if not any(value == t[0] for t in tokens):
            tokens.append((value, ""))

    return tokens


@dataclass
class EntropyFinding:
    """Intermediate result from entropy analysis before converting to Finding."""
    token: str
    entropy: float
    charset: str          # "hex", "base64", "other"
    context_var: str      # Variable name if detected in assignment
    line_number: int
    line_content: str
    confidence: float     # 0.0 - 1.0


def analyze_line(
    line: str,
    line_number: int,
    file_path: str = "",
) -> list[EntropyFinding]:
    """
    Analyze a single line for high-entropy strings.

    Args:
        line: The line content.
        line_number: 1-indexed line number.
        file_path: File path for context scoring.

    Returns:
        List of EntropyFinding objects for tokens exceeding thresholds.
    """
    results: list[EntropyFinding] = []

    # Skip comment lines
    stripped = line.strip()
    if stripped.startswith(("#", "//", "/*", "*", "<!--")):
        return results

    tokens = extract_tokens(line)

    for token, context_var in tokens:
        # Skip known false positives
        if is_false_positive(token):
            continue

        charset = classify_charset(token)
        entropy = shannon_entropy(token)

        # Apply threshold based on charset
        threshold = (
            HEX_ENTROPY_THRESHOLD if charset == "hex"
            else BASE64_ENTROPY_THRESHOLD if charset == "base64"
            else BASE64_ENTROPY_THRESHOLD  # Default to stricter threshold
        )

        if entropy < threshold:
            continue

        # Calculate confidence based on multiple signals
        confidence = _calculate_confidence(
            entropy=entropy,
            charset=charset,
            context_var=context_var,
            file_path=file_path,
            token_length=len(token),
        )

        # Only report if confidence is meaningful
        if confidence >= 0.3:
            results.append(EntropyFinding(
                token=token,
                entropy=entropy,
                charset=charset,
                context_var=context_var,
                line_number=line_number,
                line_content=line.rstrip(),
                confidence=confidence,
            ))

    return results


def analyze_content(
    content: str,
    file_path: str = "",
) -> list[EntropyFinding]:
    """
    Analyze entire file content for high-entropy strings.

    Args:
        content: Full file content.
        file_path: File path for context scoring.

    Returns:
        List of EntropyFinding objects.
    """
    results: list[EntropyFinding] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line_results = analyze_line(line, line_number, file_path)
        results.extend(line_results)

    return results


def entropy_findings_to_findings(
    entropy_findings: list[EntropyFinding],
    file_path: str,
    commit_sha: str = "",
    commit_date: Optional[object] = None,
    author: str = "",
    branch: str = "main",
    source: SourceType = SourceType.WORKING_TREE,
) -> list[Finding]:
    """
    Convert EntropyFinding objects to standard Finding objects.

    This bridges the entropy module's output into the shared
    data model used by the rest of the pipeline.
    """
    findings: list[Finding] = []

    for ef in entropy_findings:
        # Determine severity based on confidence and context
        if ef.confidence >= 0.8:
            severity = Severity.HIGH
        elif ef.confidence >= 0.5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        findings.append(Finding(
            rule_id="entropy-detection",
            rule_name=f"High Entropy String ({ef.charset})",
            secret_type=SecretType.HIGH_ENTROPY_STRING,
            matched_content=ef.token,
            file_path=file_path,
            line_number=ef.line_number,
            commit_sha=commit_sha,
            commit_date=commit_date,
            author=author,
            branch=branch,
            source=source,
            detection_method="entropy",
            entropy_value=ef.entropy,
            base_severity=severity,
            validation_status=ValidationStatus.UNKNOWN,
        ))

    return findings


# ============================================================
# Internal Helpers
# ============================================================


def _calculate_confidence(
    entropy: float,
    charset: str,
    context_var: str,
    file_path: str,
    token_length: int,
) -> float:
    """
    Calculate a confidence score (0.0-1.0) that a high-entropy
    string is actually a secret.

    Combines multiple heuristic signals:
      - Entropy value relative to threshold
      - Whether it's assigned to a suspicious variable name
      - Whether it's in a sensitive file type
      - Token length (longer = more likely to be a secret)
    """
    confidence = 0.0

    # Signal 1: Entropy magnitude (higher entropy = more confident)
    threshold = (
        HEX_ENTROPY_THRESHOLD if charset == "hex"
        else BASE64_ENTROPY_THRESHOLD
    )
    entropy_excess = entropy - threshold
    confidence += min(entropy_excess * 0.3, 0.3)  # Max 0.3 from entropy

    # Signal 2: Suspicious variable name
    if context_var and SUSPICIOUS_VAR_NAMES.search(context_var):
        confidence += 0.35  # Strong signal

    # Signal 3: Sensitive file type
    if file_path:
        import os
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SENSITIVE_FILE_EXTENSIONS:
            confidence += 0.15

    # Signal 4: Token length (20-64 chars is the sweet spot for secrets)
    if 20 <= token_length <= 64:
        confidence += 0.15
    elif token_length > 64:
        confidence += 0.05  # Long strings are less likely to be secrets

    # Signal 5: No suspicious context — penalty
    if not context_var:
        confidence -= 0.1

    return max(0.0, min(1.0, confidence))
