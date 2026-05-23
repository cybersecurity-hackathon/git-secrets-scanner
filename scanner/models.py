"""Shared data models for GitSentinel.

All components import from this module to ensure consistent data structures
across the Sensor -> Analyser -> Responder pipeline.

These models serve as the data contracts between all pipeline stages:
  Collector -> Detector -> Scorer -> Validator -> Rotator -> Reporter

Every module imports from here — never define domain objects inline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ============================================================
# Enums
# ============================================================


class Severity(str, Enum):
    """Secret severity classification aligned with MITRE ATT&CK impact."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def score(self) -> float:
        """Base severity score (0-10 scale)."""
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
        }[self]

    @property
    def numeric(self) -> int:
        """Return a numeric weight used by the scoring engine."""
        return {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
        }[self]

    @property
    def emoji(self) -> str:
        """Emoji indicator for CLI output."""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
        }[self]


class ValidationStatus(str, Enum):
    """Result of credential liveness validation."""
    LIVE = "LIVE"             # Confirmed active — immediate rotation required
    POSSIBLY_LIVE = "POSSIBLY_LIVE"  # Could not confirm, but format is valid
    REVOKED = "REVOKED"       # Confirmed inactive / already rotated
    INVALID = "INVALID"       # Malformed — not a real credential
    UNKNOWN = "UNKNOWN"       # Validation not supported for this secret type
    TEST = "TEST"             # Detected as a test/example credential
    HISTORICAL = "HISTORICAL" # Found only in git history (deleted from working tree)

    @property
    def score(self) -> float:
        """Validity score (0-10 scale)."""
        return {
            ValidationStatus.LIVE: 10.0,
            ValidationStatus.POSSIBLY_LIVE: 7.0,
            ValidationStatus.UNKNOWN: 5.0,
            ValidationStatus.HISTORICAL: 4.0,
            ValidationStatus.REVOKED: 2.0,
            ValidationStatus.INVALID: 1.0,
            ValidationStatus.TEST: 1.0,
        }[self]


class SecretType(str, Enum):
    """Category of secret for routing to the correct validator/rotator.

    This enum supports both specific types (used by the teammate's scorer /
    validator / rotator) and generic categories (used by the detection engine).
    """
    # --- Specific types (for validator/rotator routing) ---
    AWS_ACCESS_KEY = "AWS Access Key ID"
    AWS_SECRET_KEY = "AWS Secret Access Key"
    GITHUB_PAT = "GitHub Personal Access Token"
    SLACK_TOKEN = "Slack Token"
    RSA_PRIVATE_KEY = "RSA Private Key"
    EC_PRIVATE_KEY = "EC Private Key"
    DSA_PRIVATE_KEY = "DSA Private Key"
    OPENSSH_PRIVATE_KEY = "OpenSSH Private Key"
    GENERIC_PRIVATE_KEY = "Generic Private Key"
    JWT_SECRET = "JWT Signing Secret"
    DB_CONNECTION_STRING = "Database Connection String"
    DB_PASSWORD = "Database Password"
    STRIPE_SECRET_KEY = "Stripe Secret Key"
    GENERIC_PASSWORD = "Generic Password"
    GENERIC_API_KEY = "Generic API Key"
    ENV_SECRET = "Environment Variable Secret"
    HIGH_ENTROPY_STRING = "High Entropy String"
    # --- Generic categories (used by detection engine patterns) ---
    CLOUD_CREDENTIAL = "cloud_credential"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    TOKEN = "token"
    CONNECTION_STRING = "connection_string"
    API_KEY = "api_key"
    SIGNING_KEY = "signing_key"
    GENERIC = "generic"


class RotationStatus(str, Enum):
    """Status of a credential rotation attempt."""
    PENDING = "PENDING"
    ROTATING = "ROTATING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"       # Not eligible for auto-rotation
    DRY_RUN = "DRY_RUN"      # Would have rotated, but --dry-run was set


class ScanSource(str, Enum):
    """Where in the Git repo the content was collected from."""
    WORKING_TREE = "working_tree"
    HISTORY = "history"
    STAGED = "staged"


# Alias for backward compatibility — teammate code may use SourceType
SourceType = ScanSource


class DetectionMethod(str, Enum):
    """How the secret was identified."""
    PATTERN = "pattern"         # Regex match
    ENTROPY = "entropy"         # High Shannon entropy
    COMBINED = "combined"       # Both regex + entropy flagged it


# ============================================================
# Data Classes
# ============================================================


@dataclass
class SecretPattern:
    """A single regex-based detection rule (gitleaks / truffleHog inspired).

    Used by patterns.py to define what we're looking for,
    and by detector.py to run the actual matching.

    Attributes:
        id:            Stable identifier, e.g. ``"aws-access-key-id"``.
        name:          Human-readable name for reports.
        pattern:       Compiled regex pattern.
        severity:      Default severity when this pattern matches.
        secret_type:   Category of credential.
        description:   Brief explanation shown in reports.
        can_validate:  Whether the validator module can check liveness.
        can_rotate:    Whether the rotator module can auto-rotate it.
        keywords:      Optional context keywords that raise confidence
                       (e.g. ``["aws", "access", "key"]``).
    """
    id: str                    # Unique rule ID, e.g. "aws-access-key-id"
    name: str                  # Human-readable name, e.g. "AWS Access Key ID"
    pattern: re.Pattern        # Compiled regex
    severity: Severity         # Base severity level
    secret_type: SecretType    # Category for routing
    can_validate: bool = False # Whether validator.py can check if it's live
    can_rotate: bool = False   # Whether rotator.py can auto-rotate it
    description: str = ""      # What this pattern catches (for reports)
    keywords: list[str] = field(default_factory=list)


@dataclass
class ScanTarget:
    """A single unit of content to be scanned.

    The Collector produces these; the Detector consumes them.
    Each represents one file's content from one specific commit.

    Attributes:
        file_path:    Repo-relative path, e.g. ``"config/database.yml"``.
        content:      The raw text content (file body or diff).
        commit_sha:   The commit this content belongs to (``"WORKING_TREE"``
                      for current files).
        commit_date:  When the commit was authored.
        author:       Git author string.
        branch:       The branch this was found on.
        source:       Whether it came from working tree, history, or staging.
    """
    file_path: str              # Relative path in repo, e.g. "config/database.yml"
    content: str                # The file content or diff content to scan
    commit_sha: str = "WORKING_TREE"  # Which commit this came from
    commit_date: Optional[datetime] = None  # When it was committed
    author: str = ""            # Commit author
    branch: str = "main"        # Which branch
    source: ScanSource = ScanSource.WORKING_TREE  # Where it was found


@dataclass
class Finding:
    """A single detected secret with full contextual metadata.

    The Detector produces these; the Scorer, Validator, Reporter, and
    Rotator consume them.  This is the primary data object that flows
    through the entire pipeline.
    """
    # --- What was found ---
    rule_id: str                    # Which pattern matched, e.g. "aws-access-key-id"
    rule_name: str                  # Human-readable name
    secret_type: SecretType         # Category
    severity: Severity              # Severity classification
    file_path: str                  # Relative path in repo

    # --- Location context ---
    line_number: int = 0            # Line number in the file (1-indexed)
    line_content: str = ""          # The full line containing the secret
    matched_text: str = ""          # The actual matched string
    redacted_match: str = ""        # Redacted version for safe display

    # --- Git metadata ---
    commit_sha: str = "WORKING_TREE"
    commit_date: Optional[datetime] = None
    author: str = ""                # Who committed it
    branch: str = "main"            # Which branch
    source: ScanSource = ScanSource.WORKING_TREE

    # --- Detection metadata ---
    detection_method: DetectionMethod = DetectionMethod.PATTERN
    entropy_score: float = 0.0      # Shannon entropy (if calculated)

    # --- Scoring (filled by scorer.py) ---
    base_severity: Severity = Severity.MEDIUM
    severity_score: float = 0.0     # Weighted severity score (0-10)
    final_score: float = 0.0        # Alias — same as severity_score
    severity_label: str = ""        # Final classification: CRITICAL, HIGH, MEDIUM, LOW

    # --- Validation (filled by validator.py) ---
    validation_status: ValidationStatus = ValidationStatus.UNKNOWN
    validation_detail: str = ""     # Extra info, e.g. "Key belongs to IAM user 'deploy-bot'"

    # --- Rotation (filled by rotator.py) ---
    rotation_status: RotationStatus = RotationStatus.SKIPPED
    rotation_detail: str = ""       # Extra info about rotation result

    # --- Extensibility ---
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        """Auto-generate a redacted version if not provided."""
        if not self.redacted_match and self.matched_text:
            self.redacted_match = _redact(self.matched_text)

    # Backward compatibility alias
    @property
    def matched_content(self) -> str:
        """Alias for matched_text (backward compat)."""
        return self.matched_text

    @property
    def entropy_value(self) -> float:
        """Alias for entropy_score (backward compat)."""
        return self.entropy_score

    @property
    def redacted_content(self) -> str:
        """Return the matched content with middle characters masked."""
        return self.redacted_match or _redact(self.matched_text)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "secret_type": self.secret_type.value,
            "matched_content_redacted": self.redacted_content,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "commit_sha": self.commit_sha[:8] if self.commit_sha else "",
            "commit_date": self.commit_date.isoformat() if self.commit_date else "",
            "author": self.author,
            "branch": self.branch,
            "source": self.source.value,
            "detection_method": self.detection_method.value,
            "entropy_score": round(self.entropy_score, 3),
            "severity": self.severity.value,
            "base_severity": self.base_severity.value,
            "final_score": round(self.final_score, 1),
            "severity_score": round(self.severity_score, 1),
            "severity_label": self.severity_label,
            "validation_status": self.validation_status.value,
            "validation_detail": self.validation_detail,
            "rotation_status": self.rotation_status.value,
            "rotation_detail": self.rotation_detail,
        }


@dataclass
class RotationRecord:
    """Audit record for a credential rotation event.

    Written to the audit log by rotator.py.
    """
    timestamp: datetime
    finding: Finding                    # The finding that triggered rotation
    old_key_hash: str                   # SHA-256 hash of old credential (never store raw)
    new_key_hint: str = ""              # First 4 chars of new credential (for verification)
    new_key_id: str = ""                # ID of the newly generated credential
    rotation_status: RotationStatus = RotationStatus.PENDING
    iam_user: str = ""                  # AWS IAM user (if applicable)
    details: str = ""                   # Human-readable summary of what happened
    detail: str = ""                    # Alias for details
    alert_sent: bool = False            # Whether Slack/console alert was dispatched

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON audit log."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.finding.rule_id,
            "secret_type": self.finding.secret_type.value,
            "file_path": self.finding.file_path,
            "old_key_hash": self.old_key_hash,
            "new_key_hint": self.new_key_hint,
            "new_key_id": self.new_key_id,
            "rotation_status": self.rotation_status.value,
            "iam_user": self.iam_user,
            "details": self.details or self.detail,
            "alert_sent": self.alert_sent,
        }


@dataclass
class ScanReport:
    """Complete scan results for a repository.

    Produced by the pipeline after all stages complete.
    """
    repo_path: str
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: Optional[datetime] = None
    total_commits_scanned: int = 0
    total_branches_scanned: int = 0
    total_files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    rotation_records: list[RotationRecord] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        """Scan duration in seconds."""
        if self.scan_end is None:
            return 0.0
        return (self.scan_end - self.scan_start).total_seconds()

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == Severity.CRITICAL or f.severity_label == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == Severity.HIGH or f.severity_label == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == Severity.MEDIUM or f.severity_label == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings
                   if f.severity == Severity.LOW or f.severity_label == "LOW")

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON report."""
        return {
            "repository": self.repo_path,
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat() if self.scan_end else "",
            "duration_seconds": round(self.duration_seconds, 2),
            "summary": {
                "total_commits_scanned": self.total_commits_scanned,
                "total_branches_scanned": self.total_branches_scanned,
                "total_files_scanned": self.total_files_scanned,
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "findings": [f.to_dict() for f in self.findings],
            "rotation_records": [r.to_dict() for r in self.rotation_records],
        }


# ============================================================
# Helpers
# ============================================================

def _redact(text: str, visible_chars: int = 4) -> str:
    """Redact a secret string, keeping first and last ``visible_chars``.

    Example::

        >>> _redact("AKIAIOSFODNN7EXAMPLE")
        'AKIA************MPLE'
    """
    if not text:
        return ""
    if len(text) <= visible_chars * 2:
        return text[:2] + "*" * (len(text) - 2) if len(text) > 2 else "*" * len(text)
    return text[:visible_chars] + "*" * (len(text) - visible_chars * 2) + text[-visible_chars:]
