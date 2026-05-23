"""
Shared data models for GitSentinel.

All components import from this module to ensure consistent data structures
across the Sensor → Analyser → Responder pipeline.
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


class Severity(Enum):
    """Secret severity classification."""
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
    def emoji(self) -> str:
        """Emoji indicator for CLI output."""
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
        }[self]


class ValidationStatus(Enum):
    """Result of credential liveness validation."""
    LIVE = "LIVE"             # Confirmed active — immediate rotation required
    POSSIBLY_LIVE = "POSSIBLY_LIVE"  # Could not confirm, but format is valid
    REVOKED = "REVOKED"       # Confirmed inactive / already rotated
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
            ValidationStatus.TEST: 1.0,
        }[self]


class SecretType(Enum):
    """Category of secret for routing to the correct validator/rotator."""
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


class RotationStatus(Enum):
    """Status of a credential rotation attempt."""
    PENDING = "PENDING"
    ROTATING = "ROTATING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"       # Not eligible for auto-rotation
    DRY_RUN = "DRY_RUN"      # Would have rotated, but --dry-run was set


class SourceType(Enum):
    """Where in the Git repo the secret was found."""
    WORKING_TREE = "working_tree"   # Current file on disk
    HISTORY = "history"             # Found in a past commit (may be deleted now)
    STAGED = "staged"               # In the Git staging area (pre-commit hook)


# ============================================================
# Data Classes
# ============================================================


@dataclass
class SecretPattern:
    """
    A single regex-based detection rule.

    Used by patterns.py to define what we're looking for,
    and by detector.py to run the actual matching.
    """
    id: str                    # Unique rule ID, e.g. "aws-access-key-id"
    name: str                  # Human-readable name, e.g. "AWS Access Key ID"
    pattern: re.Pattern        # Compiled regex
    severity: Severity         # Base severity level
    secret_type: SecretType    # Category for routing
    can_validate: bool = False # Whether validator.py can check if it's live
    can_rotate: bool = False   # Whether rotator.py can auto-rotate it
    description: str = ""      # What this pattern catches (for reports)


@dataclass
class ScanTarget:
    """
    A single unit of content to be scanned.

    The Collector produces these; the Detector consumes them.
    Each represents one file's content from one specific commit.
    """
    file_path: str              # Relative path in repo, e.g. "config/database.yml"
    content: str                # The file content or diff content to scan
    commit_sha: str = ""        # Which commit this came from (empty for working tree)
    commit_date: Optional[datetime] = None  # When it was committed
    author: str = ""            # Commit author
    branch: str = "main"        # Which branch
    source: SourceType = SourceType.WORKING_TREE  # Where it was found


@dataclass
class Finding:
    """
    A single detected secret.

    The Detector produces these; the Scorer, Validator, and Reporter consume them.
    """
    # --- What was found ---
    rule_id: str                    # Which pattern matched, e.g. "aws-access-key-id"
    rule_name: str                  # Human-readable name
    secret_type: SecretType         # Category
    matched_content: str            # The actual matched string (will be redacted in reports)

    # --- Where it was found ---
    file_path: str                  # Relative path in repo
    line_number: int = 0            # Line number in the file (1-indexed)
    commit_sha: str = ""            # Which commit
    commit_date: Optional[datetime] = None
    author: str = ""                # Who committed it
    branch: str = "main"            # Which branch
    source: SourceType = SourceType.WORKING_TREE

    # --- Detection metadata ---
    detection_method: str = "pattern"  # "pattern" or "entropy"
    entropy_value: float = 0.0         # Shannon entropy (if detected by entropy)

    # --- Scoring (filled by scorer.py) ---
    base_severity: Severity = Severity.MEDIUM
    final_score: float = 0.0       # Weighted severity score (0-10)
    severity_label: str = ""       # Final classification: CRITICAL, HIGH, MEDIUM, LOW

    # --- Validation (filled by validator.py) ---
    validation_status: ValidationStatus = ValidationStatus.UNKNOWN
    validation_detail: str = ""    # Extra info, e.g. "Key belongs to IAM user 'deploy-bot'"

    # --- Rotation (filled by rotator.py) ---
    rotation_status: RotationStatus = RotationStatus.SKIPPED
    rotation_detail: str = ""      # Extra info about rotation result

    @property
    def redacted_content(self) -> str:
        """Return the matched content with middle characters masked."""
        s = self.matched_content
        if len(s) <= 8:
            return s[:2] + "*" * (len(s) - 2)
        return s[:4] + "*" * (len(s) - 8) + s[-4:]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "secret_type": self.secret_type.value,
            "matched_content_redacted": self.redacted_content,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "commit_sha": self.commit_sha[:8] if self.commit_sha else "",
            "commit_date": self.commit_date.isoformat() if self.commit_date else "",
            "author": self.author,
            "branch": self.branch,
            "source": self.source.value,
            "detection_method": self.detection_method,
            "entropy_value": round(self.entropy_value, 3),
            "base_severity": self.base_severity.value,
            "final_score": round(self.final_score, 1),
            "severity_label": self.severity_label,
            "validation_status": self.validation_status.value,
            "validation_detail": self.validation_detail,
            "rotation_status": self.rotation_status.value,
            "rotation_detail": self.rotation_detail,
        }


@dataclass
class RotationRecord:
    """
    Audit record for a credential rotation event.

    Written to the audit log by rotator.py.
    """
    timestamp: datetime
    finding: Finding                    # The finding that triggered rotation
    old_key_hash: str                   # SHA-256 hash of old credential (never store raw)
    new_key_hint: str = ""              # First 4 chars of new credential (for verification)
    rotation_status: RotationStatus = RotationStatus.PENDING
    iam_user: str = ""                  # AWS IAM user (if applicable)
    detail: str = ""                    # Human-readable summary of what happened
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
            "rotation_status": self.rotation_status.value,
            "iam_user": self.iam_user,
            "detail": self.detail,
            "alert_sent": self.alert_sent,
        }


@dataclass
class ScanReport:
    """
    Complete scan results for a repository.

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
        return sum(1 for f in self.findings if f.severity_label == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity_label == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity_label == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity_label == "LOW")

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
