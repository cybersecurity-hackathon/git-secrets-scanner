"""
Severity scoring engine for GitSentinel.

Implements a weighted multi-factor scoring model to prioritise
findings by real-world risk. A live AWS key in a production
config scores far higher than a test password in a unit test.

Scoring formula:
    score = (base_severity × 0.3)
          + (validity × 0.3)
          + (exposure × 0.2)
          + (age × 0.1)
          + (context × 0.1)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from scanner.models import (
    Finding,
    Severity,
    SourceType,
    ValidationStatus,
)


# ============================================================
# Scoring Weights
# ============================================================

WEIGHT_BASE_SEVERITY = 0.30
WEIGHT_VALIDITY = 0.30
WEIGHT_EXPOSURE = 0.20
WEIGHT_AGE = 0.10
WEIGHT_CONTEXT = 0.10


# ============================================================
# Context Scoring Helpers
# ============================================================

# File patterns that suggest production use
PRODUCTION_FILE_PATTERNS = [
    ".env.production", ".env.prod", "production.yml", "production.yaml",
    "prod.config", "production.json", "deploy/", "infra/",
]

# File patterns that suggest config/infra
CONFIG_FILE_PATTERNS = [
    ".env", ".yml", ".yaml", ".json", ".toml", ".ini",
    ".cfg", ".conf", ".config", ".properties",
    "docker-compose", "Dockerfile", "kubernetes/", "k8s/",
]

# File patterns that suggest test/example use
TEST_FILE_PATTERNS = [
    "test_", "_test.", ".test.", "tests/", "test/",
    "spec/", "specs/", "__tests__/",
    "example", "sample", "demo", "mock", "fixture",
    "README", "CONTRIBUTING",
]


def _score_exposure(finding: Finding) -> float:
    """
    Score based on where in the repo the secret was found.

    Public/main branches are higher risk than feature branches
    or historical-only findings.
    """
    # Source type scoring
    if finding.source == SourceType.STAGED:
        return 9.0   # About to be committed — high urgency
    elif finding.source == SourceType.WORKING_TREE:
        # Check branch
        branch = finding.branch.lower()
        if branch in ("main", "master", "production", "release"):
            return 8.0
        elif branch.startswith(("feat", "feature", "dev")):
            return 5.0
        return 6.0
    elif finding.source == SourceType.HISTORY:
        return 3.0   # Historical — may already be rotated
    return 5.0


def _score_age(finding: Finding) -> float:
    """
    Score based on how recently the secret was committed.

    Recent leaks are more urgent because there's been less
    time for an attacker to find and exploit them — but also
    less time for the team to have noticed and rotated.
    """
    if finding.commit_date is None:
        return 5.0  # Unknown age — middle score

    now = datetime.now(timezone.utc)
    commit_date = finding.commit_date

    # Ensure timezone-aware comparison
    if commit_date.tzinfo is None:
        commit_date = commit_date.replace(tzinfo=timezone.utc)

    age_hours = (now - commit_date).total_seconds() / 3600

    if age_hours < 24:
        return 10.0   # Less than 24 hours — hot leak
    elif age_hours < 168:  # 7 days
        return 7.0
    elif age_hours < 720:  # 30 days
        return 5.0
    else:
        return 3.0    # Old — but still needs rotation


def _score_context(finding: Finding) -> float:
    """
    Score based on the file path and surrounding context.

    A secret in .env.production scores higher than one in
    tests/test_config.py.
    """
    path_lower = finding.file_path.lower()

    # Check for production files (highest risk)
    for pattern in PRODUCTION_FILE_PATTERNS:
        if pattern in path_lower:
            return 10.0

    # Check for test/example files (lowest risk)
    for pattern in TEST_FILE_PATTERNS:
        if pattern in path_lower:
            return 2.0

    # Check for config files (medium-high risk)
    for pattern in CONFIG_FILE_PATTERNS:
        if pattern in path_lower:
            return 7.0

    # Source code files — moderate risk
    return 5.0


# ============================================================
# Main Scoring Function
# ============================================================


def score_finding(finding: Finding) -> Finding:
    """
    Calculate the weighted severity score for a single finding.

    Mutates the finding in-place and returns it for chaining.

    Scoring formula:
        score = (base_severity × 0.3)
              + (validity × 0.3)
              + (exposure × 0.2)
              + (age × 0.1)
              + (context × 0.1)

    Args:
        finding: The Finding to score.

    Returns:
        The same Finding with final_score and severity_label set.
    """
    # Factor 1: Base severity from the detection rule
    base_score = finding.base_severity.score

    # Factor 2: Validation status
    validity_score = finding.validation_status.score

    # Factor 3: Exposure (branch, source type)
    exposure_score = _score_exposure(finding)

    # Factor 4: Age (how recently committed)
    age_score = _score_age(finding)

    # Factor 5: Context (file path, production vs test)
    context_score = _score_context(finding)

    # Weighted sum
    final_score = (
        base_score * WEIGHT_BASE_SEVERITY
        + validity_score * WEIGHT_VALIDITY
        + exposure_score * WEIGHT_EXPOSURE
        + age_score * WEIGHT_AGE
        + context_score * WEIGHT_CONTEXT
    )

    # Clamp to 0-10 range
    finding.final_score = max(0.0, min(10.0, final_score))

    # Classify
    if finding.final_score >= 8.0:
        finding.severity_label = "CRITICAL"
    elif finding.final_score >= 5.0:
        finding.severity_label = "HIGH"
    elif finding.final_score >= 3.0:
        finding.severity_label = "MEDIUM"
    else:
        finding.severity_label = "LOW"

    return finding


def score_findings(findings: list[Finding]) -> list[Finding]:
    """
    Score and sort a list of findings by severity.

    Args:
        findings: List of findings to score.

    Returns:
        Same list, scored and sorted (highest severity first).
    """
    for finding in findings:
        score_finding(finding)

    # Sort by final_score descending
    findings.sort(key=lambda f: f.final_score, reverse=True)

    return findings


def filter_by_severity(
    findings: list[Finding],
    min_severity: str = "LOW",
) -> list[Finding]:
    """
    Filter findings to only include those at or above a minimum severity.

    Args:
        findings: Scored findings list.
        min_severity: Minimum severity to include (CRITICAL, HIGH, MEDIUM, LOW).

    Returns:
        Filtered list of findings.
    """
    thresholds = {
        "CRITICAL": 8.0,
        "HIGH": 5.0,
        "MEDIUM": 3.0,
        "LOW": 0.0,
    }
    threshold = thresholds.get(min_severity.upper(), 0.0)
    return [f for f in findings if f.final_score >= threshold]
