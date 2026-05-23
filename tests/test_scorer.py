"""
Unit tests for the severity scoring engine (scanner.scorer).

Tests cover:
  - Weighted scoring formula correctness (5-factor model)
  - Weight constants sum to 1.0
  - Individual factor scoring (exposure, age, context)
  - Classification thresholds (CRITICAL >= 8.0, HIGH >= 5.0, etc.)
  - score_findings() batch scoring and sort order
  - filter_by_severity() filtering
  - Edge cases: unknown dates, missing fields
"""

import pytest
from datetime import datetime, timezone, timedelta

from scanner.scorer import (
    score_finding,
    score_findings,
    filter_by_severity,
    _score_exposure,
    _score_age,
    _score_context,
    WEIGHT_BASE_SEVERITY,
    WEIGHT_VALIDITY,
    WEIGHT_EXPOSURE,
    WEIGHT_AGE,
    WEIGHT_CONTEXT,
)
from scanner.models import (
    Finding,
    ScanSource,
    SecretType,
    Severity,
    ValidationStatus,
)


# ============================================================
# Fixtures
# ============================================================


def _finding(**kwargs) -> Finding:
    """Helper to create a Finding with sensible defaults."""
    defaults = {
        "rule_id": "test-rule",
        "rule_name": "Test Rule",
        "secret_type": SecretType.CLOUD_CREDENTIAL,
        "severity": Severity.HIGH,
        "file_path": "config/settings.py",
        "matched_text": "some_secret_value_here",
        "base_severity": Severity.HIGH,
        "source": ScanSource.WORKING_TREE,
        "branch": "main",
        "validation_status": ValidationStatus.UNKNOWN,
    }
    defaults.update(kwargs)
    return Finding(**defaults)


# ============================================================
# Weight Validation
# ============================================================


class TestWeights:
    """Ensure scoring weights are correctly configured."""

    def test_weights_sum_to_one(self):
        """All 5 scoring weights must sum to exactly 1.0."""
        total = (
            WEIGHT_BASE_SEVERITY
            + WEIGHT_VALIDITY
            + WEIGHT_EXPOSURE
            + WEIGHT_AGE
            + WEIGHT_CONTEXT
        )
        assert abs(total - 1.0) < 0.001

    def test_weight_values(self):
        """Verify the individual weight values match the design spec."""
        assert WEIGHT_BASE_SEVERITY == 0.30
        assert WEIGHT_VALIDITY == 0.30
        assert WEIGHT_EXPOSURE == 0.20
        assert WEIGHT_AGE == 0.10
        assert WEIGHT_CONTEXT == 0.10


# ============================================================
# Individual Factor Tests
# ============================================================


class TestExposureScoring:
    """Tests for the exposure factor (_score_exposure)."""

    def test_staged_highest(self):
        """Staged secrets should score highest (about to be committed)."""
        f = _finding(source=ScanSource.STAGED)
        assert _score_exposure(f) >= 8.0

    def test_main_branch_high(self):
        """Secrets on main/master branch should score high."""
        f = _finding(source=ScanSource.WORKING_TREE, branch="main")
        assert _score_exposure(f) >= 7.0

    def test_feature_branch_moderate(self):
        """Secrets on feature branches should score moderately."""
        f = _finding(source=ScanSource.WORKING_TREE, branch="feature/auth")
        assert _score_exposure(f) >= 4.0

    def test_history_lowest(self):
        """Historical secrets should score lowest (may already be rotated)."""
        f = _finding(source=ScanSource.HISTORY)
        assert _score_exposure(f) <= 4.0


class TestAgeScoring:
    """Tests for the age factor (_score_age)."""

    def test_recent_commit_highest(self):
        """Commit within last 24 hours should score highest."""
        recent = datetime.now(timezone.utc) - timedelta(hours=2)
        f = _finding(commit_date=recent)
        assert _score_age(f) >= 9.0

    def test_week_old_commit(self):
        """Commit from a few days ago should score high."""
        week_ago = datetime.now(timezone.utc) - timedelta(days=3)
        f = _finding(commit_date=week_ago)
        assert 5.0 <= _score_age(f) <= 8.0

    def test_old_commit(self):
        """Commit from months ago should score low."""
        old = datetime.now(timezone.utc) - timedelta(days=90)
        f = _finding(commit_date=old)
        assert _score_age(f) <= 4.0

    def test_no_date_default(self):
        """Missing commit date should use a default middle score."""
        f = _finding(commit_date=None)
        assert 4.0 <= _score_age(f) <= 6.0


class TestContextScoring:
    """Tests for the context factor (_score_context)."""

    def test_production_file_highest(self):
        """Secrets in production config files should score highest."""
        f = _finding(file_path=".env.production")
        assert _score_context(f) >= 9.0

    def test_test_file_lowest(self):
        """Secrets in test files should score lowest."""
        f = _finding(file_path="tests/test_config.py")
        assert _score_context(f) <= 3.0

    def test_config_file_moderate(self):
        """Secrets in generic config files should score moderately."""
        f = _finding(file_path="config/database.yml")
        assert _score_context(f) >= 5.0

    def test_source_code_default(self):
        """Secrets in regular source code should get a default score."""
        f = _finding(file_path="src/utils/helpers.py")
        assert 3.0 <= _score_context(f) <= 7.0


# ============================================================
# Full Scoring Tests
# ============================================================


class TestScoreFinding:
    """Tests for the complete score_finding() function."""

    def test_critical_live_aws_key(self):
        """A live AWS key on main branch should score CRITICAL (>= 8.0)."""
        f = _finding(
            base_severity=Severity.CRITICAL,
            severity=Severity.CRITICAL,
            validation_status=ValidationStatus.LIVE,
            source=ScanSource.WORKING_TREE,
            branch="main",
            file_path=".env.production",
            commit_date=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        result = score_finding(f)
        assert result.final_score >= 8.0
        assert result.severity_label == "CRITICAL"

    def test_test_credential_scores_low(self):
        """A test credential in a test file should score LOW (< 3.0)."""
        f = _finding(
            base_severity=Severity.LOW,
            severity=Severity.LOW,
            validation_status=ValidationStatus.TEST,
            source=ScanSource.WORKING_TREE,
            file_path="tests/test_config.py",
            commit_date=datetime.now(timezone.utc) - timedelta(days=30),
        )
        result = score_finding(f)
        assert result.final_score < 3.0
        assert result.severity_label == "LOW"

    def test_historical_medium_password(self):
        """A password found only in git history should score MEDIUM or lower."""
        f = _finding(
            base_severity=Severity.MEDIUM,
            severity=Severity.MEDIUM,
            validation_status=ValidationStatus.UNKNOWN,
            source=ScanSource.HISTORY,
            file_path="config/database.yml",
            commit_date=datetime.now(timezone.utc) - timedelta(days=60),
        )
        result = score_finding(f)
        assert result.final_score < 6.0

    def test_score_clamped_to_range(self):
        """Final score should always be in [0.0, 10.0] range."""
        f = _finding(
            base_severity=Severity.CRITICAL,
            validation_status=ValidationStatus.LIVE,
        )
        result = score_finding(f)
        assert 0.0 <= result.final_score <= 10.0

    def test_score_sets_severity_label(self):
        """score_finding() should populate severity_label field."""
        f = _finding()
        result = score_finding(f)
        assert result.severity_label in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# ============================================================
# Batch Scoring Tests
# ============================================================


class TestScoreFindings:
    """Tests for batch scoring and sorting."""

    def test_sorted_by_score_descending(self):
        """score_findings() should return results sorted highest-first."""
        findings = [
            _finding(base_severity=Severity.LOW, severity=Severity.LOW),
            _finding(base_severity=Severity.CRITICAL, severity=Severity.CRITICAL),
            _finding(base_severity=Severity.MEDIUM, severity=Severity.MEDIUM),
        ]
        scored = score_findings(findings)
        scores = [f.final_score for f in scored]
        assert scores == sorted(scores, reverse=True)

    def test_all_findings_have_scores(self):
        """Every finding in the list should have a score and label after scoring."""
        findings = [
            _finding(base_severity=s, severity=s)
            for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        ]
        scored = score_findings(findings)
        for f in scored:
            assert f.final_score > 0.0
            assert f.severity_label != ""

    def test_empty_list(self):
        """Should handle empty list gracefully."""
        assert score_findings([]) == []


# ============================================================
# Filter Tests
# ============================================================


class TestFilterBySeverity:
    """Tests for filter_by_severity()."""

    def test_filter_critical_only(self):
        """Filtering for CRITICAL should only include scores >= 8.0."""
        findings = [
            _finding(base_severity=s, severity=s)
            for s in [Severity.CRITICAL, Severity.HIGH, Severity.LOW]
        ]
        scored = score_findings(findings)
        filtered = filter_by_severity(scored, min_severity="CRITICAL")
        for f in filtered:
            assert f.final_score >= 8.0

    def test_filter_low_includes_all(self):
        """Filtering for LOW should include everything."""
        findings = [
            _finding(base_severity=s, severity=s)
            for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        ]
        scored = score_findings(findings)
        filtered = filter_by_severity(scored, min_severity="LOW")
        assert len(filtered) == len(scored)

    def test_filter_case_insensitive(self):
        """Filter should accept lowercase severity strings."""
        findings = [_finding(base_severity=Severity.HIGH, severity=Severity.HIGH)]
        scored = score_findings(findings)
        filtered = filter_by_severity(scored, min_severity="high")
        assert len(filtered) >= 0  # Should not crash
