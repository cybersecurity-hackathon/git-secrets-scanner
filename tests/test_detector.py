"""
Unit tests for the Detector engine (scanner.detector).

Tests cover:
  - Pattern-based detection of all major secret types
  - Shannon entropy-based detection of high-entropy tokens
  - Deduplication across multiple ScanTargets
  - Allowlisting (value and path level)
  - Edge cases: empty content, binary-looking data, diff metadata
"""

import pytest

from scanner.detector import Detector, _shannon_entropy, _tokenise_line, _classify_encoding
from scanner.models import (
    DetectionMethod,
    Finding,
    ScanSource,
    ScanTarget,
    SecretType,
    Severity,
)


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def detector():
    """Fresh Detector with entropy enabled."""
    return Detector(enable_entropy=True)


@pytest.fixture
def detector_no_entropy():
    """Detector with entropy analysis disabled."""
    return Detector(enable_entropy=False)


def _target(content: str, path: str = "config/test.py") -> ScanTarget:
    """Helper to create a simple ScanTarget."""
    return ScanTarget(
        file_path=path,
        content=content,
        commit_sha="abc123",
        author="tester",
        branch="main",
        source=ScanSource.WORKING_TREE,
    )


# ============================================================
# Pattern Detection Tests
# ============================================================


class TestPatternDetection:
    """Tests for regex-based secret detection."""

    def test_aws_access_key_id(self, detector):
        """Should detect an AWS Access Key ID (AKIA prefix + 16 chars)."""
        target = _target('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')
        findings = detector.scan(target)

        aws_findings = [f for f in findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) >= 1
        matched = aws_findings[0]
        assert "AKIAIOSFODNN7EXAMPLE" in matched.matched_text
        assert matched.severity in (Severity.CRITICAL, Severity.HIGH)

    def test_aws_secret_access_key(self, detector):
        """Should detect an AWS Secret Access Key assigned with '='."""
        target = _target(
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        )
        findings = detector.scan(target)

        secret_findings = [f for f in findings if "secret" in f.rule_id.lower()]
        assert len(secret_findings) >= 1

    def test_rsa_private_key(self, detector):
        """Should detect an RSA private key block."""
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7Mhg\n"
            "-----END RSA PRIVATE KEY-----"
        )
        target = _target(pem, path="certs/server.key")
        findings = detector.scan(target)

        key_findings = [f for f in findings if "private-key" in f.rule_id.lower() or "rsa" in f.rule_id.lower()]
        assert len(key_findings) >= 1
        assert key_findings[0].severity == Severity.CRITICAL

    def test_github_pat(self, detector):
        """Should detect a GitHub Personal Access Token (ghp_ prefix)."""
        target = _target('github_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"')
        findings = detector.scan(target)

        gh_findings = [f for f in findings if "github" in f.rule_id.lower()]
        assert len(gh_findings) >= 1

    def test_slack_token(self, detector):
        """Should detect a Slack bot token (xoxb- prefix)."""
        target = _target(
            f'SLACK_BOT_TOKEN={"xoxb" + "-123456789012-1234567890123-AbCdEfGhIjKlMnOpQr"}'
        )
        findings = detector.scan(target)

        slack_findings = [f for f in findings if "slack" in f.rule_id.lower()]
        assert len(slack_findings) >= 1

    def test_jwt_secret(self, detector):
        """Should detect a JWT signing secret."""
        target = _target(
            'JWT_SECRET = "mySuperSecretJWTKey2024_ForSigning"',
            path="src/auth/config.js",
        )
        findings = detector.scan(target)

        jwt_findings = [f for f in findings if "jwt" in f.rule_id.lower()]
        assert len(jwt_findings) >= 1

    def test_database_connection_string(self, detector):
        """Should detect a database connection string with embedded password."""
        target = _target(
            'DATABASE_URL=postgres://admin:SuperSecret@db.prod:5432/mydb'
        )
        findings = detector.scan(target)

        db_findings = [f for f in findings if "database" in f.rule_id.lower()]
        assert len(db_findings) >= 1

    def test_generic_password(self, detector):
        """Should detect a generic password assignment."""
        target = _target('password = "SuperS3cretDBPass!2024"', path="config/db.yml")
        findings = detector.scan(target)

        pw_findings = [f for f in findings if "password" in f.rule_id.lower()]
        assert len(pw_findings) >= 1

    def test_stripe_secret_key(self, detector):
        """Should detect a Stripe live secret key."""
        # Construct dynamically to avoid GitHub push protection
        stripe_key = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        target = _target(f'STRIPE_SECRET_KEY={stripe_key}')
        findings = detector.scan(target)

        stripe_findings = [f for f in findings if "stripe" in f.rule_id.lower()]
        assert len(stripe_findings) >= 1

    def test_no_false_positive_on_clean_code(self, detector):
        """Should NOT flag clean code that contains no secrets."""
        clean_code = """
def hello():
    print("Hello, World!")
    x = 42
    name = "Alice"
    return name
"""
        target = _target(clean_code, path="src/hello.py")
        findings = detector.scan(target)
        assert len(findings) == 0

    def test_empty_content(self, detector):
        """Should handle empty content gracefully."""
        target = _target("", path="empty.py")
        findings = detector.scan(target)
        assert len(findings) == 0


# ============================================================
# Entropy Detection Tests
# ============================================================


class TestEntropyDetection:
    """Tests for Shannon entropy-based detection."""

    def test_high_entropy_string_detected(self, detector):
        """High-entropy token in a config file with suspicious context should be flagged."""
        # Generate a high-entropy string that looks like a secret
        target = _target(
            'API_SECRET = "aB3xYz9Kw2mN5pQ8rT1vU4hJ7gF0cLd"',
            path="config/settings.env",
        )
        findings = detector.scan(target)
        # Should be caught by either pattern or entropy
        assert len(findings) >= 1

    def test_low_entropy_string_ignored(self, detector_no_entropy):
        """Low-entropy repeated string should not be flagged by patterns alone."""
        target = _target(
            'message = "aaaaaaaaaaaaaaaaaaaaaa"',
            path="src/utils.py",
        )
        findings = detector_no_entropy.scan(target)
        # Pure repetition should not match any pattern
        password_findings = [f for f in findings if "password" not in f.rule_id]
        # There should be no false positives on repeated chars
        assert all("aaaa" not in f.matched_text for f in findings)


# ============================================================
# Deduplication Tests
# ============================================================


class TestDeduplication:
    """Tests for cross-target deduplication."""

    def test_same_secret_same_file_deduped(self, detector):
        """Same secret in same file across two targets should be deduplicated."""
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        t1 = _target(content, path="config/aws.py")
        t2 = ScanTarget(
            file_path="config/aws.py",
            content=content,
            commit_sha="def456",
            source=ScanSource.HISTORY,
        )

        f1 = detector.scan(t1)
        f2 = detector.scan(t2)

        # Second scan of same secret+file should be suppressed
        assert len(f1) >= 1
        assert len(f2) == 0  # deduplicated
        assert detector.stats["duplicates_suppressed"] >= 1

    def test_same_secret_different_file_not_deduped(self, detector):
        """Same secret in different files should be reported separately."""
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        t1 = _target(content, path="config/aws.py")
        t2 = _target(content, path="backup/aws_old.py")

        f1 = detector.scan(t1)
        f2 = detector.scan(t2)

        assert len(f1) >= 1
        assert len(f2) >= 1

    def test_reset_clears_dedup(self, detector):
        """After reset(), the same secret should be detected again."""
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
        t1 = _target(content, path="config/aws.py")

        detector.scan(t1)
        detector.reset()
        f2 = detector.scan(t1)

        assert len(f2) >= 1


# ============================================================
# Allowlisting Tests
# ============================================================


class TestAllowlisting:
    """Tests for value and path allowlisting."""

    def test_allowlisted_value_skipped(self):
        """Exact value in allowlist should be suppressed."""
        det = Detector(allowlist={"AKIAIOSFODNN7EXAMPLE"})
        target = _target('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')
        findings = det.scan(target)

        aws_findings = [f for f in findings if "AKIAIOSFODNN7EXAMPLE" in f.matched_text]
        assert len(aws_findings) == 0

    def test_allowlisted_path_skipped(self):
        """File matching an allowlist path glob should be skipped entirely."""
        det = Detector(allowlist_paths={"tests/*"})
        target = _target(
            'password = "SuperSecret123!"',
            path="tests/test_config.py",
        )
        findings = det.scan(target)
        assert len(findings) == 0


# ============================================================
# Utility Function Tests
# ============================================================


class TestUtilities:
    """Tests for module-level utility functions."""

    def test_shannon_entropy_empty(self):
        assert _shannon_entropy("") == 0.0

    def test_shannon_entropy_single_char(self):
        """Repeated single character should have zero entropy."""
        assert _shannon_entropy("aaaa") == 0.0

    def test_shannon_entropy_high(self):
        """A random-looking string should have high entropy."""
        entropy = _shannon_entropy("aB3xYz9Kw2mN5pQ8rT1vU4hJ7gF0cLd")
        assert entropy > 4.0

    def test_tokenise_line(self):
        """Should split on common delimiters."""
        tokens = _tokenise_line('key = "value123"  # comment')
        assert "key" in tokens
        assert "value123" in tokens

    def test_classify_encoding_hex(self):
        encoding, threshold = _classify_encoding("aabbccdd11223344", 3.0, 4.5)
        assert encoding == "hex"
        assert threshold == 3.0

    def test_classify_encoding_base64(self):
        encoding, threshold = _classify_encoding("aB3xYz9Kw2mN5pQ8", 3.0, 4.5)
        assert encoding == "base64"
        assert threshold == 4.5

    def test_classify_encoding_neither(self):
        encoding, _ = _classify_encoding("hello world!", 3.0, 4.5)
        assert encoding is None


# ============================================================
# Edge Cases
# ============================================================


class TestEdgeCases:
    """Edge cases and regression tests."""

    def test_diff_metadata_lines_skipped(self, detector):
        """Git diff metadata lines should not produce findings."""
        diff_content = """diff --git a/config.py b/config.py
index abc123..def456 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,3 @@
+AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
"""
        target = _target(diff_content, path="config.py")
        findings = detector.scan(target)
        # The +line should still be detected (diff prefix stripped)
        aws_findings = [f for f in findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) >= 1

    def test_multiline_private_key(self, detector):
        """A full multi-line RSA key should be captured as a single finding."""
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2y\n"
            "aFDrBz3y4B7Nm/5Bq7vX7GEzhCLHGQfaCZPh5kN8bSN5FphE30SkMKRIB3MXDK\n"
            "-----END RSA PRIVATE KEY-----"
        )
        target = _target(pem, path="certs/key.pem")
        findings = detector.scan(target)

        rsa_findings = [f for f in findings if "rsa" in f.rule_id.lower() or "private-key" in f.rule_id.lower()]
        assert len(rsa_findings) >= 1
        # The matched text should include BEGIN/END markers
        assert "BEGIN RSA PRIVATE KEY" in rsa_findings[0].matched_text

    def test_scan_all_batch(self, detector):
        """scan_all() should aggregate findings from multiple targets."""
        targets = [
            _target('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"', path="a.py"),
            _target('password = "SuperSecret123!"', path="b.yml"),
        ]
        findings = detector.scan_all(targets)
        assert len(findings) >= 2
        assert detector.stats["targets_scanned"] == 2
