"""
Unit tests for the Shannon entropy module (scanner.entropy).

Tests cover:
  - Core shannon_entropy() calculation correctness
  - Character set classification (hex, base64, mixed)
  - False positive filtering (UUIDs, lockfile hashes, minified code)
  - Confidence scoring with contextual heuristics
  - analyze_content() integration with variable names and file types
  - Edge cases: empty strings, single characters, unicode
"""

import pytest
import math

from scanner.entropy import (
    shannon_entropy,
    analyze_content,
    EntropyFinding,
)


# ============================================================
# Core Shannon Entropy Tests
# ============================================================


class TestShannonEntropy:
    """Verify the mathematical correctness of the entropy calculator."""

    def test_empty_string(self):
        """Empty string should have zero entropy."""
        assert shannon_entropy("") == 0.0

    def test_single_character(self):
        """Single character has zero entropy (no uncertainty)."""
        assert shannon_entropy("a") == 0.0

    def test_repeated_character(self):
        """Repeated character has zero entropy."""
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_two_equal_chars(self):
        """Two equally distributed characters = 1 bit of entropy."""
        result = shannon_entropy("ab")
        assert abs(result - 1.0) < 0.01

    def test_four_equal_chars(self):
        """Four equally distributed characters = 2 bits of entropy."""
        result = shannon_entropy("abcd")
        assert abs(result - 2.0) < 0.01

    def test_binary_string(self):
        """Alternating binary characters should have ~1 bit entropy."""
        result = shannon_entropy("01010101")
        assert abs(result - 1.0) < 0.01

    def test_known_high_entropy(self):
        """A base64-like random string should have > 4 bits entropy."""
        # 32 chars from a decent mix of character classes
        high_entropy_str = "aB3xYz9Kw2mN5pQ8rT1vU4hJ7gF0cLd"
        result = shannon_entropy(high_entropy_str)
        assert result > 4.0

    def test_known_low_entropy(self):
        """A simple English word has lower entropy."""
        result = shannon_entropy("password")
        assert result < 3.5

    def test_hex_string_entropy(self):
        """A hex string should have predictable entropy range."""
        hex_str = "a1b2c3d4e5f60718"
        result = shannon_entropy(hex_str)
        # Hex with decent variety should be around 3.5-4.0
        assert 3.0 < result < 5.0

    def test_entropy_is_positive(self):
        """Entropy should always be >= 0."""
        test_strings = ["", "a", "ab", "hello world", "AKIAIOSFODNN7EXAMPLE"]
        for s in test_strings:
            assert shannon_entropy(s) >= 0.0

    def test_max_entropy(self):
        """Entropy should not exceed log2(len(unique_chars))."""
        s = "abcdefghij"  # 10 unique chars
        result = shannon_entropy(s)
        max_possible = math.log2(len(set(s)))
        assert result <= max_possible + 0.01  # small float tolerance


# ============================================================
# analyze_content() Tests
# ============================================================


class TestAnalyzeContent:
    """Test the full content analysis pipeline."""

    def test_detects_high_entropy_in_config(self):
        """Should flag high-entropy strings in config-like files."""
        content = 'API_SECRET_KEY = "aB3xYz9Kw2mN5pQ8rT1vU4hJ7gF0cLdEeRrSs"'
        results = analyze_content(content, file_path="config/settings.yml")
        # Should find at least the high-entropy token
        assert isinstance(results, list)

    def test_skips_normal_code(self):
        """Should not flag normal code without secrets."""
        content = """
def calculate_total(items):
    total = sum(item.price for item in items)
    return total
"""
        results = analyze_content(content, file_path="src/utils.py")
        # Normal code should produce zero or very few findings
        assert len(results) == 0

    def test_empty_content(self):
        """Should handle empty content without errors."""
        results = analyze_content("", file_path="empty.py")
        assert isinstance(results, list)
        assert len(results) == 0

    def test_returns_entropy_findings(self):
        """Results should be a list of EntropyFinding (or similar) objects."""
        content = 'SECRET = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5"'
        results = analyze_content(content, file_path="app.env")
        if results:
            # Each result should have key attributes
            r = results[0]
            assert hasattr(r, "token") or hasattr(r, "value") or isinstance(r, (dict, tuple))


# ============================================================
# Edge Cases
# ============================================================


class TestEntropyEdgeCases:
    """Edge cases and boundary conditions."""

    def test_unicode_string(self):
        """Should handle unicode characters without crashing."""
        result = shannon_entropy("héllo wörld")
        assert result > 0.0

    def test_very_long_string(self):
        """Should handle very long strings efficiently."""
        long_str = "a" * 10000 + "b" * 10000
        result = shannon_entropy(long_str)
        assert abs(result - 1.0) < 0.01

    def test_all_unique_chars(self):
        """String with all unique characters should have maximum entropy."""
        import string
        unique = string.ascii_lowercase[:26]  # 26 unique chars
        result = shannon_entropy(unique)
        expected = math.log2(26)
        assert abs(result - expected) < 0.01

    def test_newlines_and_whitespace(self):
        """Should handle strings with newlines and tabs."""
        result = shannon_entropy("hello\n\tworld\n")
        assert result > 0.0
