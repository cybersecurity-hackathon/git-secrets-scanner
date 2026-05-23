"""ANALYSER: Pattern matching + Shannon entropy detection engine.

The Detector is the second stage of the Sensor → Analyser → Responder pipeline.
It receives ``ScanTarget`` objects from the Collector and produces ``Finding``
objects for any detected secrets.

Two complementary detection techniques are applied:

1. **Regex Pattern Matching** — using the rules defined in ``patterns.py``.
   High-precision but only catches known secret formats.
2. **Shannon Entropy Analysis** — flags high-entropy strings that look like
   random tokens even if they don't match a known pattern.
   Higher recall but noisier — controlled by contextual heuristics.

A deduplication layer ensures the same secret (same matched text + same file)
is only reported once, even if it appears in both the working tree and a
historical commit.

Usage::

    from scanner.detector import Detector

    detector = Detector()
    findings = detector.scan(scan_target)     # single target
    findings = detector.scan_all(targets)     # batch
"""

from __future__ import annotations

import logging
import math
import os
import re
import string
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    DetectionMethod,
    Finding,
    ScanSource,
    ScanTarget,
    SecretType,
    Severity,
)
from .patterns import SECRET_PATTERNS, SecretPattern

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Entropy thresholds and constants
# ---------------------------------------------------------------------------

# Shannon entropy thresholds (bits per character).
# These are calibrated to minimise false positives while still catching
# high-entropy tokens that don't match known patterns.
HEX_ENTROPY_THRESHOLD: float = 3.0
BASE64_ENTROPY_THRESHOLD: float = 4.5

# Minimum token length to consider for entropy analysis.
# Shorter tokens (UUIDs, short hashes) produce too many false positives.
MIN_ENTROPY_TOKEN_LENGTH: int = 16

# Maximum token length — very long strings are likely encoded data, not secrets.
MAX_ENTROPY_TOKEN_LENGTH: int = 256

# Character sets for classifying token encoding
HEX_CHARS = set(string.hexdigits)
BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=")

# Variable-name context keywords that raise confidence when nearby
SUSPICIOUS_VAR_NAMES = {
    "secret", "key", "token", "password", "passwd", "pwd", "credential",
    "auth", "api_key", "apikey", "api_secret", "access_key", "private_key",
    "signing_key", "jwt_secret", "bearer", "authorization",
}

# File extensions that are more likely to contain secrets (config files)
HIGH_RISK_EXTENSIONS = {
    ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".xml", ".config", ".secret", ".pem", ".key",
}

# Lines/content to skip entirely (too noisy)
ENTROPY_SKIP_PATTERNS = [
    re.compile(r"^\s*(?://|#|/\*|\*)\s"),       # Comments
    re.compile(r"^\s*$"),                         # Empty lines
    re.compile(r"integrity.*sha\d+-"),            # NPM lockfile hashes
    re.compile(r"sha256-[A-Za-z0-9+/=]{40,}"),   # Known hash patterns
    re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I),  # UUIDs
]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class Detector:
    """Secret detection engine combining regex patterns and entropy analysis.

    Parameters
    ----------
    enable_entropy : bool
        Whether to run Shannon entropy analysis in addition to patterns.
    entropy_threshold_hex : float
        Override the default hex entropy threshold.
    entropy_threshold_base64 : float
        Override the default base64 entropy threshold.
    allowlist : set[str] | None
        Set of exact strings to suppress (e.g. known test values, placeholder
        constants).
    allowlist_paths : set[str] | None
        Set of glob-style path patterns to exclude from scanning.
    """

    def __init__(
        self,
        enable_entropy: bool = True,
        entropy_threshold_hex: float = HEX_ENTROPY_THRESHOLD,
        entropy_threshold_base64: float = BASE64_ENTROPY_THRESHOLD,
        allowlist: Optional[Set[str]] = None,
        allowlist_paths: Optional[Set[str]] = None,
    ) -> None:
        self.enable_entropy = enable_entropy
        self.entropy_threshold_hex = entropy_threshold_hex
        self.entropy_threshold_base64 = entropy_threshold_base64
        self.allowlist = allowlist or set()
        self.allowlist_paths = allowlist_paths or set()

        # Dedup tracker: (rule_id_or_method, matched_text, file_path) → bool
        self._seen: Set[Tuple[str, str, str]] = set()

        # Statistics
        self.stats = {
            "targets_scanned": 0,
            "lines_scanned": 0,
            "pattern_matches": 0,
            "entropy_matches": 0,
            "duplicates_suppressed": 0,
            "allowlisted": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target: ScanTarget) -> List[Finding]:
        """Scan a single ``ScanTarget`` and return all findings.

        Parameters
        ----------
        target : ScanTarget
            A content unit from the Collector.

        Returns
        -------
        list[Finding]
            Zero or more detected secrets.
        """
        if self._is_path_allowlisted(target.file_path):
            return []

        self.stats["targets_scanned"] += 1
        findings: List[Finding] = []

        # --- 1. Regex pattern matching ---
        findings.extend(self._scan_patterns(target))

        # --- 2. Shannon entropy analysis ---
        if self.enable_entropy:
            findings.extend(self._scan_entropy(target))

        return findings

    def scan_all(self, targets) -> List[Finding]:
        """Scan an iterable of ``ScanTarget`` objects.

        Parameters
        ----------
        targets : Iterable[ScanTarget]
            Typically the generator returned by ``Collector.collect()``.

        Returns
        -------
        list[Finding]
            Aggregated findings from all targets.
        """
        all_findings: List[Finding] = []
        for target in targets:
            all_findings.extend(self.scan(target))
        return all_findings

    def reset(self) -> None:
        """Reset deduplication state and statistics (for re-scanning)."""
        self._seen.clear()
        self.stats = {k: 0 for k in self.stats}

    # ------------------------------------------------------------------
    # Private: Regex pattern scanning
    # ------------------------------------------------------------------

    def _scan_patterns(self, target: ScanTarget) -> List[Finding]:
        """Apply all regex patterns against every line of content."""
        findings: List[Finding] = []
        lines = target.content.splitlines()

        for line_num_0, line in enumerate(lines, start=1):
            self.stats["lines_scanned"] += 1

            # Skip diff metadata lines (e.g. "+++ a/file", "--- b/file")
            stripped = line.lstrip()
            if stripped.startswith(("diff --git", "index ", "--- ", "+++ ", "@@ ")):
                continue

            # Strip diff prefix ("+", "-") for matching but keep original
            clean_line = line
            if stripped.startswith(("+", "-")) and not stripped.startswith(("++", "--")):
                clean_line = stripped[1:]

            for pattern_def in SECRET_PATTERNS:
                match = pattern_def.pattern.search(clean_line)
                if not match:
                    # Also try on full original line
                    match = pattern_def.pattern.search(line)
                if not match:
                    continue

                # Extract the matched secret value
                # Prefer the first capturing group; fall back to full match
                matched_text = match.group(1) if match.lastindex else match.group(0)
                matched_text = matched_text.strip().strip("'\"")

                if not matched_text or len(matched_text) < 4:
                    continue

                # Allowlist check
                if matched_text in self.allowlist:
                    self.stats["allowlisted"] += 1
                    continue

                # Dedup check
                dedup_key = (pattern_def.id, matched_text, target.file_path)
                if dedup_key in self._seen:
                    self.stats["duplicates_suppressed"] += 1
                    continue
                self._seen.add(dedup_key)

                self.stats["pattern_matches"] += 1

                # Calculate entropy for informational purposes
                entropy = _shannon_entropy(matched_text)

                findings.append(Finding(
                    rule_id=pattern_def.id,
                    rule_name=pattern_def.name,
                    secret_type=pattern_def.secret_type,
                    severity=pattern_def.severity,
                    base_severity=pattern_def.severity,
                    file_path=target.file_path,
                    line_number=line_num_0,
                    line_content=line.rstrip(),
                    matched_text=matched_text,
                    commit_sha=target.commit_sha,
                    commit_date=target.commit_date,
                    author=target.author,
                    branch=target.branch,
                    source=target.source,
                    detection_method=DetectionMethod.PATTERN,
                    entropy_score=entropy,
                ))

        # --- Multiline Pattern Pass ---
        # Some patterns (like PEM private keys) span multiple lines and won't be caught
        # by the line-by-line loop above. We scan the full content for them here.
        for pattern_def in SECRET_PATTERNS:
            if "PRIVATE KEY" in pattern_def.pattern.pattern or "PGP" in pattern_def.pattern.pattern:
                for match in pattern_def.pattern.finditer(target.content):
                    matched_text = match.group(1) if match.lastindex else match.group(0)
                    matched_text = matched_text.strip().strip("'\"")

                    if not matched_text or len(matched_text) < 4:
                        continue

                    if matched_text in self.allowlist:
                        self.stats["allowlisted"] += 1
                        continue

                    dedup_key = (pattern_def.id, matched_text, target.file_path)
                    if dedup_key in self._seen:
                        self.stats["duplicates_suppressed"] += 1
                        continue
                    self._seen.add(dedup_key)

                    self.stats["pattern_matches"] += 1
                    line_num_0 = target.content[:match.start()].count('\n') + 1
                    line_content = matched_text.splitlines()[0] if matched_text else ""

                    findings.append(Finding(
                        rule_id=pattern_def.id,
                        rule_name=pattern_def.name,
                        secret_type=pattern_def.secret_type,
                        severity=pattern_def.severity,
                        base_severity=pattern_def.severity,
                        file_path=target.file_path,
                        line_number=line_num_0,
                        line_content=line_content,
                        matched_text=matched_text,
                        commit_sha=target.commit_sha,
                        commit_date=target.commit_date,
                        author=target.author,
                        branch=target.branch,
                        source=target.source,
                        detection_method=DetectionMethod.PATTERN,
                        entropy_score=_shannon_entropy(matched_text),
                    ))

        return findings

    # ------------------------------------------------------------------
    # Private: Entropy-based scanning
    # ------------------------------------------------------------------

    def _scan_entropy(self, target: ScanTarget) -> List[Finding]:
        """Flag high-entropy tokens that weren't caught by pattern rules."""
        findings: List[Finding] = []
        lines = target.content.splitlines()

        _, ext = os.path.splitext(target.file_path)
        is_config_file = ext.lower() in HIGH_RISK_EXTENSIONS

        for line_num_0, line in enumerate(lines, start=1):
            # Skip lines that are known to produce false positives
            if any(sp.search(line) for sp in ENTROPY_SKIP_PATTERNS):
                continue

            # Tokenise the line on whitespace, assignment operators, and quotes
            tokens = _tokenise_line(line)

            for token in tokens:
                if len(token) < MIN_ENTROPY_TOKEN_LENGTH:
                    continue
                if len(token) > MAX_ENTROPY_TOKEN_LENGTH:
                    continue

                # Determine encoding type
                encoding, threshold = _classify_encoding(
                    token,
                    self.entropy_threshold_hex,
                    self.entropy_threshold_base64,
                )
                if encoding is None:
                    continue  # Not hex or base64 — skip

                entropy = _shannon_entropy(token)
                if entropy < threshold:
                    continue

                # Contextual heuristics — boost or suppress
                has_suspicious_context = _has_suspicious_context(line)
                if not is_config_file and not has_suspicious_context:
                    # Only flag non-config files if the variable name is suspicious
                    continue

                # Dedup against pattern matches (don't double-report)
                dedup_key = ("entropy", token, target.file_path)
                if dedup_key in self._seen:
                    self.stats["duplicates_suppressed"] += 1
                    continue

                # Also check if this token was already caught by a regex rule
                already_caught = any(
                    (pid, token, target.file_path) in self._seen
                    for pid in [p.id for p in SECRET_PATTERNS]
                )
                if already_caught:
                    continue

                self._seen.add(dedup_key)
                self.stats["entropy_matches"] += 1

                # Assign severity based on context
                severity = Severity.MEDIUM
                if has_suspicious_context and is_config_file:
                    severity = Severity.HIGH
                elif has_suspicious_context:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                findings.append(Finding(
                    rule_id="entropy-detection",
                    rule_name=f"High-Entropy {encoding.title()} String",
                    secret_type=SecretType.GENERIC,
                    severity=severity,
                    base_severity=severity,
                    file_path=target.file_path,
                    line_number=line_num_0,
                    line_content=line.rstrip(),
                    matched_text=token,
                    commit_sha=target.commit_sha,
                    commit_date=target.commit_date,
                    author=target.author,
                    branch=target.branch,
                    source=target.source,
                    detection_method=DetectionMethod.ENTROPY,
                    entropy_score=entropy,
                ))

        return findings

    # ------------------------------------------------------------------
    # Private: Allowlist path matching
    # ------------------------------------------------------------------

    def _is_path_allowlisted(self, file_path: str) -> bool:
        """Check if the file path matches any allowlist pattern."""
        import fnmatch
        for pattern in self.allowlist_paths:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False


# ---------------------------------------------------------------------------
# Entropy utilities (module-level for reuse / testing)
# ---------------------------------------------------------------------------

def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character.

    Higher entropy ≈ more random ≈ more likely to be a secret.
    Typical values:
    - English text: ~3.5–4.0 bits
    - Hex-encoded random bytes: ~3.7–4.0 bits
    - Base64-encoded random bytes: ~5.5–6.0 bits
    - Truly random ASCII: ~6.5+ bits

    Parameters
    ----------
    data : str
        The string to analyse.

    Returns
    -------
    float
        Shannon entropy in bits per character.  Returns ``0.0`` for
        empty strings.
    """
    if not data:
        return 0.0

    length = len(data)
    freq = Counter(data)
    entropy = 0.0

    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def _tokenise_line(line: str) -> List[str]:
    """Split a line into candidate tokens for entropy analysis.

    Splits on whitespace, quotes, assignment operators (``=``, ``:``, ``=>``),
    and common delimiters.  Returns only tokens that look like potential
    secret values (alphanumeric + base64/hex chars).
    """
    # Split on common delimiters
    parts = re.split(r'[\s=:,;{}\[\]()"\']', line)

    tokens = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # Keep only tokens that are predominantly alphanumeric + base64 chars
        if re.match(r'^[A-Za-z0-9+/=\-_]+$', part):
            tokens.append(part)

    return tokens


def _classify_encoding(
    token: str,
    hex_threshold: float,
    base64_threshold: float,
) -> Tuple[Optional[str], float]:
    """Classify a token as hex, base64, or neither.

    Returns
    -------
    tuple[str | None, float]
        ``("hex", threshold)`` or ``("base64", threshold)`` or ``(None, 0.0)``.
    """
    token_chars = set(token)

    # Check if it's hex (0-9, a-f, A-F)
    if token_chars.issubset(HEX_CHARS):
        return ("hex", hex_threshold)

    # Check if it's base64 (alphanumeric + /+=)
    if token_chars.issubset(BASE64_CHARS):
        return ("base64", base64_threshold)

    # Extended base64 (with - and _ for URL-safe base64)
    extended_b64 = BASE64_CHARS | {"-", "_"}
    if token_chars.issubset(extended_b64):
        return ("base64", base64_threshold)

    return (None, 0.0)


def _has_suspicious_context(line: str) -> bool:
    """Check if a line contains variable names suggestive of secrets."""
    line_lower = line.lower()
    return any(keyword in line_lower for keyword in SUSPICIOUS_VAR_NAMES)
