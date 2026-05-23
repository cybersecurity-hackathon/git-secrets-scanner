"""
Configuration and allowlists for GitSentinel.

Centralises all tuneable parameters so the scanner can be
customised without modifying detection logic.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ============================================================
# Default Configuration
# ============================================================

# LocalStack endpoint for AWS simulation
DEFAULT_LOCALSTACK_ENDPOINT = "http://localhost:4566"

# AWS region for LocalStack
DEFAULT_AWS_REGION = "us-east-1"

# Dummy AWS credentials for LocalStack (LocalStack accepts anything)
DEFAULT_AWS_ACCESS_KEY = "test"
DEFAULT_AWS_SECRET_KEY = "test"

# File size limit — skip files larger than this (in bytes)
MAX_FILE_SIZE = 1_000_000  # 1 MB

# Maximum commits to scan in history (0 = unlimited)
MAX_COMMITS = 0

# File extensions to skip during scanning (binary files, etc.)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".o", ".obj",
    ".woff", ".woff2", ".ttf", ".eot",
    ".sqlite", ".db",
    ".lock",  # Package lockfiles generate false positives
}

# Directories to skip
SKIP_DIRECTORIES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "*.egg-info", ".next", ".nuxt",
}

# Files to skip
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    "Pipfile.lock", "Cargo.lock", "go.sum",
    "composer.lock", "Gemfile.lock",
}


@dataclass
class AllowlistEntry:
    """A single allowlist rule to suppress a known false positive."""
    reason: str             # Why this is allowlisted
    rule_id: str = ""       # Specific rule to suppress (empty = all rules)
    file_path: str = ""     # Specific file (empty = all files)
    pattern: str = ""       # Specific value pattern to ignore (regex)


@dataclass
class ScanConfig:
    """
    Complete scanner configuration.

    Can be loaded from a .gitsentinel.json file in the repo root,
    or constructed programmatically.
    """
    # --- Detection ---
    enable_pattern_matching: bool = True
    enable_entropy_analysis: bool = True
    entropy_hex_threshold: float = 3.0
    entropy_base64_threshold: float = 4.5
    min_token_length: int = 16

    # --- Scanning scope ---
    scan_working_tree: bool = True
    scan_history: bool = True
    scan_all_branches: bool = True
    max_commits: int = MAX_COMMITS
    max_file_size: int = MAX_FILE_SIZE
    skip_extensions: set[str] = field(default_factory=lambda: set(SKIP_EXTENSIONS))
    skip_directories: set[str] = field(default_factory=lambda: set(SKIP_DIRECTORIES))
    skip_files: set[str] = field(default_factory=lambda: set(SKIP_FILES))

    # --- Severity ---
    min_severity: str = "LOW"  # Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW

    # --- Validation ---
    enable_validation: bool = True
    localstack_endpoint: str = DEFAULT_LOCALSTACK_ENDPOINT
    aws_region: str = DEFAULT_AWS_REGION
    aws_access_key: str = DEFAULT_AWS_ACCESS_KEY
    aws_secret_key: str = DEFAULT_AWS_SECRET_KEY

    # --- Rotation ---
    enable_rotation: bool = False    # Disabled by default for safety
    rotation_dry_run: bool = True    # Default to dry-run mode
    rotation_iam_user: str = "leaked-key-user"  # IAM user for LocalStack demo

    # --- Output ---
    output_format: str = "table"     # table, json, html
    output_file: str = ""            # Write report to file (empty = stdout)
    redact_secrets: bool = True      # Mask secret values in output
    colorize: bool = True            # Use ANSI colors in CLI output

    # --- Allowlist ---
    allowlist: list[AllowlistEntry] = field(default_factory=list)

    @classmethod
    def from_file(cls, config_path: str | Path) -> "ScanConfig":
        """
        Load configuration from a JSON file.

        Expected format:
        {
            "scan_history": true,
            "max_commits": 100,
            "min_severity": "MEDIUM",
            "allowlist": [
                {"reason": "Test key", "file_path": "tests/", "rule_id": "aws-access-key-id"}
            ]
        }
        """
        config_path = Path(config_path)
        if not config_path.exists():
            return cls()

        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Parse allowlist entries
        allowlist = []
        for entry_data in data.pop("allowlist", []):
            allowlist.append(AllowlistEntry(**entry_data))

        # Convert skip sets from lists
        if "skip_extensions" in data:
            data["skip_extensions"] = set(data["skip_extensions"])
        if "skip_directories" in data:
            data["skip_directories"] = set(data["skip_directories"])
        if "skip_files" in data:
            data["skip_files"] = set(data["skip_files"])

        return cls(allowlist=allowlist, **data)

    @classmethod
    def load_from_repo(cls, repo_path: str | Path) -> "ScanConfig":
        """
        Look for a .gitsentinel.json config file in the repository root.

        Falls back to default configuration if no config file is found.
        """
        config_file = Path(repo_path) / ".gitsentinel.json"
        if config_file.exists():
            return cls.from_file(config_file)
        return cls()

    def should_skip_file(self, file_path: str) -> bool:
        """Check if a file should be skipped based on configuration."""
        basename = os.path.basename(file_path)
        _, ext = os.path.splitext(file_path)

        # Skip by extension
        if ext.lower() in self.skip_extensions:
            return True

        # Skip by filename
        if basename in self.skip_files:
            return True

        # Skip by directory
        parts = Path(file_path).parts
        for skip_dir in self.skip_directories:
            if skip_dir in parts:
                return True

        return False

    def is_allowlisted(self, rule_id: str, file_path: str, matched_content: str) -> bool:
        """
        Check if a finding should be suppressed by the allowlist.

        Args:
            rule_id: The detection rule that fired.
            file_path: The file containing the finding.
            matched_content: The matched secret value.

        Returns:
            True if the finding matches an allowlist entry.
        """
        import re as re_module

        for entry in self.allowlist:
            # Check rule_id filter
            if entry.rule_id and entry.rule_id != rule_id:
                continue

            # Check file_path filter
            if entry.file_path and not file_path.startswith(entry.file_path):
                continue

            # Check pattern filter
            if entry.pattern:
                try:
                    if not re_module.search(entry.pattern, matched_content):
                        continue
                except re_module.error:
                    continue

            # All filters matched — this finding is allowlisted
            return True

        return False
