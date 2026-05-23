"""
GitSentinel — Automated Secrets Detection & Credential Rotation.

A defensive security tool for scanning Git repositories for leaked
secrets, scoring them by severity, validating credential liveness,
and triggering automated rotation workflows.

MITRE ATT&CK: T1552.001 — Credentials In Files
Architecture: Cloud-Native / Hybrid

Usage:
    python -m scanner.cli scan ./repo
    python -m scanner.cli validate ./repo
    python -m scanner.cli rotate ./repo --auto
"""

__version__ = "1.0.0"
__author__ = "Team GitSentinel"
