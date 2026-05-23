"""
GitSentinel — Automated Secrets Detection & Credential Rotation.

A defensive security tool for scanning Git repositories for leaked
secrets, scoring them by severity, validating credential liveness,
and triggering automated rotation workflows.

MITRE ATT&CK: T1552.001 — Credentials In Files
Architecture: Cloud-Native / Hybrid

Core scanner package implementing the Sensor -> Analyser -> Responder pipeline.

Modules
-------
models      Shared dataclasses (ScanTarget, Finding, SecretPattern, etc.)
patterns    Regex-based secret detection rules (gitleaks / truffleHog inspired)
collector   Git repository traversal (Sensor stage)
detector    Pattern matching + entropy analysis engine (Analyser stage)
cli         Command-line interface entry point

Teammate modules (stubs until implemented):
    entropy     Shannon entropy calculator (extended)
    scorer      Severity scoring engine
    validator   Credential liveness checker
    rotator     Automated rotation workflow (Responder stage)
    reporter    Report generation (JSON, HTML, CLI)
    config      Configuration & allowlists

Usage:
    python -m scanner.cli scan ./repo
    python -m scanner.cli validate ./repo
    python -m scanner.cli rotate ./repo --auto
"""

__version__ = "1.0.0"
__author__ = "Team GitSentinel"
