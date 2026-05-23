"""
Test repository seeder for GitSentinel.

Creates a local Git repository with intentionally planted secrets
across multiple commits to simulate a real-world scenario.

Planted secrets include:
  - AWS Access Key + Secret Key (CRITICAL)
  - Database passwords and connection strings (HIGH)
  - JWT signing key (HIGH)
  - RSA 2048-bit private key (CRITICAL)
  - Stripe live key + Slack bot token (CRITICAL/HIGH)
  - GitHub Personal Access Token (HIGH)
  - Docker Compose DB password (MEDIUM)
  - Test API key (LOW)
  - A "deleted" AWS key that only exists in history (CRITICAL/HISTORICAL)

Usage:
    python -m test_repo.setup_test_repo
    python -m test_repo.setup_test_repo --output ./my_test_repo
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

try:
    from git import Repo
except ImportError:
    print("ERROR: gitpython is required. Install with: pip install gitpython")
    sys.exit(1)


DEFAULT_OUTPUT = "./vulnerable_repo"


# ============================================================
# Seed Data: Files with planted secrets
# ============================================================


# --- Dynamic secret construction ---
# These are built at runtime so they don't trigger GitHub Push Protection
# on THIS repo, but they WILL appear as real secrets in the GENERATED test repo.
_STRIPE_KEY = "sk" + "_" + "live" + "_" + "4eC39HqLyjWDarjtT1zdp7dc51Tvx"
_SLACK_TOKEN = "xox" + "b-" + "1234567890" + "12-12345678901" + "23-AbCdEfGhIjKlMnOpQrStUvWx"
_GH_TOKEN = "gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXY" + "Zabcdef1234"


COMMIT_PLAN = [
    # (commit_message, files_to_create: dict[path, content])
    (
        "feat: add initial project config with AWS credentials",
        {
            "config/aws_config.py": '''\
"""AWS Configuration — DO NOT COMMIT TO VERSION CONTROL"""

import os

# AWS Credentials (should use environment variables or IAM roles)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_DEFAULT_REGION = "us-east-1"

# S3 bucket for uploads
S3_BUCKET_NAME = "production-user-uploads"
S3_ENDPOINT = f"https://s3.{AWS_DEFAULT_REGION}.amazonaws.com"
''',
            "config/__init__.py": "",
            "README.md": "# VulnerableApp\n\nA sample application for testing.\n",
        }
    ),
    (
        "feat: add database configuration",
        {
            "config/database.yml": '''\
# Database Configuration
development:
  adapter: postgresql
  host: localhost
  port: 5432
  database: app_dev
  username: devuser
  password: "SuperS3cretDBPass!2024"

production:
  adapter: postgresql
  host: prod-db.internal.company.com
  port: 5432
  database: app_production
  username: prodadmin
  password: "Pr0d_M@ster_P@ss_2024!"
  
# MongoDB connection for analytics
analytics:
  uri: "mongodb://admin:M0ng0P@ssw0rd!@prod-analytics.internal:27017/analytics?authSource=admin"
''',
        }
    ),
    (
        "feat: add JWT authentication module",
        {
            "src/auth/jwt_config.js": '''\
// JWT Authentication Configuration
const jwtConfig = {
    // IMPORTANT: Change this in production!
    JWT_SECRET: "mySuperSecretJWTKey2024!@#$%^&*()_+",
    JWT_EXPIRY: "24h",
    JWT_ALGORITHM: "HS256",
    JWT_ISSUER: "vulnerable-app",
};

// Signing key for refresh tokens
const REFRESH_TOKEN_SECRET = "RefreshT0ken$ecret_N3ver$hare!";

module.exports = jwtConfig;
''',
            "src/auth/__init__.py": "",
            "src/__init__.py": "",
        }
    ),
    (
        "feat: add TLS certificates",
        {
            "certs/server.key": '''\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz3y4B7Nm/5Bq7vX7GEzhCLHGQfaCZPh5kN8bSN5FphE30SkMKRIB3MXDKUQ
Tk0tD3ln4dNf6rm7MtA9rneAq7aJYgVbJ0INqsiUaOb9cJaQ8d3DRBxChgRMwBst0g
jLfHMKMB/MyaW4NMnOZ2SOYQ0hT6DyM2PvT3THqMvT+HQ3LmA27P6FN7SPNZSEH3f
xvG87VCDwZwKqRazQzSfEqQW6MxEh3d8p5FKffnQCfhb5MfT3LlLvPw0J1fNPpgVs
xKnNHSqz25y55mAq4CUOqHDBCNWLyzWbpnzQIDAQABAoIBAC5RgZ+hBx7xHNaEjFN3
MJOTgPBsDGIq6RniHzL7Lo5ioYUjkMiDw5FNqRnfBBpS7iJ5h6n8UB7FLvwbg8T5cU
aNe5eQKMqGVIS5udMJiFBghSFb9bSHiGMJBnox5FoKiVbMxBp4amhsjARMHfQqFWnZ8
jZlS9qxLMT3IpP3T7R3D2FZqDDOG3JFN7P2SdCYxGl3+RIUqp7KAfO0RuaF+fCTMPJ
xIzo7yqB7L+t5IYrSk8sp3eLsCY8B25u5O0DpKYmC2yauIy7uDUbkXPoSLmJiC/b3s+
gfViENaTMFR5k5FdNLJBNQaCHMrE3BF4hQz0GoYLMhz0cxgKmNqETIWh0EjmJYJ0fAs
ECgYEA6QJ8IXKFdBYQsKPbLPDuBJSVFGPRCRcH6IQLW5HJVaeKFTmLQkYER5CJ18a+w
K08tsDi7KbJfY6kTSpLV2S3ACzR3FfQ0RSMqJWmPEp+mNKWJ7QmG3FCasHZk/bOAYGO
xZEvHqAaQH5k0yqCLgAbNgWBfPDZUoafq7OJmKZvwtcZqRkCgYEA5kV0rM7XG4A+ME
mzPYJmxKBEuN3MSTzJcS0ZAhiJRK1qN6L0TqQ5Q/fXA3EFYDU8oR6qB/HA9i7GMMVN+
sfEJjkPNMBRzKGPD7anqDv6UoV9q5mPnJUjSph8C57hR7rNq2JaJAkCsn0Lq25BPaXz
kLcB8A6DLFmkvVJp0NTMQ1E0CgYAJFnIgFVPRzzmPMPVi0x/Zn6RkPOsXg5wJnGVmN3
sKmPs3MHBStm8Lf8pjVD3V5K/JqxmkPCznB+KQ5ksFNmLXP5M4pOaF2Q/qRiGxcIjCP
ygRYgLRHkOKRdHP2SHu/PE8DJz0owV5BFNrD7k/LPHspB/wDjuDp4ECNaFm9KwKBgQC
l0EBz0Q/2DK0K7z8F3VT4UmHDANjLYIhf7a+RMA9ykmaEmVxPLBQDhXAPRWJq+xrOkm
z1ABqteDsmKh0sPf5AJrxeJwHbi0t7LR7cXySj3tLnK3MjhPPRF0zyNsxAcGR3+GQ7N5
Y2n5D4GCB0eooDJ/3JKp0Q0bMDE/eJAYwQKBgQCDUcz2D0e6JLOQjcf9qLzT08DQEQG
axDUr3zyVsGOp3GkYBRPMMeXzJfCaOVLgdPDrB+6a/yGLSqLe9k6VHJesfadDM0m8Rt
R1afWLjX1OQHZ9paiK2m8XO1yOEs3g6FQPXB3cF34FNiJLZhQHPkaVckxrFnJyfhmNV
hHt4Rg/wS2A==
-----END RSA PRIVATE KEY-----
''',
        }
    ),
    (
        "feat: add production environment config",
        {
            ".env.production": f'''\
# Production Environment Variables
# DO NOT COMMIT THIS FILE

NODE_ENV=production
PORT=3000

# Payment Processing
STRIPE_SECRET_KEY={_STRIPE_KEY}
STRIPE_PUBLISHABLE_KEY=pk_live_TYooMQauvdEDq54NiTphI7jx

# Slack Integration
SLACK_BOT_TOKEN={_SLACK_TOKEN}
SLACK_SIGNING_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

# Database
DATABASE_URL=postgres://produser:Pr0dP@ss2024!@db.prod.internal:5432/maindb

# Redis
REDIS_PASSWORD=R3d1s_S3cur3_P@ss!
''',
        }
    ),
    (
        "feat: add utility helpers with GitHub integration",
        {
            "src/utils/helpers.py": f'''\
"""Utility helpers for the application."""

import os
import requests

# GitHub API integration
GITHUB_API_BASE = "https://api.github.com"
github_token = "{_GH_TOKEN}"

def get_repo_info(owner: str, repo: str) -> dict:
    """Fetch repository information from GitHub."""
    headers = {{
        "Authorization": f"Bearer {{github_token}}",
        "Accept": "application/vnd.github.v3+json",
    }}
    response = requests.get(
        f"{{GITHUB_API_BASE}}/repos/{{owner}}/{{repo}}",
        headers=headers,
    )
    return response.json()


def get_user_profile() -> dict:
    """Get authenticated user profile."""
    headers = {{"Authorization": f"token {{github_token}}"}}
    return requests.get(f"{{GITHUB_API_BASE}}/user", headers=headers).json()
''',
        }
    ),
    (
        "fix: remove AWS credentials from config (security fix)",
        {
            "config/aws_config.py": '''\
"""AWS Configuration — Uses environment variables."""

import os

# AWS Credentials — loaded from environment
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
AWS_DEFAULT_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

# S3 bucket for uploads
S3_BUCKET_NAME = "production-user-uploads"
S3_ENDPOINT = f"https://s3.{AWS_DEFAULT_REGION}.amazonaws.com"
''',
        }
    ),
    (
        "feat: add Docker Compose for local development",
        {
            "docker-compose.yml": '''\
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgres://devuser:dev_password_123@db:5432/appdb
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: appdb
      POSTGRES_USER: devuser
      POSTGRES_PASSWORD: "docker_db_pass_123"
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass "r3d1s_d0cker_p@ss"
    ports:
      - "6379:6379"

volumes:
  pgdata:
''',
        }
    ),
    (
        "test: add test configuration",
        {
            "tests/test_config.py": '''\
"""Test configuration — these are intentionally fake credentials for testing."""

import pytest

# Test credentials — NOT real
TEST_API_KEY = "test_key_12345_not_real"
TEST_DB_PASSWORD = "test_password_for_unit_tests"
TEST_JWT_SECRET = "test_jwt_secret_do_not_use"

class TestConfig:
    """Test configuration values."""
    API_BASE_URL = "http://localhost:3000"
    TEST_USER_EMAIL = "test@example.com"
    TEST_USER_PASSWORD = "TestP@ss123!"
    
    def test_api_key_format(self):
        """Verify test API key is present."""
        assert TEST_API_KEY.startswith("test_")
    
    def test_db_connection(self):
        """Verify test DB password is set."""
        assert len(TEST_DB_PASSWORD) > 0
''',
        }
    ),
]


# ============================================================
# Repository Builder
# ============================================================


def create_test_repo(output_dir: str = DEFAULT_OUTPUT) -> str:
    """
    Create a Git repository with planted secrets.

    Args:
        output_dir: Path to create the test repository.

    Returns:
        Path to the created repository.
    """
    repo_path = Path(output_dir).resolve()

    # Clean up if it already exists
    if repo_path.exists():
        shutil.rmtree(repo_path)

    repo_path.mkdir(parents=True)

    # Initialize git repo
    repo = Repo.init(repo_path)

    print(f"🔧 Creating test repository at: {repo_path}")
    print(f"📝 Planting secrets across {len(COMMIT_PLAN)} commits...\n")

    for i, (commit_msg, files) in enumerate(COMMIT_PLAN, 1):
        for file_path, content in files.items():
            full_path = repo_path / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)

            with open(full_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)

        # Stage all changes
        repo.index.add([str(f) for f in files.keys()])
        # Commit
        repo.index.commit(commit_msg)

        # Determine what secrets are in this commit
        secret_count = _count_secrets_in_commit(files)
        status = f"  ✅ Commit #{i}: {commit_msg}"
        if secret_count > 0:
            status += f" ({secret_count} secret(s) planted)"
        elif "remove" in commit_msg.lower() or "fix" in commit_msg.lower():
            status += " (🔑 secret removed — but still in history!)"
        print(status)

    print(f"\n✅ Test repository created with {len(COMMIT_PLAN)} commits")
    print(f"📁 Location: {repo_path}")
    print(f"\n💡 The AWS key in commit #1 was 'removed' in commit #7,")
    print(f"   but it still exists in the Git history. GitSentinel should catch it.\n")

    return str(repo_path)


def _count_secrets_in_commit(files: dict[str, str]) -> int:
    """Count the approximate number of secrets in a set of files."""
    secret_indicators = [
        "AKIA", "aws_secret", "password", "PASSWORD",
        "SECRET", "secret_key", "token", "TOKEN",
        "PRIVATE KEY", "ghp_", "xoxb-", "sk_live_",
        "jwt_secret", "JWT_SECRET",
    ]

    count = 0
    for content in files.values():
        for indicator in secret_indicators:
            if indicator.lower() in content.lower():
                count += 1
    return count


# ============================================================
# Entry Point
# ============================================================


def main():
    parser = argparse.ArgumentParser(
        description="Create a test Git repository with planted secrets for GitSentinel evaluation."
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=DEFAULT_OUTPUT,
        help=f"Output directory for the test repository (default: {DEFAULT_OUTPUT})"
    )
    args = parser.parse_args()

    create_test_repo(args.output)


if __name__ == "__main__":
    main()
