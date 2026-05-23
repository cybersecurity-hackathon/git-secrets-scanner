"""AWS Configuration — DO NOT COMMIT TO VERSION CONTROL

This file intentionally contains fake AWS credentials for testing
the GitSentinel secrets detection scanner.

WARNING: All credentials in this file are fake and non-functional.
         They follow realistic AWS key formats but cannot authenticate
         to any real AWS service.
"""

import os

# AWS Credentials (should use environment variables or IAM roles)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_DEFAULT_REGION = "us-east-1"

# S3 bucket for uploads
S3_BUCKET_NAME = "production-user-uploads"
S3_ENDPOINT = f"https://s3.{AWS_DEFAULT_REGION}.amazonaws.com"

# Secondary account credentials (for cross-account access)
AWS_SECONDARY_ACCESS_KEY = "AKIAI44QH8DHBEXAMPLE"
AWS_SECONDARY_SECRET_KEY = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"

# AWS Session Token (for temporary credentials via STS)
AWS_SESSION_TOKEN = "FwoGZXIvYXdzEBYaDHqa0AP9RRkFHxCOgyLIAR4acYjY+DEm5fMHsuDXvEXAMPLE/SESSION/TOKEN/THAT/IS/LONG/ENOUGH/TO/MATCH+PATTERN+RULES/1234567890abcdef"
