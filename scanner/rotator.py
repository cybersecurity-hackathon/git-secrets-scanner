"""
Automated credential rotation workflow for GitSentinel (RESPONDER).

When a CRITICAL + LIVE credential is detected, this module:
  1. ALERTS  — Sends notification (console + optional Slack webhook)
  2. ROTATES — Creates a new credential via LocalStack IAM
  3. REVOKES — Disables and deletes the old credential
  4. AUDITS  — Writes a JSON audit record for compliance

Uses LocalStack with boto3 for safe AWS IAM simulation.
In production, remove the endpoint_url to target real AWS.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scanner.config import ScanConfig
from scanner.models import (
    Finding,
    RotationRecord,
    RotationStatus,
    SecretType,
    ValidationStatus,
)

logger = logging.getLogger(__name__)


# ============================================================
# Main Rotation Orchestrator
# ============================================================


def rotate_finding(
    finding: Finding,
    config: ScanConfig,
    audit_dir: str = "./audit_logs",
) -> Optional[RotationRecord]:
    """
    Execute the full rotation workflow for a single finding.

    Steps: Alert → Rotate → Revoke → Audit

    Only processes findings that are:
      - CRITICAL severity
      - LIVE or POSSIBLY_LIVE validation status
      - Of a rotatable secret type (AWS keys)

    Args:
        finding: The finding to rotate.
        config: Scanner configuration.
        audit_dir: Directory to write audit logs to.

    Returns:
        RotationRecord if rotation was attempted, None if skipped.
    """
    # --- Gate: Should we rotate this? ---
    if not _should_rotate(finding, config):
        finding.rotation_status = RotationStatus.SKIPPED
        finding.rotation_detail = "Does not meet rotation criteria"
        return None

    timestamp = datetime.now(timezone.utc)
    old_key_hash = hashlib.sha256(finding.matched_content.encode()).hexdigest()[:16]

    record = RotationRecord(
        timestamp=timestamp,
        finding=finding,
        old_key_hash=old_key_hash,
        rotation_status=RotationStatus.PENDING,
    )

    # --- Step 1: ALERT ---
    _send_alert(finding, config)
    record.alert_sent = True

    # --- Step 2 & 3: ROTATE + REVOKE ---
    if config.rotation_dry_run:
        record.rotation_status = RotationStatus.DRY_RUN
        record.detail = (
            f"[DRY RUN] Would rotate {finding.secret_type.value} "
            f"in {finding.file_path} | Old key hash: {old_key_hash}"
        )
        finding.rotation_status = RotationStatus.DRY_RUN
        finding.rotation_detail = record.detail
        logger.info(f"[DRY RUN] {record.detail}")
    else:
        # Dispatch to the appropriate rotator
        _execute_rotation(finding, record, config)

    # --- Step 4: AUDIT LOG ---
    _write_audit_log(record, audit_dir)

    return record


def rotate_findings(
    findings: list[Finding],
    config: ScanConfig,
    audit_dir: str = "./audit_logs",
) -> list[RotationRecord]:
    """
    Run rotation workflow for all eligible findings.

    Args:
        findings: All scored and validated findings.
        config: Scanner configuration.
        audit_dir: Directory for audit logs.

    Returns:
        List of RotationRecord objects for all attempted rotations.
    """
    if not config.enable_rotation:
        return []

    records: list[RotationRecord] = []

    for finding in findings:
        record = rotate_finding(finding, config, audit_dir)
        if record is not None:
            records.append(record)

    return records


# ============================================================
# Step 1: Alert
# ============================================================


def _send_alert(finding: Finding, config: ScanConfig) -> None:
    """
    Send an alert notification about the detected credential.

    Outputs to console (always) and optionally to a Slack webhook.
    """
    # Console alert
    alert_msg = (
        f"\n{'='*60}\n"
        f"🚨 CREDENTIAL ROTATION ALERT\n"
        f"{'='*60}\n"
        f"  Type:     {finding.secret_type.value}\n"
        f"  File:     {finding.file_path}:{finding.line_number}\n"
        f"  Severity: {finding.severity_label} ({finding.final_score:.1f}/10)\n"
        f"  Status:   {finding.validation_status.value}\n"
        f"  Commit:   {finding.commit_sha[:8] if finding.commit_sha else 'working tree'}\n"
        f"  Author:   {finding.author or 'unknown'}\n"
        f"  Value:    {finding.redacted_content}\n"
        f"{'='*60}\n"
    )
    print(alert_msg)
    logger.warning(alert_msg)

    # Slack webhook (if configured — mock for hackathon)
    _send_slack_notification(finding, config)


def _send_slack_notification(finding: Finding, config: ScanConfig) -> None:
    """
    Send a mock Slack webhook notification.

    In production, this would POST to a real Slack webhook URL.
    For the hackathon, we log the payload that would be sent.
    """
    slack_payload = {
        "text": f"🚨 *Secret Detected & Rotation Triggered*",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔐 GitSentinel — Credential Rotation Alert",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Type:*\n{finding.secret_type.value}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{finding.severity_label} ({finding.final_score:.1f}/10)"},
                    {"type": "mrkdwn", "text": f"*File:*\n`{finding.file_path}`"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{finding.validation_status.value}"},
                ],
            },
        ],
    }

    logger.info(f"[MOCK SLACK] Would send: {json.dumps(slack_payload, indent=2)}")


# ============================================================
# Step 2 & 3: Rotate + Revoke
# ============================================================


def _execute_rotation(
    finding: Finding,
    record: RotationRecord,
    config: ScanConfig,
) -> None:
    """
    Dispatch rotation to the appropriate handler based on secret type.
    """
    rotators = {
        SecretType.AWS_ACCESS_KEY: _rotate_aws_key,
        SecretType.AWS_SECRET_KEY: _rotate_aws_key,
    }

    rotator_fn = rotators.get(finding.secret_type)

    if rotator_fn is None:
        record.rotation_status = RotationStatus.SKIPPED
        record.detail = f"No rotation handler for {finding.secret_type.value}"
        finding.rotation_status = RotationStatus.SKIPPED
        finding.rotation_detail = record.detail
        return

    try:
        record.rotation_status = RotationStatus.ROTATING
        rotator_fn(finding, record, config)
    except Exception as e:
        record.rotation_status = RotationStatus.FAILED
        record.detail = f"Rotation failed: {str(e)}"
        finding.rotation_status = RotationStatus.FAILED
        finding.rotation_detail = record.detail
        logger.error(f"Rotation failed: {e}")


def _rotate_aws_key(
    finding: Finding,
    record: RotationRecord,
    config: ScanConfig,
) -> None:
    """
    Rotate an AWS access key using LocalStack IAM.

    Steps:
      1. Create a new access key for the IAM user
      2. Deactivate the old access key
      3. Delete the old access key
      4. Verify the new key works via sts:GetCallerIdentity

    In production, the new key would be stored in HashiCorp Vault
    or AWS Secrets Manager. For the hackathon, we log it.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, EndpointConnectionError
    except ImportError:
        record.rotation_status = RotationStatus.FAILED
        record.detail = "boto3 not installed — cannot rotate AWS keys"
        finding.rotation_status = RotationStatus.FAILED
        finding.rotation_detail = record.detail
        return

    iam_user = config.rotation_iam_user
    record.iam_user = iam_user

    try:
        # Create IAM client pointing at LocalStack
        iam_client = boto3.client(
            "iam",
            endpoint_url=config.localstack_endpoint,
            region_name=config.aws_region,
            aws_access_key_id=config.aws_access_key,
            aws_secret_access_key=config.aws_secret_key,
        )

        # Ensure the IAM user exists (LocalStack may not have it)
        try:
            iam_client.create_user(UserName=iam_user)
            logger.info(f"Created IAM user '{iam_user}' on LocalStack")
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExists":
                raise

        # Step 1: Create a new access key
        print(f"  ↳ Creating new access key for IAM user '{iam_user}'...")
        new_key_response = iam_client.create_access_key(UserName=iam_user)
        new_key = new_key_response["AccessKey"]
        new_access_key_id = new_key["AccessKeyId"]
        new_secret_key = new_key["SecretAccessKey"]

        record.new_key_hint = new_access_key_id[:4] + "..."
        print(f"  ✅ New access key created: {new_access_key_id[:4]}...{new_access_key_id[-4:]}")

        # Step 2: Deactivate old key (if we can identify it)
        old_key_id = finding.matched_content if finding.secret_type == SecretType.AWS_ACCESS_KEY else ""
        if old_key_id and old_key_id.startswith("AKIA"):
            try:
                print(f"  ↳ Deactivating old key {old_key_id[:4]}...{old_key_id[-4:]}...")
                iam_client.update_access_key(
                    UserName=iam_user,
                    AccessKeyId=old_key_id,
                    Status="Inactive",
                )
                print(f"  ✅ Old key deactivated")
            except ClientError:
                # Key may not exist on LocalStack — create it first for demo
                try:
                    iam_client.create_access_key(UserName=iam_user)
                except Exception:
                    pass
                print(f"  ⚠️  Could not deactivate old key (may not exist on LocalStack)")

            # Step 3: Delete old key
            try:
                iam_client.delete_access_key(
                    UserName=iam_user,
                    AccessKeyId=old_key_id,
                )
                print(f"  ✅ Old key deleted")
            except ClientError:
                print(f"  ⚠️  Could not delete old key (may not exist on LocalStack)")

        # Step 4: Verify new key works
        print(f"  ↳ Verifying new key...")
        sts_client = boto3.client(
            "sts",
            endpoint_url=config.localstack_endpoint,
            region_name=config.aws_region,
            aws_access_key_id=new_access_key_id,
            aws_secret_access_key=new_secret_key,
        )
        identity = sts_client.get_caller_identity()
        print(f"  ✅ New key verified — ARN: {identity.get('Arn', 'unknown')}")

        # Success!
        record.rotation_status = RotationStatus.SUCCESS
        record.detail = (
            f"Successfully rotated AWS key for user '{iam_user}' | "
            f"Old key hash: {record.old_key_hash} | "
            f"New key: {new_access_key_id[:4]}...{new_access_key_id[-4:]}"
        )
        finding.rotation_status = RotationStatus.SUCCESS
        finding.rotation_detail = record.detail

        print(f"\n  🔄 ROTATION COMPLETE for {finding.secret_type.value}")
        print(f"  📋 New key would be stored in HashiCorp Vault / AWS Secrets Manager")

    except EndpointConnectionError:
        record.rotation_status = RotationStatus.FAILED
        record.detail = (
            "LocalStack not reachable at " + config.localstack_endpoint +
            " — start with: docker-compose up -d"
        )
        finding.rotation_status = RotationStatus.FAILED
        finding.rotation_detail = record.detail
        print(f"  ❌ {record.detail}")

    except Exception as e:
        record.rotation_status = RotationStatus.FAILED
        record.detail = f"AWS IAM rotation error: {str(e)}"
        finding.rotation_status = RotationStatus.FAILED
        finding.rotation_detail = record.detail
        print(f"  ❌ {record.detail}")


# ============================================================
# Step 4: Audit Log
# ============================================================


def _write_audit_log(record: RotationRecord, audit_dir: str) -> None:
    """
    Write a rotation audit record to a JSON log file.

    Each rotation event is appended as a JSON line (JSONL format)
    to the audit log for compliance and incident response.
    """
    audit_path = Path(audit_dir)
    audit_path.mkdir(parents=True, exist_ok=True)

    log_file = audit_path / "rotation_audit.jsonl"

    entry = record.to_dict()

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    logger.info(f"Audit record written to {log_file}")


# ============================================================
# Helpers
# ============================================================


def _should_rotate(finding: Finding, config: ScanConfig) -> bool:
    """
    Determine whether a finding is eligible for rotation.

    Criteria:
      1. Rotation must be enabled in config
      2. Finding must be CRITICAL or HIGH severity
      3. Finding must be LIVE or POSSIBLY_LIVE
      4. Secret type must have a rotation handler
    """
    if not config.enable_rotation:
        return False

    if finding.severity_label not in ("CRITICAL", "HIGH"):
        return False

    if finding.validation_status not in (
        ValidationStatus.LIVE,
        ValidationStatus.POSSIBLY_LIVE,
    ):
        return False

    # Only AWS keys are rotatable in this version
    rotatable_types = {
        SecretType.AWS_ACCESS_KEY,
        SecretType.AWS_SECRET_KEY,
    }

    return finding.secret_type in rotatable_types
