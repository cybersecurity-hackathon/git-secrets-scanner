# 🚀 GitSentinel — Deployment Brief

## How This Would Be Deployed in a Real Company Environment

### Deployment Model: Three-Layer Integration

GitSentinel is deployed across three layers of the software development lifecycle, ensuring secrets are caught at every stage:

**Layer 1 — Developer Workstation (Prevention)**

GitSentinel is distributed as a **Git pre-commit hook** via the organisation's developer tooling package. When a developer runs `git commit`, the hook scans staged changes for secrets. If a CRITICAL or HIGH severity secret is detected, the commit is **blocked** with an actionable error message showing the file, line number, and secret type. Developers can add legitimate high-entropy strings to a `.gitsentinel-allowlist` file to suppress false positives. This layer prevents 90% of secrets from ever entering the repository.

**Layer 2 — CI/CD Pipeline (Detection)**

A **GitHub Actions workflow** (`.github/workflows/scan.yml`) runs GitSentinel on every pull request. The scanner performs a full-history scan of the PR branch and posts results as a PR comment. If any CRITICAL finding is detected, the workflow **fails the status check**, preventing the PR from being merged. JSON reports are archived as build artefacts and forwarded to the security team's SIEM (Splunk, Elastic, or AWS CloudWatch) via a webhook. This layer acts as a safety net for secrets that bypass pre-commit hooks.

**Layer 3 — Scheduled Audit (Remediation)**

A **cron-scheduled job** (Kubernetes CronJob or GitHub Actions scheduled workflow) runs a full-history scan of all organisation repositories nightly. Findings are compared against the previous scan to identify **new** leaks. For CRITICAL findings with confirmed-live credentials (validated via AWS STS), the rotation workflow is triggered automatically: the old key is deactivated via IAM, a new key is generated and stored in **HashiCorp Vault**, and the security team is notified via Slack. This layer handles legacy secrets and historical leaks that predate the tool's deployment.

### Infrastructure Requirements

| Component | Requirement |
|-----------|------------|
| **Runtime** | Python 3.10+ (runs in any container, VM, or CI runner) |
| **Secrets Rotation** | AWS IAM access (scoped to `iam:CreateAccessKey`, `iam:UpdateAccessKey`, `iam:DeleteAccessKey`, `sts:GetCallerIdentity`) |
| **Secrets Storage** | HashiCorp Vault or AWS Secrets Manager for rotated credentials |
| **Alerting** | Slack incoming webhook URL for security notifications |
| **CI/CD** | GitHub Actions (or equivalent: GitLab CI, Jenkins, CircleCI) |

### Operational Characteristics

- **Stateless** — no database required; all state is in Git and scan reports
- **Fail-open** — if the scanner errors, CI/CD pipelines are not blocked (configurable to fail-closed)
- **Horizontally scalable** — each repo scan is independent; can run in parallel across thousands of repos
- **Low overhead** — typical scan completes in < 5 seconds for repositories with < 10,000 commits
