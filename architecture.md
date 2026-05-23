# 🏛️ GitSentinel — Architecture Document

## Overview

GitSentinel is a **defensive security tool** that sits at the **Application / Identity layer** of a cloud-native architecture. It integrates into the Software Development Lifecycle (SDLC) to detect and remediate secrets leaked into Git repositories.

---

## High-Level Architecture

```mermaid
flowchart TB
    subgraph INPUT["📥 Input Sources"]
        LOCAL["Local Git Repo"]
        REMOTE["Remote Git Repo<br/>(GitHub/GitLab)"]
        CICD["CI/CD Pipeline<br/>(GitHub Actions)"]
        HOOK["Pre-Commit Hook"]
    end

    subgraph SENSOR["🔍 Sensor / Collector"]
        CLONE["Git Clone / Open"]
        HISTORY["Commit History<br/>Traversal"]
        DIFF["Diff Extraction"]
        STAGED["Staged Changes<br/>Scanner"]
    end

    subgraph ANALYSER["🧠 Analyser / Detector"]
        REGEX["Regex Pattern<br/>Matching"]
        ENTROPY["Shannon Entropy<br/>Analysis"]
        CONTEXT["Contextual<br/>Heuristics"]
        DEDUP["Deduplication &<br/>Allowlist Filter"]
    end

    subgraph RESPONDER["⚡ Responder"]
        SCORER["Severity Scorer<br/>(Weighted Model)"]
        VALIDATOR["Credential Validator<br/>(LocalStack / boto3)"]
        ROTATOR["Rotation Engine<br/>(IAM Key Rotation)"]
        ALERTER["Alert Dispatcher<br/>(Slack / Console)"]
    end

    subgraph OUTPUT["📤 Output"]
        CLI_OUT["CLI Dashboard<br/>(Colored Table)"]
        JSON_OUT["JSON Report<br/>(CI/CD Integration)"]
        HTML_OUT["HTML Report<br/>(Stakeholder View)"]
        AUDIT["Audit Log<br/>(Compliance Trail)"]
    end

    INPUT --> SENSOR
    SENSOR --> ANALYSER
    ANALYSER --> RESPONDER
    RESPONDER --> OUTPUT

    CLONE --> HISTORY
    HISTORY --> DIFF

    REGEX --> DEDUP
    ENTROPY --> DEDUP
    CONTEXT --> DEDUP

    SCORER --> VALIDATOR
    VALIDATOR --> ROTATOR
    ROTATOR --> ALERTER
```

---

## Data Flow

```mermaid
sequenceDiagram
    actor User
    participant CLI as CLI Entry Point
    participant Collector as Sensor/Collector
    participant Git as Git Repository
    participant Detector as Analyser/Detector
    participant Scorer as Severity Scorer
    participant Validator as Credential Validator
    participant LocalStack as LocalStack (AWS)
    participant Rotator as Rotation Engine
    participant Reporter as Reporter

    User->>CLI: gitsentinel scan ./repo
    CLI->>Collector: scan(repo_path)
    Collector->>Git: Open repo, enumerate commits
    Git-->>Collector: Commit objects, diffs, blobs

    loop For each commit/file
        Collector->>Detector: ScanTarget(file, content, metadata)
        Detector->>Detector: Run regex patterns
        Detector->>Detector: Calculate Shannon entropy
        Detector->>Detector: Apply contextual heuristics
        Detector-->>Collector: List[Finding]
    end

    Collector->>Scorer: All findings
    Scorer->>Scorer: Calculate weighted severity score
    Scorer-->>Collector: Scored findings

    opt Validation enabled
        Scorer->>Validator: CRITICAL findings
        Validator->>LocalStack: sts.GetCallerIdentity()
        LocalStack-->>Validator: Valid / Invalid
        Validator-->>Scorer: Validation status
    end

    opt Auto-rotation enabled
        Scorer->>Rotator: CRITICAL + LIVE findings
        Rotator->>LocalStack: iam.CreateAccessKey()
        Rotator->>LocalStack: iam.UpdateAccessKey(Inactive)
        Rotator->>LocalStack: iam.DeleteAccessKey()
        LocalStack-->>Rotator: New credentials
        Rotator-->>Scorer: Rotation audit record
    end

    Scorer->>Reporter: Final results
    Reporter-->>User: CLI Table / JSON / HTML Report
```

---

## Component Responsibilities

```mermaid
graph LR
    subgraph scanner["scanner/ Package"]
        models["models.py<br/>─────────<br/>ScanTarget<br/>Finding<br/>SecretPattern<br/>RotationRecord"]
        collector["collector.py<br/>─────────<br/>Git traversal<br/>Commit history<br/>Branch enumeration"]
        patterns["patterns.py<br/>─────────<br/>11+ regex rules<br/>gitleaks-inspired<br/>Pattern registry"]
        entropy["entropy.py<br/>─────────<br/>Shannon entropy<br/>Hex/Base64 detect<br/>Threshold filter"]
        detector["detector.py<br/>─────────<br/>Orchestrates<br/>patterns + entropy<br/>Deduplication"]
        scorer["scorer.py<br/>─────────<br/>Weighted scoring<br/>5-factor model<br/>Classification"]
        validator["validator.py<br/>─────────<br/>AWS STS check<br/>PEM validation<br/>JWT verification"]
        rotator["rotator.py<br/>─────────<br/>IAM rotation<br/>Key lifecycle<br/>Audit logging"]
        reporter["reporter.py<br/>─────────<br/>CLI tables<br/>JSON export<br/>HTML dashboard"]
        cli["cli.py<br/>─────────<br/>argparse CLI<br/>scan/validate<br/>rotate commands"]
    end

    cli --> collector
    collector --> detector
    detector --> patterns
    detector --> entropy
    collector --> scorer
    scorer --> validator
    scorer --> rotator
    scorer --> reporter
```

---

## Deployment Integration Points

```mermaid
flowchart LR
    subgraph Developer["👨‍💻 Developer Workstation"]
        PRECOMMIT["Pre-Commit Hook<br/>gitsentinel scan --staged"]
    end

    subgraph CICD_Pipeline["🔄 CI/CD Pipeline"]
        GHA["GitHub Actions<br/>on: pull_request"]
        SCAN_STEP["Run GitSentinel<br/>python -m scanner.cli scan"]
        GATE["Quality Gate<br/>Block if CRITICAL found"]
    end

    subgraph Cloud["☁️ Cloud Infrastructure"]
        VAULT["HashiCorp Vault<br/>Store rotated creds"]
        IAM["AWS IAM<br/>Key rotation target"]
        SLACK["Slack Webhook<br/>Alert channel"]
    end

    subgraph Monitoring["📊 Security Operations"]
        SIEM["SIEM Integration<br/>JSON log ingestion"]
        DASHBOARD["Security Dashboard<br/>HTML reports"]
    end

    PRECOMMIT -->|"Block commit<br/>if secret found"| Developer
    GHA --> SCAN_STEP --> GATE
    GATE -->|"CRITICAL"| SLACK
    GATE -->|"Rotate"| IAM
    IAM -->|"New creds"| VAULT
    SCAN_STEP -->|"JSON logs"| SIEM
    SCAN_STEP -->|"HTML report"| DASHBOARD
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Language** | Python 3.10+ | Core application logic |
| **Git Integration** | GitPython | Repository traversal and history analysis |
| **Pattern Detection** | Python `re` (stdlib) | Regex-based secret pattern matching |
| **Entropy Analysis** | Python `math` (stdlib) | Shannon entropy calculation |
| **AWS Simulation** | LocalStack + boto3 | Credential validation and IAM key rotation |
| **Key Parsing** | `cryptography` | RSA/EC/DSA private key validation |
| **JWT** | `PyJWT` | JWT signing key verification |
| **CLI** | `argparse` + `colorama` + `tabulate` | Terminal interface and coloured output |
| **Reporting** | `jinja2` | HTML report template rendering |
| **CI/CD** | GitHub Actions | Automated scanning on pull requests |
| **Container** | Docker Compose | LocalStack orchestration |

---

## Security Considerations

1. **GitSentinel never exfiltrates secrets** — all processing is local; findings are reported with redacted values
2. **LocalStack isolation** — credential validation runs against a local simulation, never real cloud APIs
3. **Audit trail** — every rotation action is logged with timestamps, key hashes (not values), and operator identity
4. **Fail-open design** — if the scanner crashes, it reports the error but does not block the CI/CD pipeline (unless explicitly configured to fail-closed)
