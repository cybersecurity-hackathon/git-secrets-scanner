<p align="center">
  <h1 align="center">🔐 GitSentinel</h1>
  <p align="center">
    <strong>Automated Secrets Detection & Credential Rotation for Git Repositories</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#usage">Usage</a> •
    <a href="#demo">Demo</a> •
    <a href="threat_model.md">Threat Model</a> •
    <a href="deployment_brief.md">Deployment</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/MITRE_ATT%26CK-T1552.001-red?style=flat-square" alt="MITRE ATT&CK" />
    <img src="https://img.shields.io/badge/Architecture-Cloud--Native_|_Hybrid-blue?style=flat-square" alt="Architecture" />
    <img src="https://img.shields.io/badge/Track-Defensive-green?style=flat-square" alt="Track" />
    <img src="https://img.shields.io/badge/Python-3.10+-yellow?style=flat-square" alt="Python" />
    <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square" alt="License" />
  </p>
</p>

---

## 🎯 What Problem Does This Solve?

Developers frequently **accidentally commit secrets** — AWS access keys, database passwords, JWT signing keys, private certificates — into Git repositories. Once pushed, these credentials persist in Git history **even after deletion** from the working tree. In 2024 alone, GitGuardian reported over **12.8 million new secrets leaked** on public GitHub repositories. An attacker who gains read access to a repository can harvest these credentials and use them for lateral movement, data exfiltration, and privilege escalation across cloud infrastructure.

**GitSentinel** is an automated secrets detection pipeline that:

1. **Scans** Git repositories — current files, full commit history, all branches, and staged changes
2. **Identifies** leaked secrets using **regex pattern matching** (gitleaks-inspired rules) and **Shannon entropy analysis**
3. **Prioritises** findings by severity using a weighted scoring model (live AWS key vs. test password)
4. **Validates** whether detected credentials are still live (via LocalStack-simulated AWS)
5. **Triggers** an automated credential rotation workflow for confirmed cloud credentials

---

## 🏗️ Target Architecture

| Attribute | Value |
|-----------|-------|
| **Architecture** | Cloud-Native / Hybrid |
| **MITRE ATT&CK** | [T1552.001 — Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Defensive Track** | Secrets Detection & Rotation Automation |
| **Stack Position** | Application / Identity Layer (SDLC Pipeline) |

This tool is designed for organisations running **containerised microservices** on Kubernetes (EKS/AKS/GKE) with cloud-native CI/CD pipelines. It integrates as:
- A **pre-commit hook** — preventing secrets from entering the repository
- A **CI/CD pipeline stage** — scanning on every pull request via GitHub Actions
- A **scheduled audit tool** — periodic full-history scans of existing repositories

> See [architecture.md](architecture.md) for the full architecture diagram.

---

## <a id="quick-start"></a>🚀 Quick Start

### Prerequisites

- Python 3.10+
- Git
- Docker & Docker Compose (for LocalStack credential rotation demo)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/cybersecurity-hackathon/git-secrets-scanner.git
cd git-secrets-scanner

# 2. Create a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Start LocalStack for credential rotation demo
docker-compose up -d
```

### Seed the Test Repository

```bash
# Create a test repository with intentionally planted secrets
python -m test_repo.setup_test_repo
```

This generates a local Git repository at `./vulnerable_repo/` containing **12+ planted secrets** across multiple commits, including secrets that were committed and later deleted (to test history scanning).

---

## <a id="usage"></a>📖 Usage

### Scan a Repository

```bash
# Scan with CLI table output (default)
python -m scanner.cli scan ./vulnerable_repo

# Scan with JSON output (for CI/CD integration)
python -m scanner.cli scan ./vulnerable_repo --format json

# Scan with HTML report
python -m scanner.cli scan ./vulnerable_repo --format html --output report.html

# Scan only the current working tree (skip history)
python -m scanner.cli scan ./vulnerable_repo --no-history

# Scan with custom severity threshold
python -m scanner.cli scan ./vulnerable_repo --min-severity HIGH
```

### Validate Detected Credentials

```bash
# Check if detected AWS credentials are still live (requires LocalStack)
python -m scanner.cli validate ./vulnerable_repo
```

### Trigger Credential Rotation

```bash
# Auto-rotate all CRITICAL findings with live credentials
python -m scanner.cli rotate ./vulnerable_repo --auto

# Dry-run rotation (show what would happen without executing)
python -m scanner.cli rotate ./vulnerable_repo --dry-run
```

### Example Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                        🔐 GitSentinel Scan Report                          ║
╠══════════════════════════════════════════════════════════════════════════════╣

  Repository: ./vulnerable_repo
  Commits scanned: 9 | Branches: 2 | Files: 14
  Scan duration: 1.2s

┌──────────┬────────────────────────┬──────────────────────┬────────┬────────┐
│ Severity │ Secret Type            │ File                 │ Status │ Score  │
├──────────┼────────────────────────┼──────────────────────┼────────┼────────┤
│ 🔴 CRIT  │ AWS Access Key ID      │ config/aws_config.py │ LIVE   │ 9.4/10 │
│ 🔴 CRIT  │ AWS Secret Access Key  │ config/aws_config.py │ LIVE   │ 9.4/10 │
│ 🔴 CRIT  │ RSA Private Key        │ certs/server.key     │ VALID  │ 8.8/10 │
│ 🔴 CRIT  │ Stripe Secret Key      │ .env.production      │ LIVE   │ 8.5/10 │
│ 🟠 HIGH  │ DB Connection String   │ config/database.yml  │ UNKN   │ 7.2/10 │
│ 🟠 HIGH  │ JWT Signing Key        │ src/auth/jwt.js      │ VALID  │ 6.9/10 │
│ 🟠 HIGH  │ Slack Bot Token        │ .env.production      │ UNKN   │ 6.5/10 │
│ 🟠 HIGH  │ GitHub PAT             │ src/utils/helpers.py  │ UNKN   │ 6.1/10 │
│ 🟡 MED   │ DB Password            │ docker-compose.yml   │ UNKN   │ 4.3/10 │
│ 🟡 MED   │ AWS Key (deleted)      │ config/aws_config.py │ HIST   │ 3.8/10 │
│ 🟢 LOW   │ Test API Key           │ tests/test_config.py │ TEST   │ 1.5/10 │
└──────────┴────────────────────────┴──────────────────────┴────────┴────────┘

  ⚠  4 CRITICAL findings require immediate rotation
  ℹ  Run: python -m scanner.cli rotate ./vulnerable_repo --auto

╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## <a id="architecture"></a>🏛️ Architecture

GitSentinel follows the **Sensor → Analyser → Responder** defensive architecture pattern:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SECRETS DETECTION PIPELINE                       │
│                                                                     │
│  ┌──────────────┐   ┌──────────────────┐   ┌────────────────────┐  │
│  │   SENSOR /   │   │   ANALYSER /     │   │   RESPONDER /      │  │
│  │  COLLECTOR   │──▶│   DETECTOR       │──▶│   ROTATOR          │  │
│  │              │   │                  │   │                    │  │
│  │ • Git clone  │   │ • Regex patterns │   │ • Severity scoring │  │
│  │ • Commit     │   │ • Entropy calc   │   │ • Live key check   │  │
│  │   history    │   │ • File-type      │   │ • AWS key rotation │  │
│  │   traversal  │   │   analysis       │   │ • Alert dispatch   │  │
│  │ • Diff       │   │ • Allowlisting   │   │ • Audit log        │  │
│  │   extraction │   │                  │   │                    │  │
│  └──────────────┘   └──────────────────┘   └────────────────────┘  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                      REPORTING ENGINE                           ││
│  │  • CLI dashboard  • JSON report  • HTML report  • Git blame    ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

> See [architecture.md](architecture.md) for the full Mermaid diagram with data flows.

---

## 🔍 Detection Methods

### 1. Pattern Matching (Regex)

11+ rules inspired by [gitleaks](https://github.com/gitleaks/gitleaks) and [truffleHog](https://github.com/truffleHog/truffleHog):

| Secret Type | Example Pattern | Severity |
|------------|----------------|----------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | CRITICAL |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| GitHub PAT | `ghp_[A-Za-z0-9_]{36}` | HIGH |
| Slack Token | `xox[baprs]-...` | HIGH |
| JWT Secret | `jwt_secret = "..."` | HIGH |
| DB Connection String | `postgres://user:pass@host` | HIGH |
| Generic Password | `password = "..."` | MEDIUM |
| Generic API Key | `api_key = "..."` | MEDIUM |

### 2. Shannon Entropy Analysis

For secrets that don't match known patterns:
- Calculates Shannon entropy per token in each line
- **Thresholds:** Hex strings > 3.0 bits/char, Base64 strings > 4.5 bits/char
- Contextual heuristics: variable name analysis, file-type weighting, length filtering

### 3. Severity Scoring (Weighted Model)

```
score = (base_severity × 0.3) + (validity × 0.3) + (exposure × 0.2) + (age × 0.1) + (context × 0.1)
```

| Score Range | Classification | Action |
|------------|---------------|--------|
| ≥ 8.0 | 🔴 CRITICAL | Immediate automated rotation |
| ≥ 5.0 | 🟠 HIGH | Rotate within 24 hours |
| ≥ 3.0 | 🟡 MEDIUM | Review at next security cycle |
| < 3.0 | 🟢 LOW | Informational — likely test data |

---

## 🔄 Credential Rotation Workflow

When a **CRITICAL + LIVE** credential is detected:

```
Detect → Alert (Slack/Console) → Rotate (LocalStack IAM) → Revoke Old Key → Audit Log
```

The rotation uses **LocalStack** with the AWS SDK (`boto3`) to simulate real IAM operations:
- `iam.CreateAccessKey()` — generate new credentials
- `iam.UpdateAccessKey(Status='Inactive')` — disable the leaked key
- `iam.DeleteAccessKey()` — remove the compromised key
- `sts.GetCallerIdentity()` — verify the new key works

> In production, remove the `endpoint_url` parameter to target real AWS.

---

## 📁 Project Structure

```
git-secrets-scanner/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── setup.py                     # Package setup
├── architecture.md              # Architecture diagram (Mermaid)
├── threat_model.md              # MITRE ATT&CK mapping
├── deployment_brief.md          # Deployment guide
├── docker-compose.yml           # LocalStack for AWS simulation
├── .github/
│   └── workflows/
│       └── scan.yml             # GitHub Actions CI/CD integration
├── scanner/                     # Core scanner package
│   ├── __init__.py
│   ├── cli.py                   # CLI entry point
│   ├── models.py                # Shared data models
│   ├── collector.py             # Git repo traversal (Sensor)
│   ├── detector.py              # Detection engine (Analyser)
│   ├── patterns.py              # Regex pattern definitions
│   ├── entropy.py               # Shannon entropy calculator
│   ├── scorer.py                # Severity scoring
│   ├── validator.py             # Credential validity checker
│   ├── rotator.py               # Rotation workflow (Responder)
│   ├── reporter.py              # Report generation
│   └── config.py                # Configuration & allowlists
├── test_repo/                   # Test repository setup
│   ├── setup_test_repo.py       # Script to seed vulnerable repo
│   └── seeds/                   # Template files with planted secrets
└── tests/                       # Unit & integration tests
```

---

## 🧪 Test Repository

The test repository contains **12+ intentionally planted secrets** across 9 commits:

| Commit | Secret | Detection Challenge |
|--------|--------|-------------------|
| #1 | AWS Access Key + Secret | Standard pattern match |
| #2 | Database password + MongoDB URI | Connection string parsing |
| #3 | JWT signing key | Variable-name context |
| #4 | RSA 2048-bit private key | PEM header detection |
| #5 | Stripe key + Slack token | Multi-secret file |
| #6 | GitHub PAT | Token format match |
| #7 | *(deleted AWS key)* | **History scanning** — key removed but in git log |
| #8 | Docker Compose DB password | YAML value extraction |
| #9 | Test API key | Should be scored LOW |

> ⚠️ **All secrets in the test repo are fake and non-functional.** They follow realistic formats but cannot authenticate to any real service.

---

## <a id="demo"></a>🎬 5-Minute Demo Script

| Time | What to Show |
|------|-------------|
| 0:00–1:00 | **Threat context:** T1552.001, 12.8M leaked secrets in 2024, real-world impact |
| 1:00–3:00 | **Live terminal demo:** Scan → detect all secrets → show deleted key caught in history → severity scores |
| 3:00–4:00 | **Architecture fit:** Mermaid diagram, CI/CD integration, pre-commit hook |
| 4:00–5:00 | **Limitations & next steps:** Production deployment, ML detection, GitHub App |

---

## ⚠️ Known Limitations

- **Validation is simulated:** AWS credential validation uses LocalStack, not real AWS APIs
- **No ML-based detection:** Relies on regex + entropy; a production version would add ML classifiers
- **Single cloud provider:** Currently supports AWS rotation only; Azure/GCP would need additional modules
- **No real-time monitoring:** Runs as a batch scanner; a production version would use webhooks for push-event scanning
- **Pre-commit hook not packaged:** Currently runs as a standalone CLI; packaging as a git hook is a future enhancement

---

## 🚀 Production Roadmap

If deployed in a real enterprise environment, the next steps would be:
1. **GitHub App / GitLab Webhook** — scan every push in real-time across all org repos
2. **Real AWS IAM integration** — remove LocalStack, target real `sts` and `iam` endpoints
3. **HashiCorp Vault integration** — store rotated credentials securely
4. **Kubernetes Admission Controller** — block deployments containing hardcoded secrets
5. **ML-based detection** — train on labelled secret/non-secret data to reduce false positives
6. **Multi-cloud support** — Azure AD, GCP IAM credential rotation

---

## 👥 Team

| Role | Responsibility |
|------|---------------|
| Person 1–2 | Pattern matching engine + entropy analysis |
| Person 3 | Credential validity checker (live key detection) |
| Person 4 | Rotation automation workflow |
| Person 5 | Test repository setup + evaluation |

---

## 📄 License

This project is developed for the **FoSC 23CSE313 Cyber Security Hackathon** (VI Semester CSE).

MIT License — see [LICENSE](LICENSE) for details.