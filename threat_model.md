# 🛡️ GitSentinel — Threat Model Document

## 1. Threat Overview

| Attribute | Value |
|-----------|-------|
| **MITRE ATT&CK Technique** | [T1552.001 — Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Target Architecture** | Cloud-Native / Hybrid (Kubernetes, AWS/Azure/GCP) |
| **Threat Classification** | Insider Threat, External Reconnaissance, Supply Chain Compromise |

---

## 2. Threat Description

Developers accidentally commit sensitive credentials — API keys, database passwords, JWT signing secrets, TLS private keys — into Git repositories. These secrets become **permanently embedded** in Git's commit history, even if subsequently deleted from the working tree.

### Why This Is Dangerous

- **Git never forgets:** A secret committed and then removed in the next commit still exists in `git log`. Anyone with read access to the repository can recover it.
- **Blast radius is enormous:** A single AWS access key can provide full access to S3 buckets, EC2 instances, RDS databases, and Lambda functions.
- **Attack surface grows with time:** Every day a leaked secret remains unrotated increases the window of exploitation.
- **Scale of the problem:** GitGuardian's 2024 report identified **12.8 million new secrets** leaked on public GitHub repositories in a single year.

---

## 3. Threat Actors

| Actor | Motivation | Access Method |
|-------|-----------|---------------|
| **External Attacker** | Financial gain, espionage | Scanning public repos (GitHub dorks, truffleHog), compromised CI/CD |
| **Malicious Insider** | Sabotage, data theft | Direct repo access via employee credentials |
| **Compromised CI/CD Runner** | Lateral movement | Exploiting CI environment to read repo contents |
| **Supply Chain Attacker** | Backdoor deployment | Forking repos, reading commit history for credentials |

---

## 4. MITRE ATT&CK Kill Chain Mapping

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ATTACK KILL CHAIN                                    │
│                                                                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐ │
│  │ Recon    │──▶│ Access   │──▶│ Cred     │──▶│ Lateral  │──▶│ Impact   │ │
│  │          │   │          │   │ Access   │   │ Movement │   │          │ │
│  │ Scan     │   │ Clone    │   │ T1552    │   │ Use key  │   │ Exfil    │ │
│  │ GitHub   │   │ repo     │   │ .001     │   │ to pivot │   │ data     │ │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘ │
│                                     ▲                                       │
│                                     │                                       │
│                          ┌──────────┴──────────┐                           │
│                          │  🔐 GitSentinel     │                           │
│                          │  DETECTS & ROTATES  │                           │
│                          │  HERE               │                           │
│                          └─────────────────────┘                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

| Kill Chain Stage | ATT&CK Technique | GitSentinel's Role |
|-----------------|-------------------|-------------------|
| **Reconnaissance** | T1593.003 — Search Open Websites/Domains: Code Repositories | ⚠️ Out of scope (we detect, not prevent recon) |
| **Initial Access** | T1078.004 — Valid Accounts: Cloud Accounts | 🛡️ **Prevent** — rotate credentials before attacker uses them |
| **Credential Access** | **T1552.001 — Credentials In Files** | 🛡️ **Detect** — identify secrets in repo content and history |
| **Lateral Movement** | T1550.001 — Use Alternate Authentication Material | 🛡️ **Mitigate** — revoke old key, issue new one |
| **Exfiltration** | T1537 — Transfer Data to Cloud Account | 🛡️ **Prevent** — rotated credentials block attacker access |

---

## 5. Attack Scenarios

### Scenario 1: Leaked AWS Key on Public Repository

```
1. Developer commits aws_config.py with AKIA... key to public GitHub repo
2. Attacker runs automated scanner (truffleHog, GitHub dorking)
3. Attacker finds AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
4. Attacker calls aws sts get-caller-identity → confirms key is live
5. Attacker enumerates permissions → finds S3 read/write access
6. Attacker exfiltrates customer data from production S3 bucket
```

**GitSentinel Response:**
- **Pre-commit hook** blocks the commit before it's pushed
- **CI/CD scan** catches it on the pull request, blocks merge
- **Post-commit scan** detects it, validates it's live, auto-rotates the key
- **Time to remediate:** < 60 seconds (automated) vs. days/weeks (manual discovery)

### Scenario 2: Deleted Secret Still in Git History

```
1. Developer commits database password in config/database.yml
2. Developer realises mistake, deletes the password, commits again
3. Developer believes the secret is removed — it is NOT
4. Attacker clones repo, runs: git log -p -- config/database.yml
5. Attacker recovers the password from the diff in commit history
6. Attacker connects to production database
```

**GitSentinel Response:**
- Full history traversal scans **every commit diff**, not just current files
- Detects the password in the historical commit even though it's deleted
- Scores it as HIGH (historical but potentially still valid)
- Recommends password rotation

### Scenario 3: High-Entropy Custom Token

```
1. Developer stores a custom API token: INTERNAL_SERVICE_TOKEN=a8f3k2m9...
2. Token doesn't match any known regex pattern (custom internal format)
3. Standard pattern-matching tools miss it entirely
4. Attacker finds it, uses it to authenticate to internal microservice
```

**GitSentinel Response:**
- Shannon entropy analysis flags the high-entropy string (> 4.5 bits/char)
- Contextual heuristics detect assignment to a `TOKEN`-named variable
- Scores it as MEDIUM — flagged for manual review

---

## 6. Mitigations Provided by GitSentinel

| # | Mitigation | Implementation |
|---|-----------|---------------|
| 1 | **Detect secrets before they're pushed** | Pre-commit hook scans staged changes |
| 2 | **Detect secrets in CI/CD pipeline** | GitHub Actions workflow blocks PRs with secrets |
| 3 | **Detect secrets in Git history** | Full commit history traversal catches deleted secrets |
| 4 | **Prioritise by real-world risk** | Weighted severity scoring (live key > test password) |
| 5 | **Validate credential liveness** | boto3 calls to LocalStack verify if key is active |
| 6 | **Automate credential rotation** | IAM key rotation via LocalStack without human intervention |
| 7 | **Create audit trail** | JSON logs for compliance and incident response |
| 8 | **Alert security team** | Console alerts and Slack webhook notifications |

---

## 7. Residual Risks (What GitSentinel Does NOT Cover)

| Risk | Why It's Out of Scope |
|------|----------------------|
| Secrets in binary files (images, compiled code) | Requires binary analysis, not text scanning |
| Secrets transmitted over network (not in files) | Requires network monitoring (different tool) |
| Social engineering to obtain credentials | Human problem, not a code problem |
| Zero-day vulnerabilities in dependencies | Requires SCA tools (Dependabot, Snyk) |
| Container escape from compromised pod | Requires runtime security (Falco, Sysdig) |

---

## 8. References

- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
- [GitGuardian State of Secrets Sprawl 2024](https://www.gitguardian.com/state-of-secrets-sprawl-report-2024)
- [OWASP Top 10 — A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CIS Benchmark — Ensure credentials are not stored in code](https://www.cisecurity.org/benchmark)
- [NIST SP 800-53 — IA-5: Authenticator Management](https://csf.tools/reference/nist-sp-800-53/r5/ia/ia-5/)
