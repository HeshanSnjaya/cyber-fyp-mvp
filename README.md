# CloudPath — Graph-Based Cloud Attack Path Analyzer

Detecting **compound** cloud security misconfigurations in AWS by chaining
public exposure → IAM privilege → sensitive data into scored, explainable
attack paths.

> Cloud misconfigurations account for up to 80% of data breaches. Traditional
> tools (Prowler, ScoutSuite, Checkov) flag *individual* misconfigurations but
> miss compound risk — where several moderate issues chain into a critical,
> exploitable path. CloudPath models the account as a directed graph and finds
> those chains.

---

## What's new in v2.0

The original MVP was a CLI that scored mock data. v2.0 turns it into a
demo-ready full-stack application:

| Area | MVP (v1) | v2.0 |
|------|----------|------|
| Interface | CLI only | **Streamlit web UI** + CLI |
| Data source | Mock JSON only | **Switchable: Sample JSON ↔ Live AWS** |
| AWS | Planned | **Live `boto3` scan** of EC2 / IAM / S3 |
| Credentials | — | **Entered in-app, encrypted, stored in project** |
| Scoring | CVSS v3.1 | CVSS v3.1 (unchanged, spec-accurate) |
| Threat detail | Path + score | **MITRE ATT&CK, kill-chain, remediation, impact** |
| Visualization | Text | **Interactive attack graph** |
| Persistence | — | **SQLite scan history + trends** |

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │              Front-ends                   │
                    │   app.py (Streamlit UI)   main.py (CLI)   │
                    └───────────────────┬──────────────────────┘
                                        │
                    ┌───────────────────▼──────────────────────┐
                    │            core.analyzer                  │
                    │  fetch → graph → paths → CVSS → intel     │
                    └───┬──────────┬──────────┬──────────┬──────┘
                        │          │          │          │
              data_sources   graph_engine   cvss    threat_intel
              (json / aws)   (networkx)   (v3.1)   (MITRE + fixes)
                        │
                 credentials (encrypted)   database (SQLite history)
```

Both data sources emit one **normalized schema**, so the graph engine, scorer
and UI are completely decoupled from where the data came from.

```
cyber-fyp-mvp/
├── app.py                     # Streamlit web app (main UI)
├── main.py                    # CLI (sample or --aws, --json)
├── mock_data.json             # Bundled sample inventory
├── core/
│   ├── analyzer.py            # End-to-end orchestrator
│   ├── graph_engine.py        # Graph build + attack-path search
│   ├── cvss.py                # CVSS v3.1 scoring
│   ├── threat_intel.py        # MITRE ATT&CK + remediation + narrative
│   ├── credentials.py         # Encrypted, project-local AWS key store
│   ├── database.py            # SQLite scan history
│   └── data_sources/
│       ├── base.py            # DataSource interface
│       ├── json_source.py     # Sample data provider
│       └── aws_source.py      # Live AWS provider (boto3)
├── ui/
│   └── graph_viz.py           # pyvis interactive graph
└── requirements.txt
```

---

## Quick start

```bash
# 1. Create & activate a virtual environment
python -m venv venv
.\venv\Scripts\activate            # Windows
# source venv/bin/activate          # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the web app
streamlit run app.py
```

The app opens in your browser. Choose a data source in the sidebar and click
**Run Analysis**.

### CLI (optional)

```bash
python main.py                # analyze sample data (pretty output)
python main.py --json         # JSON output
python main.py --aws          # live AWS scan (uses saved keys)
python main.py --aws --json   # live AWS scan, JSON output
```

---

## Using the two modes

### 🧪 Sample Data (offline)
Uses the bundled `mock_data.json`. No AWS account or keys required — ideal for
demonstrations. Runs instantly.

### ☁️ Live AWS Account
1. In the sidebar, switch **Data source** to *Live AWS Account*.
2. Enter your **Access Key ID**, **Secret Access Key** (and optional session
   token / region) and click **Save**.
3. (Optional) **Test Connection** — verifies the keys via STS.
4. Click **Run Analysis** to scan real EC2, IAM and S3 resources.

**Credential handling (by design):**
- Keys are entered **in the app** and saved **inside the project** under
  `.secrets/`, encrypted with Fernet (AES-128-CBC + HMAC).
- The app **never** reads environment variables or `~/.aws`. Live mode passes
  your saved keys *explicitly* to `boto3.Session`.
- `.secrets/` and `scan_history.db` are git-ignored — nothing sensitive is
  committed.

**Required AWS permissions:** read-only is sufficient. AWS managed
`SecurityAudit` or `ReadOnlyAccess` covers everything (EC2 `Describe*`, IAM
`List*`/`Get*`, S3 `List`/`GetBucket*`, STS `GetCallerIdentity`). Partial
permissions degrade gracefully rather than crashing the scan.

---

## How the analysis works

1. **Fetch** — the selected source returns a normalized inventory of EC2
   instances (public? which role?), IAM roles (which buckets? admin?) and S3
   buckets (sensitive? encrypted? public?).
2. **Graph** — a `networkx` directed graph is built:
   `Internet → EC2 → IAM Role → S3`.
3. **Paths** — every simple path from `Internet` to a **sensitive** S3 bucket is
   discovered (compound attack paths).
4. **Score** — each path is mapped onto **CVSS v3.1** base metrics and scored
   with the official FIRST formula, so vectors match public calculators.
5. **Enrich** — each path gets a plain-English narrative, a per-hop kill chain,
   **MITRE ATT&CK** techniques (T1190, T1552.005, T1078.004, T1530),
   node-specific remediation and a business-impact summary.
6. **Report** — results render as metrics, charts, an interactive graph and
   expandable finding cards; every scan is saved to SQLite history and can be
   exported as JSON/CSV.

### Live-AWS heuristics
- **EC2 public** = has a public IP **and** a security group open to `0.0.0.0/0`.
- **IAM S3 access** = parsed from attached + inline policy statements
  (`s3:Get*`/`s3:List*`/`s3:*`), mapped to specific bucket ARNs; `Resource:"*"`
  or `AdministratorAccess`/`AmazonS3FullAccess` ⇒ admin (all buckets).
- **S3 sensitive** = name keywords (customer, pii, backup, prod, …) **or** a
  risky posture (unencrypted / public-access not fully blocked).

---

## Technologies

- **Python 3.9+**
- **networkx** — graph construction & traversal
- **Streamlit** — web UI
- **boto3** — live AWS integration
- **pyvis** — interactive graph visualization
- **plotly / pandas** — charts & tables
- **cryptography** — encrypted credential storage
- **SQLite** — scan-history persistence

## Roadmap
- Lambda, RDS, Security Group and VPC-peering nodes
- LocalStack-based integration tests
- Benchmarks vs. Prowler / ScoutSuite
