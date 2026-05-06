# Graph-Based Attack Path Analysis for Detecting Compound Cloud Security Misconfigurations

## Overview

Cloud misconfigurations account for up to 80% of data security breaches. Traditional tools like Prowler, ScoutSuite, and Checkov perform rule-based checks on individual resources but fail to detect compound risks — where multiple moderate misconfigurations chain together into exploitable attack paths.

For example, a publicly accessible EC2 instance assuming an overprivileged IAM role that has access to an unencrypted S3 bucket containing sensitive data. Each misconfiguration alone may seem low-risk, but chained together they form a critical vulnerability.

This tool addresses that gap by building a dependency graph from AWS resources and applying graph traversal algorithms to discover reachable attack paths from public exposure points to sensitive data stores.

## What It Does

1. **Scans AWS resources** — Loads resource data for EC2 instances, IAM roles, and S3 buckets (currently using mock data, designed for future real AWS integration)

2. **Builds a directed graph** — Constructs a networkx directed graph where:
   - Nodes represent: Internet entry point, EC2 instances, IAM roles, S3 buckets
   - Edges represent: public access (Internet → EC2), role assumption (EC2 → IAM Role), data access (IAM Role → S3)

3. **Detects attack paths** — Uses BFS-based traversal to find all simple paths from the "Internet" node to any S3 bucket marked as sensitive

4. **Scores and classifies risk** — Each path receives a severity score based on:
   - Public exposure (+5 points)
   - Sensitive data target (+5 points)
   - Short path / easy exploitation (+2 points)
   - Classified as HIGH (≥10), MEDIUM (≥7), or LOW (<7)

5. **Outputs findings** — Results are displayed via CLI with clear path visualization, or exported as structured JSON for automation

## Project Structure

```
Cyber/
├── main.py              # Main analysis tool
├── requirements.txt     # Python dependencies
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

## Key Functions

| Function | Purpose |
|----------|---------|
| `load_mock_data()` | Returns mock AWS resource data (replaceable with real scanner) |
| `build_graph()` | Constructs the directed resource dependency graph |
| `find_attack_paths()` | Finds all paths from Internet to sensitive S3 buckets |
| `score_path()` | Calculates risk score and severity for each path |
| `print_results()` | Formats and displays CLI output |
| `output_json()` | Outputs results as structured JSON |

## Prerequisites

- Python 3.9 or higher

## How to Run

### 1. Clone the repository

```bash
git clone <repository-url>
cd Cyber
```

### 2. Create and activate a virtual environment

**Windows:**
```bash
python -m venv venv
.\venv\Scripts\activate
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the tool

Standard CLI output:
```bash
python main.py
```

JSON output (for automation/integration):
```bash
python main.py --json
```

## Example Output

```
  Graph built: 12 nodes, 9 edges

============================================================
  GRAPH-BASED ATTACK PATH ANALYSIS RESULTS
============================================================

  Found 2 attack path(s):

  [CRITICAL] Attack Path #1
    Path:     Internet -> EC2-WebServer-1 -> Role-S3Admin -> S3-CustomerData
    Hops:     3
    Score:    12/12
    Severity: HIGH

  [CRITICAL] Attack Path #2
    Path:     Internet -> EC2-DevServer-3 -> Role-LambdaExec -> S3-BackupDB
    Hops:     3
    Score:    12/12
    Severity: HIGH

------------------------------------------------------------
  Summary: 2 path(s) detected
  HIGH: 2 | MEDIUM: 0 | LOW: 0
============================================================
```

## How It Works (Technical Flow)

```
Mock AWS Data → Graph Construction → BFS Path Detection → Risk Scoring → CLI/JSON Output
```

1. Resource data is loaded (EC2 with public/private flags, IAM roles with S3 permissions, S3 buckets with sensitivity flags)
2. A directed graph is built using networkx with edges representing access relationships
3. The tool identifies all sensitive S3 buckets as targets
4. For each target, BFS finds all simple (cycle-free) paths from the Internet node
5. Each discovered path is scored based on exposure, sensitivity, and path length
6. Results are presented with severity classification

## Technologies Used

- **Python** — Core language
- **networkx** — Graph construction and traversal algorithms

## Future Enhancements

- Real AWS integration using boto3
- Support for Lambda, RDS, and Security Groups
- Cytoscape.js dashboard for visual graph exploration
- LocalStack testing environment
- Comparison benchmarks against Prowler/ScoutSuite
