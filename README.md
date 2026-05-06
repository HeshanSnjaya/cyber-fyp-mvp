# Graph-Based Attack Path Analysis Tool

A prototype tool that detects compound AWS cloud security misconfigurations by constructing a directed graph of resource relationships and identifying reachable attack paths from the public Internet to sensitive data stores.

## Prerequisites

- Python 3.9 or higher

## Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd Cyber
```

2. Create a virtual environment:

```bash
python -m venv venv
```

3. Activate the virtual environment:

**Windows:**
```bash
.\venv\Scripts\activate
```

**macOS/Linux:**
```bash
source venv/bin/activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the analysis:

```bash
python main.py
```

Get JSON output:

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
