# Setup Guide — Run CloudPath after cloning

Follow these steps to run the project on a fresh laptop after cloning the
repository. Works on **Windows, macOS and Linux**.

---

## Prerequisites

- **Python 3.9+** (developed on 3.10). Check with:
  ```bash
  python --version
  ```
- **git**
- (Only for Live AWS mode) an AWS account + read-only access keys.

> You do **not** need an AWS account to try the app — the bundled **Sample
> Data** mode runs fully offline.

---

## 1. Clone the repository

```bash
git clone <your-repository-url>
cd cyber-fyp-mvp
```

## 2. Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
> If PowerShell blocks activation, run once:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

**Windows (Command Prompt):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

Your prompt should now start with `(venv)`.

## 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs: `streamlit`, `networkx`, `boto3`, `pandas`, `plotly`,
`cryptography`.

## 4. Run the web app

```bash
streamlit run app.py
```

Your browser opens at **http://localhost:8501**. In the sidebar:

- **🧪 Sample Data (offline)** — click **Run Analysis** for an instant demo.
- **☁️ Live AWS Account** — enter your AWS keys, **Save**, **Test Connection**,
  then **Run Analysis** (see below).

Stop the app with **Ctrl+C** in the terminal.

## 5. (Optional) Run the command-line version

```bash
python main.py            # sample data, readable output
python main.py --json     # sample data, JSON output
python main.py --aws      # live AWS scan (uses saved keys)
```

---

## Using Live AWS mode

1. Create a **read-only** IAM user in AWS and attach the managed policy
   **`SecurityAudit`** (or `ReadOnlyAccess`). Create an access key for it.
2. In the app sidebar, switch to **Live AWS Account**, expand
   **Enter / update keys**, paste the **Access Key ID** + **Secret Access Key**,
   set the **Region**, and click **Save**.
3. Keys are encrypted and stored locally under `.secrets/` (git-ignored — they
   are never committed and never read from your environment or `~/.aws`).
4. Click **Test Connection**, then **Run Analysis**.

> A brand-new AWS account will report **0 attack paths** because it has nothing
> misconfigured. To demonstrate a real finding you need a deliberately
> vulnerable resource set (public EC2 → over-privileged IAM role → sensitive S3
> bucket). Build it only in a throwaway account and delete it afterwards.

---

## What is NOT in the repository (created locally on first use)

| Path | Purpose | Committed? |
|------|---------|-----------|
| `venv/` | Your virtual environment | No — recreate with step 2 |
| `.secrets/` | Encrypted AWS keys | No — you enter your own |
| `scan_history.db` | SQLite scan history | No — created on first scan |

These are intentionally git-ignored. Everything needed to run is in the repo.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `python: command not found` | Use `python3`, or install Python 3.9+. |
| PowerShell won't activate venv | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` then retry. |
| `streamlit: command not found` | Activate the venv first (step 2), then reinstall (step 3). |
| Port 8501 in use | `streamlit run app.py --server.port 8600` |
| Attack graph doesn't show | It uses Streamlit's built-in Graphviz renderer; just refresh the page. |
| `pip install` fails on a package | Upgrade pip first: `pip install --upgrade pip`. |
