"""CloudPath — Graph-Based Cloud Attack Path Analyzer (Streamlit UI).

Run with:

    streamlit run app.py

Features
--------
* Switch between **Sample Data** (bundled JSON) and a **Live AWS** scan.
* Enter AWS keys in-app; they are encrypted and stored *inside the project*
  (never taken from the environment or ~/.aws).
* Interactive attack-graph visualization, CVSS v3.1 scoring, MITRE ATT&CK
  mapping, remediation guidance and downloadable reports.
* Every scan is saved to a local SQLite history with trend charts.
"""

from __future__ import annotations

import json
import io
import csv
from datetime import datetime

import pandas as pd
import streamlit as st

from core import analyzer, credentials, database
from core.data_sources import AWSDataSource
from core.data_sources.base import DataSourceError
from ui import graph_viz

# --------------------------------------------------------------------------- #
# Page config & styling
# --------------------------------------------------------------------------- #
st.set_page_config(
    page_title="CloudPath — Attack Path Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "NONE": "#22c55e",
}

st.markdown(
    """
    <style>
      .main .block-container {padding-top: 2rem; max-width: 1400px;}
      .cp-hero {
        background: linear-gradient(120deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155; border-radius: 16px;
        padding: 1.4rem 1.8rem; margin-bottom: 1.2rem;
      }
      .cp-hero h1 {margin: 0; font-size: 1.9rem; color: #f8fafc;}
      .cp-hero p {margin: .35rem 0 0; color: #94a3b8;}
      .sev-badge {
        display:inline-block; padding: .18rem .7rem; border-radius: 999px;
        color:#0b1120; font-weight:700; font-size:.8rem; letter-spacing:.03em;
      }
      .cp-pill {
        display:inline-block; padding:.15rem .6rem; border-radius:6px;
        background:#1e293b; border:1px solid #334155; color:#cbd5e1;
        font-size:.78rem; margin-right:.3rem; font-family:monospace;
      }
      .cp-card {
        background:#0f172a; border:1px solid #334155; border-radius:12px;
        padding:1rem 1.2rem; margin-bottom:.8rem;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------------- #
def _init_state():
    st.session_state.setdefault("result", None)
    st.session_state.setdefault("view_scan_id", None)
    st.session_state.setdefault("aws_conn_msg", None)


_init_state()
database.init_db()


# --------------------------------------------------------------------------- #
# Sidebar — data source control
# --------------------------------------------------------------------------- #
def sidebar():
    st.sidebar.markdown("## ⚙️ Analysis Configuration")
    mode_label = st.sidebar.radio(
        "Data source",
        ["🧪 Sample Data (offline)", "☁️ Live AWS Account"],
        help="Switch between the bundled demo dataset and a real AWS scan.",
    )
    mode = "aws" if "AWS" in mode_label else "json"

    aws_kwargs = {}
    if mode == "aws":
        aws_kwargs = _aws_controls()

    st.sidebar.divider()
    run = st.sidebar.button("🚀 Run Analysis", type="primary", use_container_width=True)
    st.sidebar.caption(
        "Sample mode uses `mock_data.json`. AWS mode uses only the keys you save "
        "here — never your environment or ~/.aws credentials."
    )
    return mode, aws_kwargs, run


def _aws_controls():
    st.sidebar.markdown("### 🔐 AWS Credentials")
    if not credentials.is_encryption_available():
        st.sidebar.warning(
            "`cryptography` not installed — credentials will be stored obfuscated, "
            "not encrypted. Run `pip install cryptography`."
        )

    saved = credentials.load_credentials()
    if saved:
        st.sidebar.success(
            f"Saved key: `{credentials.masked_access_key()}`  \n"
            f"Region: `{saved.get('region')}`"
        )

    with st.sidebar.expander("Enter / update keys", expanded=not saved):
        access_key = st.text_input("AWS Access Key ID", type="password")
        secret_key = st.text_input("AWS Secret Access Key", type="password")
        session_token = st.text_input("Session Token (optional)", type="password")
        region = st.text_input("Region", value=(saved or {}).get("region", "us-east-1"))
        c1, c2 = st.columns(2)
        if c1.button("💾 Save", use_container_width=True):
            if access_key and secret_key:
                credentials.save_credentials(access_key, secret_key, region, session_token)
                st.sidebar.success("Credentials saved to project (.secrets/).")
                st.rerun()
            else:
                st.sidebar.error("Access key and secret are required.")
        if c2.button("🗑️ Clear", use_container_width=True):
            credentials.clear_credentials()
            st.sidebar.info("Saved credentials cleared.")
            st.rerun()

    saved = credentials.load_credentials()
    if saved and st.sidebar.button("🔌 Test Connection", use_container_width=True):
        try:
            src = AWSDataSource(
                aws_access_key_id=saved["aws_access_key_id"],
                aws_secret_access_key=saved["aws_secret_access_key"],
                region=saved.get("region", "us-east-1"),
                aws_session_token=saved.get("aws_session_token"),
            )
            ok, msg = src.test_connection()
            st.session_state.aws_conn_msg = (ok, msg)
        except DataSourceError as exc:
            st.session_state.aws_conn_msg = (False, str(exc))

    if st.session_state.aws_conn_msg:
        ok, msg = st.session_state.aws_conn_msg
        (st.sidebar.success if ok else st.sidebar.error)(msg)

    if not saved:
        return None  # signal: no creds yet
    return {
        "aws_access_key_id": saved["aws_access_key_id"],
        "aws_secret_access_key": saved["aws_secret_access_key"],
        "region": saved.get("region", "us-east-1"),
        "aws_session_token": saved.get("aws_session_token"),
    }


# --------------------------------------------------------------------------- #
# Analysis runner
# --------------------------------------------------------------------------- #
def run_analysis(mode, aws_kwargs):
    if mode == "aws" and not aws_kwargs:
        st.error("Please enter and save AWS credentials before running a live scan.")
        return

    progress_bar = st.progress(0.0, text="Starting analysis…")

    def on_progress(fraction, message):
        progress_bar.progress(min(1.0, max(0.0, fraction)), text=message)

    try:
        result = analyzer.run_analysis(
            mode=mode, progress=on_progress, **(aws_kwargs or {})
        )
    except DataSourceError as exc:
        progress_bar.empty()
        st.error(f"Data source error: {exc}")
        return
    except Exception as exc:  # pragma: no cover - surface unexpected errors
        progress_bar.empty()
        st.exception(exc)
        return

    progress_bar.empty()
    scan_id = database.save_scan(result)
    result["meta"]["scan_id"] = scan_id
    st.session_state.result = result
    st.session_state.view_scan_id = None
    st.toast(f"Analysis complete — scan #{scan_id} saved to history.", icon="✅")


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
def sev_badge(severity):
    color = SEVERITY_COLORS.get(severity, "#94a3b8")
    return f'<span class="sev-badge" style="background:{color}">{severity}</span>'


def render_summary(result):
    s = result["summary"]
    meta = result["meta"]
    gs = result["graph_stats"]

    st.markdown(
        f"""
        <div class="cp-hero">
          <h1>🛡️ Cloud Attack Path Analysis</h1>
          <p>Source: <b>{meta['source_label']}</b>
          {f"· Account <b>{meta['account_id']}</b>" if meta.get('account_id') else ""}
          {f"· Region <b>{meta['region']}</b>" if meta.get('region') else ""}
          · {gs['nodes']} nodes / {gs['edges']} edges</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Attack Paths", s["total_paths"])
    c2.metric("🔴 Critical", s["critical"])
    c3.metric("🟠 High", s["high"])
    c4.metric("🟡 Medium", s["medium"])
    c5.metric("Max CVSS", f"{s['max_cvss']:.1f}")


def render_charts(result):
    findings = result["findings"]
    if not findings:
        return
    col1, col2 = st.columns([1, 1])

    sev_counts = {k: result["summary"][k.lower()] for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    df_sev = pd.DataFrame(
        {"Severity": list(sev_counts.keys()), "Count": list(sev_counts.values())}
    )
    try:
        import plotly.express as px

        fig = px.pie(
            df_sev, names="Severity", values="Count", hole=0.55,
            color="Severity", color_discrete_map=SEVERITY_COLORS,
            title="Findings by severity",
        )
        fig.update_layout(template="plotly_dark", height=320, margin=dict(t=50, b=10))
        col1.plotly_chart(fig, use_container_width=True)

        df_paths = pd.DataFrame(
            [{"Path": f"#{f['rank']}", "CVSS": f["cvss_score"], "Severity": f["severity"]}
             for f in findings]
        )
        fig2 = px.bar(
            df_paths, x="Path", y="CVSS", color="Severity",
            color_discrete_map=SEVERITY_COLORS, title="CVSS score per attack path",
            range_y=[0, 10],
        )
        fig2.update_layout(template="plotly_dark", height=320, margin=dict(t=50, b=10))
        col2.plotly_chart(fig2, use_container_width=True)
    except Exception:
        col1.bar_chart(df_sev.set_index("Severity"))


def render_graph(result):
    st.markdown("### 🕸️ Interactive Attack Graph")
    legend = "  ".join(
        f'<span class="cp-pill" style="border-color:{c}">● {label}</span>'
        for label, c in graph_viz.legend_items()
    )
    st.markdown(legend, unsafe_allow_html=True)
    html = graph_viz.render_attack_graph(result)
    if html:
        st.components.v1.html(html, height=620, scrolling=False)
    else:
        st.info("Install `pyvis` to see the interactive graph: `pip install pyvis`.")


def render_findings(result):
    findings = result["findings"]
    st.markdown("### 🎯 Attack Paths & Threat Details")
    if not findings:
        st.success(
            "No attack paths detected — all sensitive resources appear properly "
            "isolated from public exposure."
        )
        return

    for f in findings:
        header = (
            f"#{f['rank']} · {f['severity']} · CVSS {f['cvss_score']:.1f} · "
            f"{f['path_string']}"
        )
        with st.expander(header, expanded=(f["rank"] == 1)):
            st.markdown(sev_badge(f["severity"]), unsafe_allow_html=True)
            st.markdown(f"**Path:** `{f['path_string']}`  ·  **Hops:** {f['hops']}")
            st.markdown(f['intel']['narrative'])

            tabs = st.tabs(["🧭 Kill chain", "🎯 MITRE ATT&CK", "📊 CVSS", "🛠️ Remediation", "💥 Impact"])

            with tabs[0]:
                for i, hop in enumerate(f["intel"]["hops"], 1):
                    st.markdown(
                        f"**Step {i}: {hop['source']} → {hop['target']}** "
                        f"`{hop['relation']}`"
                    )
                    st.markdown(hop["explanation"])

            with tabs[1]:
                for t in f["intel"]["mitre"]:
                    st.markdown(
                        f"- **[{t['id']}]({t['url']}) {t['name']}** — *{t['tactic']}*"
                    )
                if not f["intel"]["mitre"]:
                    st.caption("No techniques mapped.")

            with tabs[2]:
                st.markdown(f"**Vector:** `{f['cvss_vector']}`")
                df = pd.DataFrame(
                    f["metric_explanation"], columns=["Metric", "Value", "Meaning"]
                )
                st.dataframe(df, use_container_width=True, hide_index=True)

            with tabs[3]:
                for r in f["intel"]["remediation"]:
                    st.markdown(f"**{r['resource']} — {r['title']}**")
                    st.caption(r["detail"])

            with tabs[4]:
                st.markdown(f["intel"]["business_impact"])


def render_inventory(result):
    st.markdown("### 📦 Resource Inventory")
    res = result["resources"]
    t1, t2, t3 = st.tabs(
        [f"EC2 ({len(res['ec2'])})", f"IAM Roles ({len(res['iam_roles'])})", f"S3 ({len(res['s3'])})"]
    )
    with t1:
        st.dataframe(pd.DataFrame(res["ec2"]), use_container_width=True, hide_index=True)
    with t2:
        df = pd.DataFrame(res["iam_roles"])
        if "s3_access" in df:
            df["s3_access"] = df["s3_access"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
        st.dataframe(df, use_container_width=True, hide_index=True)
    with t3:
        st.dataframe(pd.DataFrame(res["s3"]), use_container_width=True, hide_index=True)


def render_downloads(result):
    st.markdown("### ⬇️ Export Report")
    c1, c2 = st.columns(2)
    json_bytes = json.dumps(result, indent=2, default=str).encode("utf-8")
    c1.download_button(
        "Download JSON report", json_bytes,
        file_name=f"attack_paths_{datetime.now():%Y%m%d_%H%M%S}.json",
        mime="application/json", use_container_width=True,
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["rank", "severity", "cvss", "hops", "path", "vector"])
    for f in result["findings"]:
        writer.writerow([
            f["rank"], f["severity"], f["cvss_score"], f["hops"],
            f["path_string"], f["cvss_vector"],
        ])
    c2.download_button(
        "Download CSV summary", buf.getvalue().encode("utf-8"),
        file_name=f"attack_paths_{datetime.now():%Y%m%d_%H%M%S}.csv",
        mime="text/csv", use_container_width=True,
    )


# --------------------------------------------------------------------------- #
# History tab
# --------------------------------------------------------------------------- #
def render_history():
    st.markdown("### 🗂️ Scan History")
    scans = database.list_scans()
    if not scans:
        st.info("No scans recorded yet. Run an analysis to populate history.")
        return

    df = pd.DataFrame(scans)
    st.dataframe(df, use_container_width=True, hide_index=True)

    try:
        import plotly.express as px

        trend = df.sort_values("id")
        fig = px.line(
            trend, x="timestamp", y="max_cvss", markers=True,
            title="Max CVSS over time", range_y=[0, 10],
        )
        fig.update_layout(template="plotly_dark", height=300)
        st.plotly_chart(fig, use_container_width=True)
    except Exception:
        pass

    c1, c2 = st.columns([2, 1])
    scan_id = c1.number_input(
        "Load scan #", min_value=int(df["id"].min()),
        max_value=int(df["id"].max()), value=int(df["id"].max()), step=1,
    )
    if c1.button("📂 Load selected scan"):
        stored = database.get_scan(int(scan_id))
        if stored:
            st.session_state.result = stored
            st.toast(f"Loaded scan #{scan_id}.", icon="📂")
            st.rerun()
    if c2.button("🗑️ Clear all history"):
        database.clear_history()
        st.rerun()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    mode, aws_kwargs, run = sidebar()

    if run:
        run_analysis(mode, aws_kwargs)

    tab_results, tab_history, tab_about = st.tabs(
        ["📊 Results", "🗂️ History", "ℹ️ About"]
    )

    with tab_results:
        result = st.session_state.result
        if not result:
            st.markdown(
                """
                <div class="cp-hero">
                  <h1>🛡️ CloudPath — Attack Path Analyzer</h1>
                  <p>Detect compound cloud misconfigurations by chaining public
                  exposure → IAM privilege → sensitive data into scored attack
                  paths. Configure a source in the sidebar and click
                  <b>Run Analysis</b>.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.info("👈 Choose **Sample Data** for an instant demo, or **Live AWS** to scan a real account.")
            return

        render_summary(result)
        render_charts(result)
        render_graph(result)
        render_findings(result)
        render_inventory(result)
        render_downloads(result)

    with tab_history:
        render_history()

    with tab_about:
        render_about()


def render_about():
    st.markdown(
        """
        ### About CloudPath
        **Graph-Based Attack Path Analysis for Detecting Compound Cloud Security
        Misconfigurations.**

        Traditional scanners (Prowler, ScoutSuite, Checkov) flag individual
        misconfigurations. CloudPath instead models your account as a directed
        graph and finds *chains* — e.g. a public EC2 → an over-privileged IAM
        role → a sensitive, unencrypted S3 bucket — that together form a
        critical, exploitable path.

        **Pipeline**

        `Data source → Dependency graph → Attack-path search → CVSS v3.1 scoring
        → Threat intel (MITRE ATT&CK + remediation) → Report + history`

        **Two modes**
        - 🧪 **Sample Data** — bundled `mock_data.json`, fully offline.
        - ☁️ **Live AWS** — real EC2 / IAM / S3 scan via boto3 using keys you
          save in-app (encrypted under `.secrets/`, never from the environment).

        Scoring uses a spec-accurate CVSS v3.1 implementation, so vectors match
        public calculators.
        """
    )


if __name__ == "__main__":
    main()
