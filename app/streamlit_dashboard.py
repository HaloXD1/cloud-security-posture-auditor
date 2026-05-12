from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from cloud_audit.bootstrap import ensure_demo_outputs

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "data" / "exports"


@st.cache_data
def load_csv(name: str) -> pd.DataFrame:
    return pd.read_csv(EXPORTS / name)


st.set_page_config(page_title="Cloud Security Posture Auditor", layout="wide")
generated = ensure_demo_outputs()
if generated:
    st.toast("Synthetic security snapshots prepared")

findings = load_csv("findings.csv")
summary = load_csv("risk_summary.csv")
scorecard = load_csv("account_scorecard.csv")

st.title("Cloud Security Posture Auditor")
st.caption("Offline AWS-style security scanner for IAM, storage, network exposure, encryption, and logging gaps.")

tab_exec, tab_critical, tab_iam, tab_network, tab_storage, tab_logging, tab_remediation = st.tabs(
    [
        "Executive Risk Summary",
        "Critical Findings",
        "IAM",
        "Network Exposure",
        "Storage Security",
        "Logging and Detection",
        "Remediation Tracker",
    ]
)

with tab_exec:
    cols = st.columns(4)
    cols[0].metric("Findings", f"{len(findings):,}")
    cols[1].metric("Critical", f"{int((findings['severity'] == 'critical').sum()):,}")
    cols[2].metric("High", f"{int((findings['severity'] == 'high').sum()):,}")
    cols[3].metric("Lowest Score", f"{scorecard['security_score'].min():.1f}")
    left, right = st.columns(2)
    with left:
        st.plotly_chart(px.bar(summary, x="severity", y="finding_count", color="severity"), width="stretch")
    with right:
        st.plotly_chart(px.bar(scorecard, x="environment", y="security_score", color="account_id"), width="stretch")
    st.dataframe(scorecard, width="stretch", hide_index=True)

with tab_critical:
    critical = findings[findings["severity"].isin(["critical", "high"])]
    st.plotly_chart(px.histogram(critical, x="rule_id", color="severity"), width="stretch")
    st.dataframe(critical, width="stretch", hide_index=True)

with tab_iam:
    iam = findings[findings["compliance_tag"].str.lower() == "iam"]
    st.plotly_chart(px.histogram(iam, x="rule_id", color="severity"), width="stretch")
    st.dataframe(iam, width="stretch", hide_index=True)

with tab_network:
    network = findings[findings["compliance_tag"].str.lower() == "network"]
    st.plotly_chart(px.histogram(network, x="resource_type", color="severity"), width="stretch")
    st.dataframe(network, width="stretch", hide_index=True)

with tab_storage:
    storage = findings[findings["compliance_tag"].str.lower().isin(["storage", "encryption"])]
    st.plotly_chart(px.histogram(storage, x="resource_type", color="severity"), width="stretch")
    st.dataframe(storage, width="stretch", hide_index=True)

with tab_logging:
    logging = findings[findings["compliance_tag"].str.lower() == "logging"]
    st.plotly_chart(px.histogram(logging, x="rule_id", color="severity"), width="stretch")
    st.dataframe(logging, width="stretch", hide_index=True)

with tab_remediation:
    selected = st.multiselect(
        "Severity",
        ["critical", "high", "medium", "low"],
        default=["critical", "high", "medium"],
    )
    view = findings[findings["severity"].isin(selected)]
    st.dataframe(
        view[["severity", "resource_type", "resource_id", "rule_id", "remediation"]],
        width="stretch",
        hide_index=True,
    )
