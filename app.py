from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import PurePosixPath

import pandas as pd
import streamlit as st

from reporeality.analyzer import RepoArchiveError, analyze_repository, summarize_claims

st.set_page_config(page_title="RepoReality · Documentation integrity", page_icon="◈", layout="wide")

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&display=swap');
    :root { --bg:#080e19; --panel:#101a2a; --border:#1d2b40; --muted:#8696ad; --text:#e8eff8; --blue:#4c8dff; --cyan:#47d8d0; }
    .stApp { background: radial-gradient(ellipse at 55% -20%, #142746 0, var(--bg) 53%); color:var(--text); font-family:'DM Sans',sans-serif; }
    [data-testid="stSidebar"] { background:#0b1321; border-right:1px solid var(--border); }
    [data-testid="stSidebar"] * { color:var(--text); }
    .block-container { max-width:1440px; padding-top:2rem; padding-bottom:3rem; }
    .eyebrow { color:var(--cyan); font-family:'DM Mono',monospace; font-size:.72rem; letter-spacing:.16em; text-transform:uppercase; }
    .hero { font-size:2.65rem; line-height:1.15; font-weight:700; letter-spacing:-.045em; margin:.4rem 0 .6rem; }
    .hero span { color:var(--cyan); }
    .subhead { color:var(--muted); font-size:1rem; max-width:680px; }
    .metric-card { background:linear-gradient(145deg,#111e31,#0e1726); border:1px solid var(--border); border-radius:13px; padding:1.15rem 1.25rem; min-height:112px; }
    .metric-label { color:var(--muted); font-size:.77rem; text-transform:uppercase; letter-spacing:.1em; }
    .metric-value { font-size:2rem; font-weight:700; margin-top:.15rem; color:var(--text); }
    .metric-accent { color:var(--cyan); } .metric-fail { color:#ff7085; } .metric-warn { color:#f7c96b; }
    .section-title { font-weight:600; font-size:1.2rem; }
    .repo-chip { border:1px solid #253a56; border-radius:999px; color:#b8c8dc; padding:.35rem .65rem; font-family:'DM Mono',monospace; font-size:.78rem; display:inline-block; margin-top:.6rem; }
    .stButton > button, .stDownloadButton > button { border-radius:8px; border:1px solid #315b91; background:#142b48; color:#eaf4ff; font-weight:600; }
    .stButton > button:hover, .stDownloadButton > button:hover { background:#1b3b62; border-color:var(--blue); color:white; }
    div[data-testid="stDataFrame"] { border:1px solid var(--border); border-radius:10px; overflow:hidden; }
    .note { color:var(--muted); font-size:.83rem; line-height:1.5; }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("<div class='eyebrow'>◈ REPOREALITY</div>", unsafe_allow_html=True)
    st.markdown("### Repository check")
    st.write("Inspect README claims against the files in a repository archive.")
    uploaded = st.file_uploader("Upload repository ZIP", type=["zip"], help="The archive is inspected in memory. Repository code and commands are never executed.")
    st.markdown("---")
    st.markdown("**Checks included**")
    st.markdown("- Documented file paths\n- Common install commands\n- Declared dependencies\n- Configuration variables")
    st.markdown("---")
    st.markdown("<div class='note'>Private by design · no API keys · uploaded code is never run</div>", unsafe_allow_html=True)

st.markdown("<div class='eyebrow'>DOCUMENTATION INTEGRITY / 01</div>", unsafe_allow_html=True)
st.markdown("<div class='hero'>Trust what your README <span>promises.</span></div>", unsafe_allow_html=True)
st.markdown("<div class='subhead'>A deterministic documentation check that compares repository claims with the files that actually ship.</div>", unsafe_allow_html=True)
st.write("")

if uploaded is None:
    st.info("Upload a repository ZIP from the sidebar to begin an analysis.")
    st.markdown(
        """
        <div class="metric-card">
          <div class="section-title">Evidence, not guesswork</div>
          <div class="note" style="margin-top:.5rem">RepoReality reads README.md and supported text files from your archive. It verifies only claims it can check deterministically and labels uncertain checks clearly.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

try:
    analysis = analyze_repository(uploaded.getvalue(), PurePosixPath(uploaded.name).stem)
except RepoArchiveError as error:
    st.error(str(error))
    st.stop()

st.markdown(f"<span class='repo-chip'>◉ &nbsp;{analysis.repository_name}</span>", unsafe_allow_html=True)
st.write("")
if analysis.readme_path is None:
    st.warning("No README.md was found. The archive is valid, but there are no documentation claims to verify.")
    st.caption(f"Enumerated {len(analysis.files)} archive files.")
    st.stop()

summary = summarize_claims(analysis.claims)
columns = st.columns(4)
metrics = [
    ("CLAIMS CHECKED", summary["total"], ""),
    ("VERIFIED", summary["verified"], "metric-accent"),
    ("FAILED", summary["failed"], "metric-fail"),
    ("UNVERIFIED", summary["unverified"], "metric-warn"),
]
for column, (label, value, accent) in zip(columns, metrics):
    column.markdown(f"<div class='metric-card'><div class='metric-label'>{label}</div><div class='metric-value {accent}'>{value}</div></div>", unsafe_allow_html=True)

st.write("")
header, export = st.columns([4, 1])
header.markdown("<div class='section-title'>Analysis results</div>", unsafe_allow_html=True)
header.caption(f"README source: `{analysis.readme_path}` · {len(analysis.files)} archive files enumerated")
report = {
    "repository": analysis.repository_name,
    "readme": analysis.readme_path,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "summary": summary,
    "claims": [claim.to_dict() for claim in analysis.claims],
}
export.download_button(
    "↓  Export report",
    data=json.dumps(report, indent=2),
    file_name=f"{analysis.repository_name}-reporeality-report.json",
    mime="application/json",
    use_container_width=True,
)

if not analysis.claims:
    st.success("README found. No supported file-path, installation, dependency, or configuration claims were detected.")
else:
    rows = []
    for claim in analysis.claims:
        rows.append({
            "Status": claim.status,
            "Claim type": claim.kind,
            "README claim": claim.claim,
            "Line": claim.line,
            "Evidence": claim.evidence,
            "Evidence-backed suggestion": claim.correction or "—",
        })
    dataframe = pd.DataFrame(rows)
    st.dataframe(
        dataframe,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Status": st.column_config.TextColumn(width="small"),
            "Claim type": st.column_config.TextColumn(width="medium"),
            "README claim": st.column_config.TextColumn(width="medium"),
            "Line": st.column_config.NumberColumn(width="small"),
            "Evidence": st.column_config.TextColumn(width="large"),
            "Evidence-backed suggestion": st.column_config.TextColumn(width="large"),
        },
    )
    with st.expander("What these statuses mean"):
        st.markdown("- **Verified** — supporting evidence was found in the archive.\n- **Failed** — a supported deterministic check found contradictory or missing evidence.\n- **Unverified** — the claim could not be checked reliably by the available rules.")
