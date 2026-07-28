"""Streamlit front end for the IaC remediation loop.

A thin view over `iac_agent`. All policy — scanning, gating, stopping, best-so-far — lives in
the package; this file only collects a file, runs the loop, and renders the result.

It previously imported `detect_vulnerabilities`, `generate_fix` and `validate_with_checkov`
from a top-level `main.py` that also owned the orchestration, the prompts and a second,
divergent copy of the JSON parser. That module has been removed; the submitted version of it
remains in git history at the import commit.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from iac_agent.llm import LLMClient, ModelConfig
from iac_agent.loop import StopReason, run_loop
from iac_agent.scanners import get_scanner
from iac_agent.types import IaCAgentError, ScannerError, detect_iac_type

st.set_page_config(page_title="IaC security — detect, fix, verify", page_icon="🔒", layout="wide")

SEVERITY_COLOURS = {
    "critical": "background-color:#7f1d1d; color:white; font-weight:600;",
    "high": "background-color:#b91c1c; color:white;",
    "medium": "background-color:#fef3c7; color:#92400e;",
    "low": "background-color:#dcfce7; color:#166534;",
}

STOP_EXPLANATIONS = {
    StopReason.CONVERGED: "No findings remain.",
    StopReason.MAX_ITERS: "Hit the iteration cap with findings still outstanding.",
    StopReason.NO_PROGRESS: "An iteration failed to improve on the best result, so the loop "
    "stopped rather than burn tokens oscillating.",
    StopReason.TOKEN_BUDGET: "Token budget reached.",
}


def _severity_style(value: object) -> str:
    return SEVERITY_COLOURS.get(str(value).lower(), "")


st.title("🔒 Infrastructure-as-Code security")
st.caption(
    "Detect misconfigurations, rewrite them, and verify the rewrite actually fixed something — "
    "including whether a resource was quietly deleted instead of secured."
)

uploaded = st.file_uploader("Terraform (.tf) or Dockerfile", type=["tf", "Dockerfile"])

if uploaded is None:
    st.info("Upload a file to begin. `samples/` in this repo contains deliberately vulnerable ones.")
    st.stop()

code = uploaded.read().decode("utf-8")

try:
    iac_type = detect_iac_type(uploaded.name)
except IaCAgentError as exc:
    st.error(str(exc))
    st.stop()

language = "docker" if iac_type.value == "dockerfile" else "hcl"
with st.expander(f"Uploaded — {uploaded.name} ({iac_type.value})", expanded=False):
    st.code(code, language=language)

col_scan, col_fix = st.columns(2)
scan_only = col_scan.button("Scan only — no API key needed", use_container_width=True)
run_fix = col_fix.button("Scan, fix and verify", type="primary", use_container_width=True)

if not (scan_only or run_fix):
    st.stop()

# The uploaded file must reach the scanner under a name that implies its type: both Checkov
# and Trivy select their Dockerfile rulesets by filename, so writing a Dockerfile to a .tf
# path makes it scan clean against Terraform rules.
workdir = Path(tempfile.mkdtemp())
target = workdir / ("Dockerfile" if iac_type.value == "dockerfile" else uploaded.name)
target.write_text(code)

if scan_only:
    try:
        result = get_scanner("checkov").scan(target, iac_type)
    except ScannerError as exc:
        st.error(f"The scanner could not run, so this file has **not** been checked.\n\n{exc}")
        st.stop()

    st.metric("Findings", result.failed_count)
    if result.failed:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "rule": f.rule_id,
                        "severity": f.severity,
                        "resource": f.resource,
                        "finding": f.message,
                    }
                    for f in result.failed
                ]
            ).style.map(_severity_style, subset=["severity"]),
            use_container_width=True,
        )
    else:
        st.success("No findings.")
    st.stop()

# --- full loop -------------------------------------------------------------------------

with st.status("Running detect → fix → verify → refine…", expanded=True) as status:
    try:
        result = run_loop(
            target,
            scanner="checkov",
            client=LLMClient(),
            cfg=ModelConfig(),
            max_iters=3,
            output_dir=workdir,
        )
    except ScannerError as exc:
        status.update(label="Scanner failure", state="error")
        st.error(f"The scanner could not run, so nothing was verified.\n\n{exc}")
        st.stop()
    except IaCAgentError as exc:
        status.update(label="Failed", state="error")
        st.error(str(exc))
        st.stop()
    status.update(label=f"Done — {result.stop_reason.name}", state="complete")

before, after = result.baseline.failed_count, (
    result.best.scan.failed_count if result.best and result.best.scan else before
)

a, b, c = st.columns(3)
a.metric("Findings before", before)
b.metric("Findings after", after, delta=after - before, delta_color="inverse")
c.metric("Iterations", len(result.iterations))
st.caption(f"**{result.stop_reason.name}** — {STOP_EXPLANATIONS.get(result.stop_reason, '')}")

# Drift is surfaced prominently and before the diff: a run that lowered the finding count by
# deleting the offending resource looks like a success in every other number on this page.
rejected_for_drift = [r for r in result.iterations if "drift" in (r.rejected_because or "")]
if rejected_for_drift:
    st.warning(
        "**A proposed fix was rejected for removing a resource that carried a finding.** "
        "Deleting a resource makes its findings disappear without securing anything, so the "
        "candidate was discarded rather than scored.\n\n"
        + "\n".join(f"- iteration {r.index}: `{r.rejected_because}`" for r in rejected_for_drift)
    )

if after >= before:
    st.info("No candidate improved on the original, so the original file is returned unchanged.")

st.subheader("Original vs remediated")
left, right = st.columns(2)
left.caption("Original")
left.code(code, language=language)
right.caption("Remediated")
right.code(result.best.code if result.best else code, language=language)

with st.expander("Per-iteration detail"):
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "iteration": r.index,
                    "accepted": r.accepted,
                    "findings": r.scan.failed_count if r.scan else None,
                    "rejected because": r.rejected_because or "",
                    "tokens": r.total_tokens,
                }
                for r in result.iterations
            ]
        ),
        use_container_width=True,
    )

st.download_button(
    "Download JSON report",
    data=json.dumps(
        {
            "target": uploaded.name,
            "iac_type": iac_type.value,
            "scanner": result.scanner,
            "before": before,
            "after": after,
            "stop_reason": result.stop_reason.name,
            "total_tokens": result.total_tokens,
            "iterations": [
                {
                    "index": r.index,
                    "accepted": r.accepted,
                    "findings": r.scan.failed_count if r.scan else None,
                    "rejected_because": r.rejected_because,
                }
                for r in result.iterations
            ],
        },
        indent=2,
    ),
    file_name="iac_security_report.json",
    mime="application/json",
)
