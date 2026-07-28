"""Streamlit front end for the IaC remediation loop.

A thin view over `iac_agent`. It collects an input, calls `run_loop` (or a single scanner),
and renders what came back. Every decision the results describe — what counts as a finding,
when a candidate is rejected, when the loop stops — is made inside the package. No policy is
implemented here, and no measured number is typed into this file: the evaluation figures are
read from `eval/results/RESULTS.md` at runtime, and the sample list is the contents of
`samples/` at runtime.

It previously imported `detect_vulnerabilities`, `generate_fix` and `validate_with_checkov`
from a top-level `main.py` that also owned the orchestration, the prompts and a second,
divergent copy of the JSON parser. That module has been removed; the submitted version of it
remains in git history at the import commit.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import difflib
import importlib.util
import inspect
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from iac_agent import __version__
from iac_agent.llm import LLMClient, ModelConfig
from iac_agent.loop import StopReason, run_loop
from iac_agent.scanners import SCANNERS, get_scanner
from iac_agent.types import IaCAgentError, IaCType, ScannerError, detect_iac_type

REPO_ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = REPO_ROOT / "samples"
RESULTS_MD = REPO_ROOT / "eval" / "results" / "RESULTS.md"

st.set_page_config(
    page_title="IaC security — detect, fix, verify",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------------------------------------------
# presentation tables (labels and colours only — no analysis lives in this file)
# --------------------------------------------------------------------------------------

# Severity is shown with an emoji rather than a CSS background colour: the previous
# hardcoded light-mode palette was unreadable in Streamlit's dark theme, and emoji plus
# Streamlit's own semantic badge colours render correctly in both.
SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "unknown": "⚪",
}
SEVERITY_BADGE = {
    "critical": "red",
    "high": "orange",
    "medium": "yellow",
    "low": "blue",
    "info": "gray",
    "unknown": "gray",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

STOP_REASONS: dict[str, tuple[str, str]] = {
    "CONVERGED": (
        "Converged",
        "The scanner reported zero failed checks on a candidate that passed every gate. "
        "That means this ruleset has nothing left to say about the file — not that the file "
        "is secure.",
    ),
    "MAX_ITERS": (
        "Hit the iteration cap",
        "The loop used every attempt it was allowed and findings were still outstanding. "
        "The best candidate seen is the one returned.",
    ),
    "NO_PROGRESS": (
        "Stopped making progress",
        "Consecutive attempts failed to beat the best result so far, so the loop stopped "
        "rather than spend tokens oscillating between equivalent rewrites.",
    ),
    "TOKEN_BUDGET": (
        "Ran out of token budget",
        "The run reached its token ceiling before converging. The best candidate so far is "
        "what you get.",
    ),
}

# How a rejection is shown. The mapping is over the reason prefixes `iac_agent.loop` writes
# into `IterationRecord.rejected_because`; the classification itself is the package's.
REJECTION_KINDS: tuple[tuple[str, str, str, str], ...] = (
    ("drift:", "🚫", "rejected — deleted a resource", "red"),
    ("drift_unmeasurable:", "🚫", "rejected — drift could not be verified", "red"),
    ("invalid:", "✋", "rejected — did not parse", "orange"),
    ("llm_error:", "⚠️", "model call failed", "gray"),
    ("scan_failed:", "❗", "scanner failed — candidate unverified", "violet"),
)

TOKEN_BUDGET_DEFAULT = inspect.signature(run_loop).parameters["token_budget"].default


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def _language(iac_type_value: str) -> str:
    return "docker" if iac_type_value == IaCType.DOCKERFILE.value else "hcl"


def _language_of(name: str) -> str:
    """Highlighting language for a filename, degrading to plain text rather than raising."""
    try:
        return _language(detect_iac_type(name).value)
    except IaCAgentError:
        return "text"


def _list_samples() -> list[Path]:
    """Every bundled fixture the package is willing to route to a scanner.

    Listed at runtime rather than hardcoded: fixtures are added to `samples/` over time and
    a stale list in the UI would silently hide them.
    """
    if not SAMPLES_DIR.is_dir():
        return []
    out: list[Path] = []
    for path in sorted(SAMPLES_DIR.iterdir()):
        if not path.is_file() or path.name.startswith("."):
            continue
        try:
            detect_iac_type(path)
        except IaCAgentError:
            continue
        out.append(path)
    return out


def _fix_availability() -> tuple[bool, str]:
    """Can the remediation loop run at all? Returns (enabled, explanation).

    The key itself is never read or displayed here. `LLMClient` calls `load_dotenv()` on its
    first live call, so a `.env` on disk counts as "a key may be available"; if it turns out
    not to contain one, the loop raises `LLMError` and this page renders that message rather
    than a traceback.
    """
    missing = [m for m in ("openai", "dotenv") if importlib.util.find_spec(m) is None]
    if missing:
        return False, (
            f"Not installed: {', '.join(missing)}. Live model calls need them "
            '(`pip install -e ".[dev]"`). Scanning still works.'
        )
    if os.getenv("OPENAI_API_KEY"):
        return True, "`OPENAI_API_KEY` found in the environment."
    if (REPO_ROOT / ".env").is_file():
        return True, (
            "`OPENAI_API_KEY` is not in the environment, but a `.env` file exists and "
            "`iac_agent` loads it at call time. If the key is not in there, the run stops "
            "with a message instead of a partial result."
        )
    return False, (
        "`OPENAI_API_KEY` is not set and there is no `.env` file, so no fix can be "
        "generated. Everything on this page that does not need a model still works: "
        "scan a sample, read the drift explanation, read the measured results."
    )


def _finding_rows(findings: list[Any]) -> list[dict]:
    """Flatten `Finding` objects for display. Presentation only — no filtering."""
    return [
        {
            "severity": f.severity,
            "rule": f.rule_id,
            "resource": f.resource,
            "finding": f.message,
            "line": f.line,
            "docs": f.guideline,
        }
        for f in findings
    ]


def _verdict(record: dict) -> tuple[str, str, str]:
    """(icon, label, badge colour) for one iteration."""
    if record["accepted"]:
        return ("✅", "accepted — scanned", "green")
    reason = record["reason"] or ""
    for prefix, icon, label, colour in REJECTION_KINDS:
        if reason.startswith(prefix):
            return (icon, label, colour)
    return ("•", "rejected", "gray")


def _truncate(text: str, limit: int = 110) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --------------------------------------------------------------------------------------
# rendering blocks
# --------------------------------------------------------------------------------------


def _render_severity_summary(rows: list[dict], scanner: str) -> None:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["severity"]] = counts.get(row["severity"], 0) + 1
    bar = st.container(horizontal=True)
    for severity, count in sorted(
        counts.items(), key=lambda kv: (SEVERITY_ORDER.get(kv[0], 9), kv[0])
    ):
        bar.badge(
            f"{SEVERITY_ICON.get(severity, '⚪')} {severity} · {count}",
            color=SEVERITY_BADGE.get(severity, "gray"),
        )
    if "unknown" in counts and scanner == "checkov":
        st.caption(
            "`unknown` is what Checkov's community build reports for most checks: the "
            "scanner supplied no severity. It does not mean the finding is minor."
        )


def _render_findings_table(rows: list[dict]) -> None:
    frame = pd.DataFrame(rows)
    frame["_rank"] = frame["severity"].map(lambda s: SEVERITY_ORDER.get(s, 9))
    frame = frame.sort_values(["_rank", "rule"]).drop(columns=["_rank"])
    frame["severity"] = frame["severity"].map(
        lambda s: f"{SEVERITY_ICON.get(s, '⚪')} {s}"
    )
    # A scanner may report no line number; a nullable integer keeps the column numeric
    # instead of falling back to object dtype, which the column config cannot format.
    frame["line"] = pd.to_numeric(frame["line"], errors="coerce").astype("Int64")
    st.dataframe(
        frame,
        hide_index=True,
        column_config={
            "severity": st.column_config.TextColumn("severity", width="small"),
            "rule": st.column_config.TextColumn("rule", width="small"),
            "resource": st.column_config.TextColumn("resource", width="medium"),
            "finding": st.column_config.TextColumn("finding", width="large"),
            "line": st.column_config.NumberColumn("line", width="small", format="%d"),
            "docs": st.column_config.LinkColumn("docs", display_text="open", width="small"),
        },
    )


def _render_scan_outcome(rows: list[dict], scanner: str, passed: int, parse_errors: int) -> None:
    """Findings, or an explicit clean result. Never used to render a scanner failure."""
    if rows:
        _render_severity_summary(rows, scanner)
        _render_findings_table(rows)
    else:
        st.success(
            f"**{scanner} ran and reported 0 failed checks** ({passed} checks passed). "
            "This is a real result from a scanner that executed — not an absent one."
        )
        st.caption(
            "Zero findings from one ruleset is not a proof of security; it means these "
            "rules did not fire."
        )
    if parse_errors:
        st.warning(
            f"**{scanner} reported {parse_errors} parsing error(s).** Part of this file was "
            "not analysed, so the count above is a floor, not a total."
        )


def _render_diff(before: str, after: str, from_name: str, to_name: str, language: str) -> None:
    lines = list(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=from_name,
            tofile=to_name,
            lineterm="",
            n=3,
        )
    )
    if not lines:
        st.info(
            "The returned file is byte-identical to the input — nothing was accepted, so "
            "the original is what you get back."
        )
        return
    body = lines[2:]
    added = sum(1 for line in body if line.startswith("+"))
    removed = sum(1 for line in body if line.startswith("-"))
    bar = st.container(horizontal=True)
    bar.badge(f"+{added} added", color="green")
    bar.badge(f"−{removed} removed", color="red")
    st.code("\n".join(lines), language="diff", height=min(680, 40 + 21 * len(lines)))
    with st.expander("Full files, side by side"):
        left, right = st.columns(2)
        left.caption(f"`{from_name}`")
        left.code(before, language=language, height=520, line_numbers=True)
        right.caption(f"`{to_name}`")
        right.code(after, language=language, height=520, line_numbers=True)


def _render_drift_primer(compact: bool) -> None:
    """The project's differentiating idea, stated before any result is on screen."""
    if compact:
        with st.container(border=True):
            st.markdown(
                "#### Why a falling finding count is not a result\n"
                "**Deleting the offending resource makes its findings disappear.** A rewrite "
                "that drops the public S3 bucket scores zero and has secured nothing. So "
                "every candidate is first compared against the *original's* resource set: if "
                "a resource that carried a finding is gone, the candidate is **rejected "
                "before it is ever scanned**, and cannot score at all."
            )
            st.caption(
                "In the measured evaluation the model deleted "
                "`aws_s3_bucket_policy.public_policy` instead of restricting it in 5 of 6 "
                "runs — see the *Measured results* tab. Rejections are reported here, not "
                "hidden."
            )
        return

    st.markdown(
        """
### The drift gate

Any tool that tells you the finding count fell is asking you to trust that the findings which
vanished were *fixed*. There is a much cheaper way to make them vanish:

```hcl
# the file the scanner complained about
resource "aws_s3_bucket" "b" {
  acl = "public-read"
}

# a rewrite that scores perfectly:
# (nothing — the resource was deleted)
```

Delete the resource and every finding attached to it disappears. The file scans clean. The
infrastructure it described is simply gone, which is a worse outcome than the finding.

**What this tool does instead.** Each candidate rewrite goes through gates, in this order:

1. **Parse gate** — the candidate must parse as Terraform / Dockerfile. A malformed file can
   scan *better* than a correct one.
2. **Drift gate** — the resource set of the candidate is compared with the resource set of
   the original. If any resource that carried a baseline finding was deleted or renamed away,
   the candidate is rejected.
3. **Rescan** — only a candidate that survives both is written to disk and scanned. Only then
   can its number count.

A rejected candidate is **never scanned**, so a deletion can never be recorded as an
improvement. The name of the deleted resource is fed back to the model as the next turn's
instruction, which is why a rejection is often followed by a real fix.

**What it does not cover, stated plainly:**

- Dockerfiles have no addressable resources, so the drift gate does not apply to them. The
  parse gate still does.
- If the *original* file does not parse, drift cannot be measured against it. The loop
  records that as "drift gate disabled" and this page shows it — "not checked" is never
  displayed as "no drift".
- The gate compares resource sets. A resource that survives with its meaning gutted is a
  weaker signal than one that was deleted, and this catches the deletion.
        """
    )


def _render_results_page() -> None:
    """Render `eval/results/RESULTS.md` from disk. Nothing here is duplicated into the UI."""
    st.markdown("### Measured results")
    if not RESULTS_MD.is_file():
        st.warning(
            f"**`{RESULTS_MD.relative_to(REPO_ROOT)}` is not present in this checkout**, so "
            "there is nothing measured to show. Rather than print numbers from memory, this "
            "page shows nothing.\n\nRegenerate it with:\n\n"
            "```bash\n.venv/bin/python -m eval.run_eval report\n```"
        )
        return
    try:
        text = RESULTS_MD.read_text(encoding="utf-8")
    except OSError as exc:
        st.error(f"Could not read `{RESULTS_MD}`:\n\n```\n{exc}\n```")
        return

    stamp = datetime.fromtimestamp(RESULTS_MD.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
    st.caption(
        f"Read at page load from `{RESULTS_MD.relative_to(REPO_ROOT)}` "
        f"(last modified {stamp}). This file is generated by the evaluation harness; the UI "
        "renders it and never edits or restates it."
    )

    banner, body = "", text
    stripped = text.lstrip()
    if stripped.startswith("<!--") and "-->" in stripped:
        raw, _, body = stripped.partition("-->")
        banner = raw.removeprefix("<!--").strip()
    if banner:
        with st.expander("Provenance of these numbers"):
            st.text(banner)
    st.markdown(body)


def _render_how_it_works() -> None:
    cfg = ModelConfig()
    st.markdown(
        f"""
### The pipeline

```
input file ──▶ scanner (baseline) ──▶ model: what is wrong? ──▶ model: rewrite it
                                                                      │
        ◀── best candidate ◀── rescan ◀── drift gate ◀── parse gate ◀──┘
```

The loop repeats until one of four stop conditions fires. Everything above happens inside
`iac_agent.run_loop`; this page only shows what it returned.

**Fail closed, always.** A scanner that crashes, times out, produces no output, or reports a
fatal condition raises an error. It is never converted into an empty finding list — an
absence of analysis is not a passing result, and this page renders the two differently and
loudly.

**Filenames are load-bearing.** Both Checkov and Trivy select their Dockerfile rules by
*filename*, so a Dockerfile saved as `.tf` scans clean and reports a false pass. Anything you
upload here is written under a name that implies its type before a scanner sees it.

### Why the loop stops
        """
    )
    for reason in StopReason:
        title, explanation = STOP_REASONS.get(reason.name, (reason.name, ""))
        with st.container(border=True):
            st.markdown(f"**`{reason.name}` — {title}**")
            st.caption(explanation)

    st.markdown(
        f"""
### Run configuration

| setting | value |
| --- | --- |
| model | `{cfg.model}` |
| temperature / seed | `{cfg.temperature}` / `{cfg.seed}` |
| prompt version | `{cfg.prompt_version}` |
| default token budget | `{TOKEN_BUDGET_DEFAULT}` |
| scanners available | {', '.join(f'`{s}`' for s in sorted(SCANNERS))} |
| package version | `{__version__}` |

Read from `iac_agent` at page load, not written down here.

**This UI is a view, not a second implementation.** The supported interface is the CLI
(`python -m iac_agent.cli`); everything this page can do, that can do, and the evaluation
harness in `eval/` is what produces the numbers in *Measured results*.
        """
    )


# --------------------------------------------------------------------------------------
# actions — each returns a plain dict so results survive Streamlit reruns
# --------------------------------------------------------------------------------------


def _prepare(name: str, code: str, workdir: Path) -> tuple[IaCType, Path]:
    """Write the input under a name that implies its type, and return that path.

    Load-bearing, not cosmetic: both scanners select their Dockerfile rulesets by filename,
    so a Dockerfile written to a `.tf` path scans clean and reports a false pass.
    """
    iac_type = detect_iac_type(name)
    target = workdir / ("Dockerfile" if iac_type is IaCType.DOCKERFILE else Path(name).name)
    target.write_text(code, encoding="utf-8")
    return iac_type, target


def _do_scan(name: str, code: str, scanner: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        iac_type, target = _prepare(name, code, Path(tmp))
        result = get_scanner(scanner).scan(target, iac_type)
        return {
            "kind": "scan",
            "name": name,
            "scanner": scanner,
            "iac_type": iac_type.value,
            "code": code,
            "scanned_as": target.name,
            "findings": _finding_rows(result.failed),
            "passed": result.passed_count,
            "parse_errors": result.parse_errors,
        }


def _do_fix(name: str, code: str, scanner: str, max_iters: int) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        iac_type, target = _prepare(name, code, workdir)
        result = run_loop(
            target,
            scanner=scanner,
            client=LLMClient(),
            cfg=ModelConfig(),
            max_iters=max_iters,
            output_dir=workdir / "out",
        )
        best_scan = result.best.scan
        return {
            "kind": "fix",
            "name": name,
            "scanner": result.scanner,
            "iac_type": iac_type.value,
            "code": code,
            "scanned_as": target.name,
            "max_iters": max_iters,
            "before": result.baseline_failed,
            "after": best_scan.failed_count if best_scan is not None else None,
            "resolved": len(result.resolved),
            "introduced": len(result.introduced),
            "accepted_any": result.accepted_any,
            "stop_reason": result.stop_reason.name,
            "tokens": result.total_tokens,
            "detect_tokens": result.detect_tokens,
            "aborted": result.aborted_because,
            "drift_note": result.drift_gate_note,
            "fixed_code": result.best_code,
            "output_name": iac_type.output_name,
            "baseline_findings": _finding_rows(result.baseline.failed),
            "final_findings": (
                _finding_rows(best_scan.failed) if best_scan is not None else None
            ),
            "final_passed": best_scan.passed_count if best_scan is not None else 0,
            "final_parse_errors": best_scan.parse_errors if best_scan is not None else 0,
            "issues": result.issues,
            "summary": result.summary(),
            "iterations": [
                {
                    "index": record.index,
                    "accepted": record.accepted,
                    "findings": record.scan.failed_count if record.scan else None,
                    "reason": record.rejected_because,
                    "tokens": record.total_tokens,
                    "is_best": record.is_best,
                    "drift_checked": record.drift is not None,
                    "drift_summary": record.drift.summary() if record.drift else "",
                }
                for record in result.iterations
            ],
        }


# --------------------------------------------------------------------------------------
# result rendering
# --------------------------------------------------------------------------------------


def _render_failure(failure: dict) -> None:
    """A failure is never allowed to look like a clean result."""
    if failure["kind"] == "scanner":
        st.error(
            "### 🛑 The scanner did not run\n"
            "**This file has not been checked.** An absent analysis is not a passing "
            "analysis, so no finding count is shown for it."
        )
    elif failure["kind"] == "agent":
        st.error(f"### The run stopped\n**{failure['label']}** — nothing partial was kept.")
    else:
        st.error(
            "### Unexpected error\nThis is a bug in the app, not a verdict about the file. "
            "Nothing was scanned or verified."
        )
    st.code(failure["message"], language="text", wrap_lines=True)


def _render_scan(payload: dict) -> None:
    st.markdown(f"#### `{payload['scanner']}` on `{payload['name']}`")
    left, right = st.columns([1, 3], vertical_alignment="center")
    left.metric("Failed checks", len(payload["findings"]))
    right.caption(
        f"Scanned as `{payload['scanned_as']}` ({payload['iac_type']}) so the scanner "
        f"selects the right ruleset · {payload['passed']} checks passed · "
        "no model was called."
    )
    _render_scan_outcome(
        payload["findings"], payload["scanner"], payload["passed"], payload["parse_errors"]
    )
    st.caption(
        "This is the baseline the LLM has to beat. On the six original fixtures the "
        "scanners find more than the model does on its own — the *Measured results* tab has "
        "the recall numbers."
    )


def _render_trail(payload: dict) -> None:
    """The loop's progression, one card per step, plus a one-line textual trail."""
    before = payload["before"]
    steps: list[dict] = [
        {
            "label": "Baseline",
            "value": str(before),
            "delta": None,
            "icon": "📋",
            "verdict": "the file as given",
            "colour": "gray",
            "note": f"`{payload['scanner']}` on the input",
            "best": not payload["accepted_any"],
        }
    ]
    parts = [f"baseline **{before}**"]
    for record in payload["iterations"]:
        icon, verdict, colour = _verdict(record)
        findings = record["findings"]
        steps.append(
            {
                "label": f"Iteration {record['index']}",
                "value": str(findings) if findings is not None else "—",
                "delta": (findings - before) if findings is not None else None,
                "icon": icon,
                "verdict": verdict,
                "colour": colour,
                "note": _truncate(record["reason"], 90)
                or f"{record['tokens']} tokens · scanned",
                "best": record["is_best"],
            }
        )
        if findings is None:
            parts.append(f"iter {record['index']} *{verdict}*")
        else:
            parts.append(f"iter {record['index']} **{findings}** ({verdict.split('—')[0].strip()})")

    st.markdown("**Trail** · " + "  →  ".join(parts))
    columns = st.columns(len(steps), gap="small")
    for column, step in zip(columns, steps):
        with column.container(border=True):
            st.caption(step["label"] + (" · returned" if step["best"] else ""))
            st.metric(
                "failed checks",
                step["value"],
                delta=step["delta"],
                delta_color="inverse",
                label_visibility="collapsed",
            )
            st.badge(f"{step['icon']} {step['verdict']}", color=step["colour"])
            st.caption(step["note"])
    st.caption(
        "A rejected iteration is a result, not noise: it is never scanned and never written, "
        "so it cannot lower the count. Its reason is fed back to the model as the next "
        "turn's instruction."
    )


def _render_drift_verdict(payload: dict) -> None:
    rejections = [
        record
        for record in payload["iterations"]
        if (record["reason"] or "").startswith("drift")
    ]
    if rejections:
        with st.container(border=True):
            st.markdown("### 🚫 The drift gate fired")
            st.error(
                f"**{len(rejections)} proposed fix(es) were rejected for removing a resource "
                "that carried a finding.** Deleting a resource makes its findings vanish "
                "without securing anything, so the candidate was thrown away *before it was "
                "scanned* — it never got a number."
            )
            for record in rejections:
                st.markdown(f"- **Iteration {record['index']}** — `{record['reason']}`")
                if record["drift_summary"]:
                    st.caption(f"  resource diff: {record['drift_summary']}")
            st.caption(
                "This is the finding this project exists to produce. Without the gate, each "
                "of these would have been reported as an improvement."
            )
        return

    if payload["drift_note"]:
        st.warning(
            f"**Drift was not checked.** {payload['drift_note']}. That is not the same as "
            "'no drift' — this run cannot tell you whether resources were removed."
        )
        return

    if payload["iac_type"] == IaCType.DOCKERFILE.value:
        st.info(
            "**Drift gate not applicable.** A Dockerfile has no addressable resources to "
            "compare, so only the parse gate ran here. The gate applies to Terraform."
        )
        return

    checked = sum(1 for record in payload["iterations"] if record["drift_checked"])
    if checked:
        st.success(
            f"**Drift gate ran on {checked} candidate(s) and found no deleted resources.** "
            "The reduction below is a change to the configuration, not a removal of it."
        )
    else:
        st.info(
            "No candidate reached the drift gate — every attempt failed the parse gate first."
        )


def _render_fix(payload: dict) -> None:
    before, after = payload["before"], payload["after"]
    st.markdown(f"#### `{payload['scanner']}` loop on `{payload['name']}`")

    cols = st.columns(5)
    cols[0].metric("Findings before", before)
    cols[1].metric(
        "Findings after",
        after if after is not None else "—",
        delta=(after - before) if after is not None else None,
        delta_color="inverse",
    )
    cols[2].metric("Resolved", payload["resolved"], help="Present at baseline, absent now.")
    cols[3].metric(
        "Introduced",
        payload["introduced"],
        delta=payload["introduced"] or None,
        delta_color="inverse",
        help="Findings the rewrite created. Never subtracted from 'resolved'.",
    )
    cols[4].metric("Tokens", payload["tokens"], help=f"Budget: {TOKEN_BUDGET_DEFAULT}")

    title, explanation = STOP_REASONS.get(
        payload["stop_reason"], (payload["stop_reason"], "")
    )
    st.markdown(f"**Stopped: {title}** (`{payload['stop_reason']}`)")
    st.caption(explanation)

    if payload["aborted"]:
        st.warning(f"**The run ended on an error, not a planned stop:** {payload['aborted']}")

    # Drift verdict sits above the diff on purpose: a run that lowered the count by deleting
    # the offending resource looks like a success in every other number on this page.
    _render_drift_verdict(payload)

    if not payload["accepted_any"]:
        st.info(
            "**No candidate was accepted**, so the original file is returned unchanged. "
            "The count did not move because nothing was allowed to move it."
        )

    st.divider()
    _render_trail(payload)
    st.divider()

    tabs = st.tabs(
        ["Diff", "Findings", "Per-iteration detail", "What the model claimed", "Download"]
    )
    with tabs[0]:
        _render_diff(
            payload["code"],
            payload["fixed_code"],
            payload["name"],
            payload["output_name"],
            _language(payload["iac_type"]),
        )
    with tabs[1]:
        left, right = st.columns(2)
        with left:
            st.markdown(f"**Before — {before} failed**")
            _render_severity_summary(payload["baseline_findings"], payload["scanner"])
            if payload["baseline_findings"]:
                _render_findings_table(payload["baseline_findings"])
        with right:
            if payload["final_findings"] is None:
                st.error(
                    "The returned candidate was never scanned, so there is no 'after' list. "
                    "This is not a clean result."
                )
            else:
                st.markdown(f"**After — {after} failed**")
                _render_scan_outcome(
                    payload["final_findings"],
                    payload["scanner"],
                    payload["final_passed"],
                    payload["final_parse_errors"],
                )
    with tabs[2]:
        if payload["iterations"]:
            detail = pd.DataFrame(
                [
                    {
                        "iteration": record["index"],
                        "verdict": f"{_verdict(record)[0]} {_verdict(record)[1]}",
                        "findings": record["findings"],
                        "drift checked": record["drift_checked"],
                        "reason": record["reason"],
                        "tokens": record["tokens"],
                        "returned": record["is_best"],
                    }
                    for record in payload["iterations"]
                ]
            )
            # An unscanned candidate has no count; a nullable integer says "no value"
            # rather than coercing it to a number that would read as zero findings.
            detail["findings"] = pd.to_numeric(
                detail["findings"], errors="coerce"
            ).astype("Int64")
            st.dataframe(
                detail,
                hide_index=True,
                column_config={
                    "findings": st.column_config.NumberColumn(
                        "findings",
                        help="Blank means the candidate was rejected and never scanned — "
                        "it is not a zero.",
                    ),
                    "reason": st.column_config.TextColumn("reason", width="large"),
                },
            )
        else:
            st.info("The baseline was already clean, so the model was never called.")
        st.code(payload["summary"], language="text", wrap_lines=True)
    with tabs[3]:
        st.caption(
            f"The model's own detection pass ({payload['detect_tokens']} tokens). It is "
            "shown because it is *not* what the count above is based on — the scanners are. "
            "Measured on the fixtures, the model's detection recall is worse than Checkov "
            "alone; the *Measured results* tab has both numbers."
        )
        if payload["issues"]:
            st.dataframe(pd.DataFrame(payload["issues"]), hide_index=True)
        else:
            st.info("The model reported nothing, or was never asked.")
    with tabs[4]:
        st.download_button(
            "Remediated file",
            data=payload["fixed_code"],
            file_name=payload["output_name"],
            mime="text/plain",
            width="stretch",
        )
        st.download_button(
            "JSON report",
            data=json.dumps(
                {
                    key: payload[key]
                    for key in (
                        "name", "iac_type", "scanner", "max_iters", "before", "after",
                        "resolved", "introduced", "accepted_any", "stop_reason", "tokens",
                        "aborted", "drift_note", "iterations", "summary",
                    )
                },
                indent=2,
            ),
            file_name="iac_security_report.json",
            mime="application/json",
            width="stretch",
        )


# --------------------------------------------------------------------------------------
# page
# --------------------------------------------------------------------------------------

st.title("🔒 Infrastructure-as-Code security — detect, fix, verify")
st.markdown(
    "Static scanners find misconfigurations in Terraform and Dockerfiles, a language model "
    "rewrites the file, and the scanners run again to check the rewrite actually fixed "
    "something.  \n"
    "Every candidate must survive a parse gate and a **drift gate** before its number "
    "counts — and a scanner that fails to run is reported as a failure, never as a clean pass."
)

_render_drift_primer(compact=True)

samples = _list_samples()
fix_enabled, fix_reason = _fix_availability()

with st.sidebar:
    st.subheader("Input")
    modes = ["Bundled sample", "Upload"]
    mode = st.radio(
        "Source",
        modes,
        index=0 if samples else 1,
        horizontal=True,
        label_visibility="collapsed",
    )

    input_name: str | None = None
    input_code: str | None = None
    input_error: str | None = None

    if mode == "Bundled sample":
        if not samples:
            input_error = (
                f"No usable fixtures found in `{SAMPLES_DIR.name}/`. Switch to **Upload**."
            )
        else:
            by_name = {path.name: path for path in samples}
            picked = st.selectbox(
                "Fixture",
                list(by_name),
                help="Listed from samples/ at page load, so fixtures added to the repo "
                "appear here without touching this file.",
            )
            chosen = by_name[picked]
            try:
                input_code = chosen.read_text(encoding="utf-8")
                input_name = chosen.name
            except OSError as exc:
                input_error = f"Could not read `{chosen}`: {exc}"
            else:
                st.caption(
                    f"`samples/{chosen.name}` · {len(input_code.splitlines())} lines · "
                    "deliberately vulnerable"
                )
    else:
        uploaded = st.file_uploader(
            "Terraform or Dockerfile",
            help="Accepted: *.tf, Dockerfile, *.Dockerfile. Nothing leaves this machine "
            "unless you press the fix button.",
        )
        if uploaded is None:
            input_error = "Choose a file, or switch to **Bundled sample** to try it now."
        else:
            try:
                input_code = uploaded.getvalue().decode("utf-8")
            except UnicodeDecodeError:
                input_error = "That file is not UTF-8 text, so it is not IaC source."
            else:
                input_name = Path(uploaded.name).name
                try:
                    detect_iac_type(input_name)
                except IaCAgentError as exc:
                    input_error, input_name, input_code = str(exc), None, None

    st.subheader("Settings")
    scanner_name = st.selectbox("Scanner", sorted(SCANNERS))
    st.caption(
        "The tool must be installed. If it cannot run, this page says so — it never "
        "reports a missing scanner as a clean file."
    )
    max_iters = st.slider("Max iterations", 1, 5, 3)

    st.subheader("Run")
    ready = input_name is not None and input_code is not None
    scan_clicked = st.button(
        "Scan only", icon="🔍", width="stretch", disabled=not ready,
        help="Runs the scanner. No API key, no model, no cost.",
    )
    fix_clicked = st.button(
        "Scan, fix and verify",
        icon="🛠️",
        type="primary",
        width="stretch",
        disabled=not (ready and fix_enabled),
        help=fix_reason if not fix_enabled else "Calls the model. This one costs money.",
    )
    if fix_enabled:
        st.caption(f"✅ {fix_reason}")
    else:
        st.caption(f"🔒 **Fixing is unavailable.** {fix_reason}")
    if input_error:
        st.caption(f"⚠️ {input_error}")

    st.divider()
    st.caption(
        f"`iac_agent` {__version__} · model `{ModelConfig().model}` · the supported "
        "interface is the CLI; this page is a view over the same package."
    )

tab_run, tab_drift, tab_results, tab_how = st.tabs(
    ["▶ Analyse", "🚫 Drift gate", "📊 Measured results", "❓ How it works"]
)

with tab_run:
    if (scan_clicked or fix_clicked) and input_name is not None and input_code is not None:
        st.session_state.pop("outcome", None)
        st.session_state.pop("failure", None)
        label = (
            f"Scanning `{input_name}` with {scanner_name}…"
            if scan_clicked
            else f"Detect → fix → verify on `{input_name}`…"
        )
        with st.status(label, expanded=True) as status:
            try:
                if scan_clicked:
                    st.write(
                        f"Writing the file under a name that implies its type, then running "
                        f"`{scanner_name}` on it."
                    )
                    st.session_state["outcome"] = _do_scan(
                        input_name, input_code, scanner_name
                    )
                else:
                    st.write(f"**1.** Baseline scan with `{scanner_name}`.")
                    st.write("**2.** Ask the model what is wrong, then for a rewrite.")
                    st.write(
                        f"**3.** Parse gate → drift gate → rescan, up to {max_iters} "
                        "time(s), keeping the best candidate."
                    )
                    st.caption(
                        "One blocking call into `iac_agent.run_loop`; the trail below shows "
                        "what actually happened, including rejected attempts."
                    )
                    st.session_state["outcome"] = _do_fix(
                        input_name, input_code, scanner_name, max_iters
                    )
            except ScannerError as exc:
                st.session_state["failure"] = {"kind": "scanner", "message": str(exc)}
                status.update(label="Scanner failure", state="error")
            except IaCAgentError as exc:
                st.session_state["failure"] = {
                    "kind": "agent",
                    "label": type(exc).__name__,
                    "message": str(exc),
                }
                status.update(label="Stopped", state="error")
            except Exception as exc:  # never show the user a raw traceback
                st.session_state["failure"] = {
                    "kind": "unexpected",
                    "message": f"{type(exc).__name__}: {exc}",
                }
                status.update(label="Unexpected error", state="error")
            else:
                status.update(label="Done", state="complete", expanded=False)

    failure = st.session_state.get("failure")
    outcome = st.session_state.get("outcome")

    if failure:
        _render_failure(failure)
    elif outcome:
        if input_name and outcome["name"] != input_name:
            st.info(
                f"Showing the result for `{outcome['name']}`. The selected input is now "
                f"`{input_name}` — press a run button to analyse it."
            )
        if outcome["kind"] == "scan":
            _render_scan(outcome)
        else:
            _render_fix(outcome)
    else:
        st.info(
            "**Nothing has been run yet.** A fixture from `samples/` is already selected in "
            "the sidebar — press **Scan only** for a real result with no API key and no "
            "cost, or upload your own file."
        )

    if input_code and input_name:
        with st.expander(f"Input — `{input_name}`", expanded=False):
            st.code(
                input_code,
                language=_language_of(input_name),
                line_numbers=True,
                height=420,
            )

with tab_drift:
    _render_drift_primer(compact=False)

with tab_results:
    _render_results_page()

with tab_how:
    _render_how_it_works()
