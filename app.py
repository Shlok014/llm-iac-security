"""Streamlit front end for the IaC remediation loop.

A thin view over `iac_agent`. It collects an input, calls `run_loop` (or a single scanner),
and renders what came back. Every decision the results describe — what counts as a finding,
when a candidate is rejected, when the loop stops — is made inside the package. No policy is
implemented here, and no measured number is typed into this file: the evaluation figures are
read from `eval/results/RESULTS.md` at runtime, and the sample list is the contents of
`samples/` at runtime.

Presentation lives in `ui_theme.py` and `.streamlit/config.toml`; the reasoning behind both —
the palette, the type pairing, and why the gate rail is drawn the way it is — is in
`docs/UI_DESIGN.md`. The rule worth knowing before editing this file: **amber plus a dashed
border means "not verified"**, and nothing else may use it.

It previously imported `detect_vulnerabilities`, `generate_fix` and `validate_with_checkov`
from a top-level `main.py` that also owned the orchestration, the prompts and a second,
divergent copy of the JSON parser. That module has been removed; the submitted version of it
remains in git history at the import commit.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import difflib
import html
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

import ui_theme as ui
from iac_agent import __version__
from iac_agent.llm import LLMClient, ModelConfig
from iac_agent.loop import StopReason, finding_key, run_loop
from iac_agent.scanners import SCANNERS, get_scanner, scanner_path
from iac_agent.types import IaCAgentError, IaCType, ScannerError, detect_iac_type

REPO_ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = REPO_ROOT / "samples"
RESULTS_MD = REPO_ROOT / "eval" / "results" / "RESULTS.md"

st.set_page_config(
    page_title="IaC security — detect, fix, verify",
    page_icon="◤",
    layout="wide",
    initial_sidebar_state="expanded",
)
ui.inject()

# --------------------------------------------------------------------------------------
# presentation tables (labels and colours only — no analysis lives in this file)
# --------------------------------------------------------------------------------------

INK = "var(--ix-ink)"
MUTED = "var(--ix-muted)"
SIGNAL = "var(--ix-signal)"
BLOCKED = "var(--ix-blocked)"

# Station indices into `ui_theme.STATIONS`: input=1, model=2, parse=3, drift=4, rescan=5,
# returned=6.
ST_INPUT, ST_MODEL, ST_PARSE, ST_DRIFT, ST_RESCAN, ST_RETURNED = range(1, 7)

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

# Where on the rail a rejected candidate came to rest, and how that stop is drawn. The mapping
# is over the reason prefixes `iac_agent.loop` writes into `IterationRecord.rejected_because`;
# the classification itself is the package's. `unverified` switches the pip to the dashed amber
# treatment that means "we could not establish this", as opposed to "this failed".
REJECTION_KINDS: tuple[tuple[str, int, str, str, bool], ...] = (
    ("drift:", ST_DRIFT, "rejected — protected structure changed", BLOCKED, False),
    ("drift_unmeasurable:", ST_DRIFT, "rejected — drift unverifiable", SIGNAL, True),
    ("invalid:", ST_PARSE, "rejected — did not parse", BLOCKED, False),
    ("llm_error:", ST_MODEL, "the model call failed", MUTED, False),
    ("scan_failed:", ST_RESCAN, "scanner failed — unverified", SIGNAL, True),
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


def _display_resource(resource: str, workdir: Path) -> str:
    """Drop the scratch directory from a resource name.

    Terraform findings name a resource (`aws_s3_bucket.public_bucket`) and pass through
    untouched. Dockerfile findings name the *file* the instruction was found in, so a scan run
    out of a temporary directory reports `/var/folders/q0/…/tmpchwlh4tq/Dockerfile.ADD`: sixty
    characters of machine path in front of the one word that identifies the instruction, and the
    column is too narrow to show the end of it. The path is an artefact of where this page had
    to put the file — the CLI, scanning in place, never produces it — so it is not information
    the reader can act on. Only paths that are genuinely inside the run's own scratch directory
    are shortened; anything else is left exactly as the scanner reported it.
    """
    if not resource.startswith("/"):
        return resource
    candidate = Path(resource)
    for base in (workdir, workdir.resolve()):
        if base in candidate.parents:
            return candidate.name
    return resource


def _finding_rows(findings: list[Any], workdir: Path) -> list[dict]:
    """Flatten `Finding` objects for display. Presentation only — no filtering."""
    return [
        {
            "severity": f.severity,
            "rule": f.rule_id,
            "resource": _display_resource(f.resource, workdir),
            "finding": f.message,
            "line": f.line,
            "docs": f.guideline,
        }
        for f in findings
    ]


# Ordered worst-news-first: what the rewrite created, then what it did not touch, then what it
# actually fixed. A reader scanning from the top meets the things that need a decision first.
CHANGE_ORDER = {"introduced": 0, "still failing": 1, "resolved": 2}


def _change_rows(
    baseline: list[Any],
    final: list[Any] | None,
    resolved: set[tuple[str, str]],
    introduced: set[tuple[str, str]],
    iac_type: IaCType,
    workdir: Path,
) -> list[dict]:
    """One row per finding, labelled with what the run did to it.

    Answering "what changed?" used to mean putting two tables side by side, each at half width
    and each truncating, and diffing them by eye — while the counts that *are* the answer sat
    in a different line entirely. This joins them instead. The classification is not decided
    here: `resolved` and `introduced` are the loop's own key sets, and `finding_key` is the
    loop's own normalisation, so this cannot disagree with the numbers in the verdict.
    """
    rows: list[dict] = []
    for f in baseline:
        if finding_key(f, iac_type) in resolved:
            rows.append({"status": "resolved", **_finding_rows([f], workdir)[0]})
    for f in final or []:
        key = finding_key(f, iac_type)
        status = "introduced" if key in introduced else "still failing"
        rows.append({"status": status, **_finding_rows([f], workdir)[0]})
    rows.sort(key=lambda r: (CHANGE_ORDER[r["status"]], r["resource"], r["rule"]))
    return rows


def _station(record: dict) -> tuple[int, str, str, bool]:
    """(station reached, label, tone, unverified) for one iteration."""
    # `record.accepted` means "cleared every gate and was scanned". It does *not* mean the
    # candidate was kept: `LoopResult.accepted_any` is a different question, answered by
    # whether the best record is still the baseline. The page must not use one word for both.
    if record["accepted"]:
        return (ST_RESCAN, "cleared the gates — scanned", INK, False)
    reason = record["reason"] or ""
    for prefix, station, label, tone, unverified in REJECTION_KINDS:
        if reason.startswith(prefix):
            return (station, label, tone, unverified)
    # An unrecognised reason must not be drawn as having reached the scanner: "we do not know
    # where this stopped" fails to the earliest station it could have stopped at, not the latest.
    return (ST_MODEL, "rejected — reason unrecognised", SIGNAL, True)


def _truncate(text: str, limit: int = 110) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _mono(value: object) -> str:
    """A filename, rule or resource, marked as the literal string it is."""
    return f"<b>{_esc(value)}</b>"


# --------------------------------------------------------------------------------------
# rendering blocks
# --------------------------------------------------------------------------------------


def _render_severity_summary(rows: list[dict], scanner: str) -> None:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["severity"]] = counts.get(row["severity"], 0) + 1
    ui.chips(
        [
            (f"{severity} · {count}", severity, severity == "unknown")
            for severity, count in sorted(
                counts.items(), key=lambda kv: (ui.SEVERITY_ORDER.get(kv[0], 9), kv[0])
            )
        ]
    )
    if "unknown" in counts and scanner == "checkov":
        # One line, not three. Checkov reports `unknown` for most checks, so this note is on
        # screen for practically every scan; at its old length it was a paragraph the reader
        # had to step over each time to reach the table.
        st.caption(
            "Checkov's community build supplies no severity for most checks — `unknown` means "
            "the scanner declined to say, not that the finding is minor."
        )


def _render_findings_table(
    rows: list[dict],
    *,
    select_key: str | None = None,
    severity_stated_above: bool = False,
) -> dict | None:
    """The findings, sorted so they can be read in order. Returns the selected row, if any.

    Two things here are about reading rather than about data. Findings are sorted by severity,
    then **by resource**, so everything wrong with one bucket sits together instead of being
    scattered by rule ID — "what is wrong with my S3 bucket" is the question people actually
    arrive with. And a column whose every cell holds the same value is dropped: Checkov reports
    `unknown` for all of them and Trivy reports no resource at all on Dockerfiles, so the widest
    column on screen was regularly one repeated word, squeezing the message that is the point.

    Dropping the *severity* column is only free where something else has already said what it
    would have said, which is why the caller has to assert it: `_render_scan_outcome` draws the
    severity chips first, and the before/after comparison draws no chips at all. Getting that
    backwards would silently delete the only statement of severity on the screen.
    """
    frame = pd.DataFrame(rows)
    # A scanner may report no line number; a nullable integer keeps the column numeric
    # instead of falling back to object dtype, which the column config cannot format.
    frame["line"] = pd.to_numeric(frame["line"], errors="coerce").astype("Int64")
    frame["_rank"] = frame["severity"].map(lambda s: ui.SEVERITY_ORDER.get(s, 9))
    order = ["_rank", "resource", "line", "rule"]
    if "status" in frame.columns:
        # The before/after table groups by what the run did first; severity orders within it.
        frame["_status"] = frame["status"].map(lambda s: CHANGE_ORDER.get(s, 9))
        order = ["_status", *order]
    frame = (
        frame.sort_values(order)
        .drop(columns=[c for c in ("_rank", "_status") if c in frame.columns])
        .reset_index(drop=True)
    )

    config = {
        "status": st.column_config.TextColumn("status", width="small"),
        "severity": st.column_config.TextColumn("severity", width="small"),
        "rule": st.column_config.TextColumn("rule", width="small"),
        "resource": st.column_config.TextColumn("resource", width="medium"),
        "finding": st.column_config.TextColumn("finding", width="large"),
        "line": st.column_config.NumberColumn("line", width="small", format="%d"),
        "docs": st.column_config.LinkColumn("docs", display_text="open", width="small"),
    }
    config = {k: v for k, v in config.items() if k in frame.columns}
    droppable = ("severity", "resource") if severity_stated_above else ("resource",)
    for column in droppable:
        if column in frame.columns and frame[column].nunique(dropna=False) <= 1:
            frame = frame.drop(columns=[column])
            config.pop(column)
    # The comparison table adds a `status` column, and six columns in this width leaves the
    # rule IDs clipped mid-identifier. `docs` is the one to give up there: you open a rule's
    # documentation while reading a single finding, not while diffing two scans.
    if "status" in frame.columns and "docs" in frame.columns:
        frame = frame.drop(columns=["docs"])
        config.pop("docs")

    # Size the table to its contents up to a ceiling. Streamlit's default height is a fixed
    # ten rows, so a five-finding scan got a scrollbar it did not need and a thirty-finding
    # scan got a scroll region that swallowed the page's own scroll whenever the pointer was
    # over it — the reader's wheel moved the table instead of the page.
    height = min(36 + 33 * len(frame), 640)

    event = st.dataframe(
        frame,
        hide_index=True,
        height=height,
        column_config=config,
        key=select_key,
        on_select="rerun" if select_key else "ignore",
        selection_mode="single-row",
    )
    if select_key and event.selection.rows:
        # Bounds-checked because the widget key outlives the data: select the thirtieth finding
        # of one file, scan a file with five, and a stale index would raise here — turning a
        # perfectly good result into a traceback.
        index = event.selection.rows[0]
        if 0 <= index < len(frame):
            return frame.iloc[index].to_dict()
    return None


def _render_scan_outcome(
    rows: list[dict],
    scanner: str,
    passed: int,
    parse_errors: int,
    *,
    select_key: str | None = None,
) -> dict | None:
    """Findings, or an explicit clean result. Never used to render a scanner failure."""
    picked: dict | None = None
    if rows:
        _render_severity_summary(rows, scanner)
        picked = _render_findings_table(
            rows, select_key=select_key, severity_stated_above=True
        )
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
    return picked


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
            "The returned file is byte-identical to the input — nothing beat the baseline, "
            "so the original is what you get back."
        )
        return
    body = lines[2:]
    added = sum(1 for line in body if line.startswith("+"))
    removed = sum(1 for line in body if line.startswith("-"))
    ui.chips([(f"+{added} added", "low", False), (f"−{removed} removed", "critical", False)])
    st.code("\n".join(lines), language="diff", height=min(680, 40 + 21 * len(lines)))
    with st.expander("Full files, side by side"):
        left, right = st.columns(2)
        left.caption(f"`{from_name}`")
        left.code(before, language=language, height=520, line_numbers=True)
        right.caption(f"`{to_name}`")
        right.code(after, language=language, height=520, line_numbers=True)


def _render_drift_primer() -> None:
    """The project's differentiating idea, stated once, in the tab named after it."""
    st.markdown(
        """
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
2. **Drift gate** — Terraform resource addresses are compared with the original, and any
   deletion or rename is rejected. For Dockerfiles, the gate checks base image families,
   per-stage copy sources and startup command presence.
3. **Rescan** — only a candidate that survives both is written to disk and scanned. Only then
   can its number count.

A rejected candidate is **never scanned**, so a deletion can never be recorded as an
improvement. That ordering is what the rail on the *analyse* tab draws: a rejected candidate
comes to rest to the left of `rescan`, and there is no position on the rail where a deleted
resource could have produced a count. The structural failure is fed back to the model
as the next turn's instruction, which is why a rejection is often followed by a real fix.

**What it does not cover, stated plainly:**

- The Dockerfile gate is structural. It does not prove the image builds or behaves the same;
  changes inside `RUN`, `COPY`, `CMD` and other instructions still need human review.
- If the *original* file does not parse, drift cannot be measured against it. The loop
  records that as "drift gate disabled" and this page shows it — "not checked" is never
  displayed as "no drift".
- The gate compares resource sets. A resource that survives with its meaning gutted is a
  weaker signal than one that was deleted, and this catches the deletion.

This is not a hypothetical failure mode. On the bundled fixtures the model reaches for deletion
rather than restriction often enough that the gate fires on ordinary runs; the *measured results*
tab carries the rate, read from the evaluation harness rather than written down here.
        """
    )


def _render_results_page() -> None:
    """Render `eval/results/RESULTS.md` from disk. Nothing here is duplicated into the UI."""
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
        """
The loop runs `baseline scan → detect → rewrite → parse gate → drift gate → rescan` and repeats
until one of four stop conditions fires. The rail on the *analyse* tab is that sequence drawn to
scale, with every candidate placed at the station it reached.

Everything above happens inside `iac_agent.run_loop`; this page only shows what it returned.

**Fail closed, always.** A scanner that crashes, times out, produces no output, or reports a
fatal condition raises an error. It is never converted into an empty finding list — an absence
of analysis is not a passing result, and this page renders the two differently and loudly.

**Filenames are load-bearing.** Both Checkov and Trivy select their Dockerfile rules by
*filename*, so a Dockerfile saved as `.tf` scans clean and reports a false pass. Anything you
upload here is written under a name that implies its type before a scanner sees it.
        """
    )

    ui.eyebrow("why the loop stops")
    st.markdown(
        "| stop reason | means | \n| --- | --- |\n"
        + "\n".join(
            f"| `{reason.name}` | **{STOP_REASONS.get(reason.name, (reason.name, ''))[0]}.** "
            f"{STOP_REASONS.get(reason.name, ('', ''))[1]} |"
            for reason in StopReason
        )
    )

    ui.eyebrow("run configuration")
    st.markdown(
        f"""
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
harness in `eval/` is what produces the numbers in *measured results*. The design brief for this
page — and the rules it is held to — are in `docs/UI_DESIGN.md`.
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


# Cached because it is deterministic and slow: the same file through the same scanner takes
# about five seconds and returns the same thing every time, and re-scanning after glancing at
# another tab was the commonest reason to wait. `_do_fix` is deliberately *not* cached — it
# spends money and it is not reproducible, so memoising it would quietly turn a second paid run
# into a replay of the first, which is exactly the kind of substitution this project objects to
# everywhere else.
@st.cache_data(show_spinner=False)
def _do_scan(name: str, code: str, scanner: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        iac_type, target = _prepare(name, code, workdir)
        result = get_scanner(scanner).scan(target, iac_type)
        return {
            "kind": "scan",
            "name": name,
            "scanner": scanner,
            "iac_type": iac_type.value,
            "code": code,
            "scanned_as": target.name,
            "findings": _finding_rows(result.failed, workdir),
            "passed": result.passed_count,
            "parse_errors": result.parse_errors,
        }


def _do_fix(
    name: str,
    code: str,
    scanner: str,
    max_iters: int,
    on_step: Any | None = None,
) -> dict:
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
            on_step=on_step,
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
            "baseline_findings": _finding_rows(result.baseline.failed, workdir),
            "final_findings": (
                _finding_rows(best_scan.failed, workdir) if best_scan is not None else None
            ),
            "changes": (
                _change_rows(
                    result.baseline.failed,
                    best_scan.failed if best_scan is not None else None,
                    result.resolved,
                    result.introduced,
                    iac_type,
                    workdir,
                )
                if best_scan is not None
                else None
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


def _report_step(stage: str, record: Any | None) -> None:
    """Write one line into the open status box as `run_loop` reaches each stage.

    The wording is chosen here, not in the package: `run_loop` reports stage names. Vocabulary
    matches the rail deliberately — someone who watched *cleared the gates* appear during the
    run should find the same phrase under the same station afterwards.
    """
    if stage == "baseline" and record is not None and record.scan is not None:
        st.write(f"Baseline: **{record.scan.failed_count}** failed checks. Asking the model.")
    elif stage == "detected":
        st.write("The model has read the file. Generating a rewrite.")
    elif stage == "iteration" and record is not None:
        if record.rejected_because:
            st.write(
                f"Iteration {record.index}: **{_truncate(record.rejected_because, 90)}** — "
                "never scanned."
            )
        elif record.scan is not None:
            st.write(
                f"Iteration {record.index}: cleared the gates · "
                f"**{record.scan.failed_count}** failed."
            )


def _render_failure(failure: dict) -> None:
    """A failure is never allowed to look like a clean result."""
    if failure["kind"] == "scanner":
        st.error(
            "### The scanner did not run\n"
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
    count = len(payload["findings"])
    # The "scanned as …" line only says something when the name on disk differs from the name
    # you chose — an upload, or a Dockerfile, which is the case it was written for. On a
    # bundled `.tf` the two are identical and it spent a line of the verdict restating the
    # filename directly above it.
    renamed = (
        ""
        if payload["scanned_as"] == payload["name"]
        else (
            f"<br>scanned as {_mono(payload['scanned_as'])} ({_esc(payload['iac_type'])}), so "
            f"the scanner selects the right ruleset"
        )
    )
    ui.verdict(
        str(count),
        "failed checks" if count != 1 else "failed check",
        f"{_mono(payload['scanner'])} on {_mono(payload['name'])} · "
        f"{payload['passed']} checks passed · <i>no model was called</i>{renamed}",
        tone="blocked" if count else "verified",
    )
    ui.eyebrow("findings")
    picked = _render_scan_outcome(
        payload["findings"],
        payload["scanner"],
        payload["passed"],
        payload["parse_errors"],
        select_key="scan_findings",
    )
    if payload["findings"]:
        # The one thing a findings table cannot do is show you the code. Selecting a row puts
        # the cited line on screen next to the rule that objected to it, which is the step the
        # reader was otherwise making by hand: read a line number, scroll to the bottom of the
        # page, open the input, and count.
        if picked is None:
            st.caption("Select a row to see the line it is about, in full.")
        else:
            line = picked.get("line")
            line = None if pd.isna(line) else int(line)
            where = f"line {line}" if line else "no line reported"
            # Also where the row's own text goes when the column was too narrow for it: the
            # resource and the message are untruncated here, and the rule's documentation is
            # a link rather than a column of the word "open".
            detail = f"`{picked['rule']}` · `{picked.get('resource') or '—'}` · {where}"
            if picked.get("docs"):
                detail += f" · [rule documentation]({picked['docs']})"
            st.caption(f"{detail}\n\n{picked['finding']}")
            ui.source_excerpt(payload["code"], line)
    st.caption(
        "This is the baseline the LLM has to beat. On the original fixtures the scanners find "
        "more than the model does on its own — the *measured results* tab has the recall "
        "numbers."
    )
    # The free path produced nothing you could take away with you; the paid one did.
    st.download_button(
        "JSON report",
        data=json.dumps(
            {
                key: payload[key]
                for key in ("name", "iac_type", "scanner", "scanned_as", "passed",
                            "parse_errors", "findings")
            },
            indent=2,
        ),
        file_name="iac_security_scan.json",
        mime="application/json",
    )


def _render_rail(payload: dict) -> None:
    """The loop's progression, drawn against the gates each candidate had to survive."""
    before = payload["before"]
    rows: list[dict] = [
        {
            "iteration": "baseline",
            "reached": ST_INPUT,
            "tone": MUTED,
            "unverified": False,
            "finished": not payload["accepted_any"],
            "outcome": (
                f"the file as given · <b>{before}</b> failed"
                + ("" if payload["accepted_any"] else " · <i>this is what was returned</i>")
            ),
        }
    ]
    for record in payload["iterations"]:
        station, label, tone, unverified = _station(record)
        findings = record["findings"]
        detail = f"<b>{findings}</b> failed" if findings is not None else "never scanned"
        reason = _truncate(record["reason"], 62)
        rows.append(
            {
                "iteration": f"iter {record['index']}",
                "reached": ST_RETURNED if record["is_best"] else station,
                "tone": tone,
                "unverified": unverified,
                "finished": record["is_best"],
                "full": record["reason"] or "",
                "outcome": (
                    f"{_esc(label)} · {detail}"
                    f"<br><i>{_esc(reason) + ' · ' if reason else ''}"
                    f"{record['tokens']} tokens</i>"
                ),
            }
        )

    ui.gate_rail(
        rows,
        "A candidate that comes to rest before <b>rescan</b> was never written to disk and "
        "never scanned, so it cannot post a count — a deletion has no way to be recorded as an "
        "improvement. Its reason is fed back to the model as the next turn's instruction, which "
        "is why a rejection is often followed by a real fix.",
    )


def _render_drift_verdict(payload: dict) -> None:
    rejections = [
        record
        for record in payload["iterations"]
        if (record["reason"] or "").startswith("drift")
    ]
    if rejections:
        st.error(
            f"**The drift gate rejected {len(rejections)} proposed fix(es).** "
            "A Terraform resource or module was removed or renamed, its count, for_each, "
            "or module source changed, or protected Dockerfile application structure changed. "
            "Each candidate was rejected before rescanning."
        )
        for record in rejections:
            summary = f" · structural diff: {record['drift_summary']}" if record["drift_summary"] else ""
            st.caption(f"Iteration {record['index']} — `{record['reason']}`{summary}")
        return

    if payload["drift_note"]:
        st.warning(
            f"**Drift was not checked.** {payload['drift_note']}. That is not the same as "
            "'no drift' — this run cannot tell you whether resources were removed."
        )
        return

    checked = sum(1 for record in payload["iterations"] if record["drift_checked"])
    if checked:
        if payload["iac_type"] == IaCType.DOCKERFILE.value:
            st.success(
                f"**Dockerfile structural gate ran on {checked} candidate(s).** "
                "Changes to protected stages, per-stage copy sources or startup commands "
                "are rejected before scanning. "
                "This does not prove the image builds or preserves its behavior."
            )
        else:
            st.success(
                f"**Resource drift gate ran on {checked} candidate(s).** "
                "Protected resource and module identity changes are rejected before scanning. "
                "Review the accepted configuration before applying it."
            )
    else:
        st.info(
            "No candidate reached the drift gate — every attempt failed the parse gate first."
        )


def _render_fix(payload: dict) -> None:
    before, after = payload["before"], payload["after"]
    title, explanation = STOP_REASONS.get(
        payload["stop_reason"], (payload["stop_reason"], "")
    )

    if after is None:
        ui.verdict(
            "—",
            "failed checks after",
            f"{_mono(payload['scanner'])} loop on {_mono(payload['name'])} · the returned "
            f"candidate was <b>never scanned</b>, so there is no count. This is not a clean "
            f"result · was {before} at baseline",
            tone="signal",
        )
    else:
        delta = after - before
        tone_word = "verified" if delta < 0 else ("blocked" if delta > 0 else "muted")
        movement = (
            f'<span class="ix-delta" data-tone="{tone_word}">'
            f"{'+' if delta > 0 else ''}{delta} vs baseline</span>"
        )
        # The stop reason is stated once, by the caption below, which is the line that can
        # also explain it. Naming it here as well meant reading "hit the iteration cap" twice
        # in adjacent lines, in two sizes, and it was what pushed the qualifier onto a fourth
        # wrapped row.
        ui.verdict(
            str(after),
            "failed checks after",
            f"{movement} &nbsp; {_mono(payload['scanner'])} loop on {_mono(payload['name'])} · "
            f"was {before} at baseline<br>"
            f"{payload['resolved']} resolved · {payload['introduced']} introduced · "
            f"{payload['tokens']} tokens of {TOKEN_BUDGET_DEFAULT}",
            tone="verified" if after == 0 else "blocked",
        )
    st.caption(
        f"**{title}** (`{payload['stop_reason']}`) — {explanation} "
        "*Introduced* findings are the ones the rewrite created; they are never subtracted "
        "from *resolved*."
    )

    if payload["aborted"]:
        st.warning(f"**The run ended on an error, not a planned stop:** {payload['aborted']}")

    # The drift verdict sits above everything else on purpose: a run that lowered the count by
    # deleting the offending resource looks like a success in every other number on this page.
    _render_drift_verdict(payload)

    if not payload["accepted_any"]:
        scanned = sum(1 for record in payload["iterations"] if record["accepted"])
        if scanned:
            st.info(
                f"**No candidate beat the baseline.** {scanned} candidate(s) cleared every "
                "gate and were scanned, but none scored better than the file you started "
                "with, so the original is returned unchanged."
            )
        else:
            st.info(
                "**No candidate cleared the gates**, so the original file is returned "
                "unchanged. The count did not move because nothing was allowed to move it."
            )

    ui.eyebrow("how that number was reached")
    _render_rail(payload)

    # Above the evidence rather than after all of it: taking the remediated file away is a
    # thing people come here to do, and it used to be reachable only by scrolling past a diff,
    # a comparison table and the model's own claims.
    bar = st.container(horizontal=True)
    bar.download_button(
        "Remediated file",
        data=payload["fixed_code"],
        file_name=payload["output_name"],
        mime="text/plain",
    )
    bar.download_button(
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
    )

    ui.eyebrow("evidence")
    view = st.segmented_control(
        "Evidence",
        ["diff", "findings", "what the model claimed"],
        default="diff",
        label_visibility="collapsed",
    )
    if view == "findings":
        if payload["changes"] is None:
            st.error(
                "The returned candidate was never scanned, so there is no 'after' list to "
                "compare against. This is not a clean result."
            )
            st.markdown(f"**Baseline — {before} failed**")
            _render_severity_summary(payload["baseline_findings"], payload["scanner"])
            if payload["baseline_findings"]:
                _render_findings_table(
                    payload["baseline_findings"], severity_stated_above=True
                )
        else:
            # One table, full width, with what happened to each finding in the first column —
            # rather than two half-width tables the reader had to diff by eye while both of
            # them truncated. Sorted introduced → still failing → resolved.
            st.caption(
                f"Every finding on both sides of the run: {before} at baseline, {after} in "
                "the returned file. Line numbers are in the original file for *resolved* rows "
                "and in the returned file for the rest, because that is where each one is."
            )
            if not payload["final_findings"]:
                # Nothing is left to sit in the table's "still failing" and "introduced"
                # groups, so the clean-result statement has to be made explicitly — an empty
                # group is not the same claim as a scanner that ran and found nothing.
                _render_scan_outcome(
                    payload["final_findings"],
                    payload["scanner"],
                    payload["final_passed"],
                    payload["final_parse_errors"],
                )
            if payload["changes"]:
                _render_findings_table(payload["changes"])
    elif view == "what the model claimed":
        st.caption(
            f"The model's own detection pass ({payload['detect_tokens']} tokens). It is "
            "shown because it is *not* what the count above is based on — the scanners are. "
            "Measured on the fixtures, the model's detection recall is worse than Checkov "
            "alone; the *measured results* tab has both numbers."
        )
        if payload["issues"]:
            st.dataframe(pd.DataFrame(payload["issues"]), hide_index=True)
        else:
            st.info("The model reported nothing, or was never asked.")
    else:
        _render_diff(
            payload["code"],
            payload["fixed_code"],
            payload["name"],
            payload["output_name"],
            _language(payload["iac_type"]),
        )

    with st.expander("Run summary, as the package prints it"):
        st.code(payload["summary"], language="text", wrap_lines=True)


# --------------------------------------------------------------------------------------
# page
# --------------------------------------------------------------------------------------

samples = _list_samples()
fix_enabled, fix_reason = _fix_availability()

ui.masthead(
    "static scanners detect · a model rewrites · the scanners <b>verify</b>",
    f"iac_agent {__version__} · {ModelConfig().model}",
)

with st.sidebar:
    # No mode switch. There used to be a Bundled sample / Upload radio, and switching back to
    # the samples unmounted the uploader — which in Streamlit discards the uploaded file, so a
    # visitor who uploaded their own Terraform and then glanced at a fixture lost it and had to
    # upload again, with nothing on screen explaining why. Showing both controls removes the
    # mode, the trap and a rerun: an uploaded file simply wins over the sample beneath it.
    ui.eyebrow("source")

    input_name: str | None = None
    input_code: str | None = None
    input_error: str | None = None

    if not samples:
        input_error = f"No usable fixtures found in `{SAMPLES_DIR.name}/`. Upload a file."
    else:
        by_name = {path.name: path for path in samples}
        names = list(by_name)
        # Open on Terraform so the first run illustrates resource-address drift,
        # the project's measured evaluation case. Dockerfile structural drift is
        # also checked, but it answers a different and narrower question.
        default = next((i for i, n in enumerate(names) if n.endswith(".tf")), 0)
        picked = st.selectbox(
            "Fixture",
            names,
            index=default,
            label_visibility="collapsed",
            help="Listed from `samples/` at page load, so fixtures added to the repo "
            "appear here without touching `app.py`. Every one of them is deliberately "
            "vulnerable.",
        )
        chosen = by_name[picked]
        try:
            input_code = chosen.read_text(encoding="utf-8")
            input_name = chosen.name
        except OSError as exc:
            input_error = f"Could not read `{chosen}`: {exc}"
        else:
            st.caption(f"{len(input_code.splitlines())} lines · deliberately vulnerable")

    # In an expander only so the drop zone does not out-size the fixture picker, which is the
    # path almost everyone takes. Collapsing it does not unmount the widget — that is the
    # difference from the radio, and the whole reason this is not a mode.
    with st.expander("…or upload your own"):
        uploaded = st.file_uploader(
            "Terraform or Dockerfile",
            label_visibility="collapsed",
            help="Accepted: `*.tf`, `Dockerfile`, `*.Dockerfile`. Takes precedence over the "
            "fixture above. Nothing leaves this machine unless you press **Scan, fix and "
            "verify**.",
        )
    if uploaded is not None:
        try:
            uploaded_code = uploaded.getvalue().decode("utf-8")
        except UnicodeDecodeError:
            input_error = "That file is not UTF-8 text, so it is not IaC source."
        else:
            uploaded_name = Path(uploaded.name).name
            try:
                detect_iac_type(uploaded_name)
            except IaCAgentError as exc:
                input_error = str(exc)
            else:
                input_name, input_code, input_error = uploaded_name, uploaded_code, None

    ui.eyebrow("scanner")
    scanner_name = st.selectbox(
        "Scanner",
        sorted(SCANNERS),
        label_visibility="collapsed",
        help="The tool must be installed. If it cannot run, this page says so — it never "
        "reports a missing scanner as a clean file.",
    )
    # Asked before the run rather than after it. `pip install` provides Checkov and does not
    # provide Trivy, which is a Go binary — so the commonest way to lose two minutes here was
    # to pick Trivy, press the button, and read a scanner failure at the end. The failure is
    # still rendered correctly if it happens; this just means it usually does not have to.
    scanner_installed = scanner_path(scanner_name) is not None
    if not scanner_installed:
        st.caption(
            f"⚠︎ `{scanner_name}` is not on PATH, so it cannot run. Install it, or pick the "
            "other scanner."
        )
    # "Max iterations" of what was ambiguous next to two buttons, only one of which iterates.
    max_iters = st.slider(
        "Max fix iterations",
        1,
        5,
        3,
        help="How many rewrites the loop may attempt before returning the best candidate "
        "it has seen. No effect on **Scan only**.",
    )

    ui.eyebrow("run")
    ready = input_name is not None and input_code is not None and scanner_installed
    # The reason a button is dead belongs above the button, not under it: read in order, the
    # old arrangement showed a greyed-out control first and explained it second.
    if input_error:
        st.caption(f"⚠︎ {input_error}")
    # Cost belongs in the label. It used to live only in `help=`, and a Streamlit button gives
    # no sign it has a tooltip — so the one thing a first-time visitor most needs to know
    # before clicking, that this button spends money, was behind a hover they had no reason to
    # try. Emphasis follows what they can actually do, too: without a key the paid button is
    # disabled, and leaving it styled as the primary action made the loudest control on the
    # page the one nothing happens on.
    scan_clicked = st.button(
        "Scan only — free",
        type="secondary" if fix_enabled else "primary",
        width="stretch",
        disabled=not ready,
        help="Runs the scanner. No API key, no model, no cost.",
    )
    fix_clicked = st.button(
        "Scan, fix and verify — paid",
        type="primary" if fix_enabled else "secondary",
        width="stretch",
        disabled=not (ready and fix_enabled),
        help=fix_reason if not fix_enabled else "Calls the model. This one costs money.",
    )
    if fix_enabled:
        # Available is the uninteresting case: one quiet line, expandable.
        with st.popover("Fixing is available", width="stretch"):
            st.markdown(fix_reason)
    else:
        # Unavailable is the case someone is stuck on, and a disabled button's tooltip is not
        # where you explain why it is disabled — several browsers never show one.
        st.caption(f"**Fixing is unavailable.** {fix_reason}")

with st.sidebar:
    st.caption(
        "The supported interface is the CLI (`python -m iac_agent.cli`); this page is a view "
        "over the same package."
    )

tab_run, tab_drift, tab_results, tab_how = st.tabs(
    ["analyse", "drift gate", "measured results", "method"]
)

with tab_run:
    # The empty state used to describe the button rather than contain one: it read "press Scan
    # only", while the actual control was in the other column, past three groups the visitor
    # had not learned yet. This is the same action, in the place they are already looking. It
    # has to be declared before the run block below, or the click would arrive on a rerun in
    # which that block had already decided nothing was pressed.
    idle_holder = st.empty()
    if not st.session_state.get("outcome") and not st.session_state.get("failure"):
        with idle_holder.container():
            ui.empty(
                "nothing has been run",
                "A fixture from <b>samples/</b> is already selected. Scanning is free — no API "
                "key, no model call. <b>Scan, fix and verify</b> in the left rail adds the "
                "model and the gates, and calls a paid API.",
            )
            scan_clicked = scan_clicked or st.button(
                "Scan only — free",
                type="primary",
                disabled=not ready,
                key="scan_from_empty_state",
            )

    if (scan_clicked or fix_clicked) and input_name is not None and input_code is not None:
        # The invitation goes away the moment it is accepted — it is written in a placeholder
        # so a run started from it does not leave "nothing has been run" above its own result.
        idle_holder.empty()
        st.session_state.pop("outcome", None)
        st.session_state.pop("failure", None)
        label = (
            f"Scanning `{input_name}` with {scanner_name}…"
            if scan_clicked
            else f"Detect → fix → verify on `{input_name}`…"
        )
        # In a placeholder so a finished run can clear its own progress box. Left in place it
        # was a full-width bordered bar reading "Done", sitting between the tab strip and the
        # answer for the rest of the session.
        status_holder = st.empty()
        with status_holder.status(label, expanded=True) as status:
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
                    # Reported as it happens rather than asserted up front. The box used to
                    # list three numbered steps before any of them had run — claiming work was
                    # done and then sitting still for a minute of model calls — which is both
                    # a lie and the least reassuring thing a slow operation can do.
                    st.write(
                        f"Baseline scan, then up to {max_iters} rewrite(s), each through the "
                        "parse and drift gates before it is allowed near a scanner."
                    )
                    st.session_state["outcome"] = _do_fix(
                        input_name, input_code, scanner_name, max_iters, _report_step
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
                status_holder.empty()

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

    # The source shown belongs to the *result* shown, not to whatever is selected in the rail.
    # Those diverge the moment someone changes the fixture without re-running, and the old
    # version put the new file's code directly beneath the old file's findings — line numbers
    # in the table indexing a listing they did not come from.
    shown_name = outcome["name"] if outcome else input_name
    shown_code = outcome["code"] if outcome else input_code
    if shown_code and shown_name:
        with st.expander(f"Input — {shown_name}", expanded=False):
            st.code(
                shown_code,
                language=_language_of(shown_name),
                line_numbers=True,
                height=420,
            )

with tab_drift:
    _render_drift_primer()

with tab_results:
    _render_results_page()

with tab_how:
    _render_how_it_works()
