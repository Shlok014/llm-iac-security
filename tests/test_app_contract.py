"""What the Streamlit view is not allowed to do.

These are the mechanically checkable half of `docs/UI_DESIGN.md` §6. They are regression guards
rather than unit tests: each one exists because breaking it would make the page assert something
the run did not establish, which is the failure mode this project is about.

`app.py` is imported by path — it is deliberately not part of the installed package, and
importing it outside a Streamlit runtime prints warnings but does not raise.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_PATH = REPO_ROOT / "app.py"
LOOP_PATH = REPO_ROOT / "iac_agent" / "loop.py"


@pytest.fixture(scope="module")
def app():
    spec = importlib.util.spec_from_file_location("_app_under_test", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def app_source() -> str:
    return APP_PATH.read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------
# the rail cannot draw a rejected candidate as having been scanned
# --------------------------------------------------------------------------------------


def test_every_rejection_the_loop_emits_is_recognised_by_the_view(app):
    """A rejection kind the page does not know about falls into the catch-all and is drawn as
    unverified. That is the safe default, but it is not the *informative* one — if `loop.py`
    learns a new rejection, this test is where you find out the rail needs a station for it.

    The scrape has to tolerate a line break between `rejected_because =` and its value, because
    `invalid:` is written that way and the original two regexes — both single-line — could not
    see it. A guard with a hole in it is worse than no guard: it reports that it checked.
    """
    source = LOOP_PATH.read_text()
    emitted = set(
        re.findall(r"rejected_because\s*=\s*\(?\s*f?\"([a-z_]+):", source, re.S)
    )
    handled = {prefix.rstrip(":") for prefix, *_ in app.REJECTION_KINDS}
    assert "invalid" in emitted, (
        "the scrape stopped seeing `invalid:` — it is written across a line break in loop.py, "
        "and that is the case this regex exists to survive"
    )
    unhandled = {kind for kind in emitted if kind not in handled}
    assert not unhandled, (
        f"`loop.py` can emit rejection kind(s) {sorted(unhandled)} that `REJECTION_KINDS` does "
        "not map to a station. Add them, or the rail will show them as 'reason unrecognised'."
    )


def test_a_gate_rejection_never_reaches_the_scanner_on_the_rail(app):
    """Parse and drift rejections must come to rest strictly before `rescan`. This is the whole
    claim: a candidate that was thrown out at a gate was never scanned, so it cannot post a
    count, and the drawing must not suggest otherwise."""
    for prefix, station, label, _tone, _unverified in app.REJECTION_KINDS:
        if prefix.startswith(("drift", "invalid", "llm_error")):
            assert station < app.ST_RESCAN, (
                f"{prefix!r} ({label}) is drawn at station {station}, at or past `rescan`. "
                "A candidate rejected at a gate is never written to disk and never scanned."
            )


def test_scan_failure_is_the_only_kind_that_reaches_rescan_and_it_is_unverified(app):
    """`scan_failed` genuinely got as far as the scanner — the scanner is what failed. It is the
    one rejection allowed at `rescan`, and it must be dashed, because the candidate's real state
    is unknown rather than bad."""
    at_rescan = [k for k in app.REJECTION_KINDS if k[1] >= app.ST_RESCAN]
    assert [k[0] for k in at_rescan] == ["scan_failed:"]
    assert at_rescan[0][4] is True, "an unverified candidate must take the dashed treatment"


def test_an_unrecognised_rejection_fails_closed(app):
    """'We do not know where this stopped' must resolve to the earliest station it could have
    stopped at, never the latest — otherwise a future rejection kind would be drawn as scanned."""
    station, _label, _tone, unverified = app._station(
        {"accepted": False, "reason": "some_future_kind: whatever"}
    )
    assert station < app.ST_RESCAN
    assert unverified is True


def test_provider_failure_does_not_claim_a_candidate_failed_parsing(app, monkeypatch):
    shown = []
    monkeypatch.setattr(app.st, "info", shown.append)
    app._render_drift_verdict({
        "aborted": "detection failed: provider returned HTTP 500",
        "iterations": [], "drift_note": "", "iac_type": "terraform",
    })
    assert shown
    assert "not reached" in shown[0].lower()
    assert "parse gate" not in shown[0].lower()


def test_rewrite_provider_failure_does_not_claim_a_candidate_failed_parsing(app, monkeypatch):
    shown = []
    monkeypatch.setattr(app.st, "info", shown.append)
    app._render_drift_verdict({
        "aborted": "model call failed on iteration 1: provider returned HTTP 500",
        "iterations": [{"reason": "llm_error: provider returned HTTP 500", "drift_checked": False}],
        "drift_note": "", "iac_type": "terraform",
    })
    assert shown
    assert "not reached" in shown[0].lower()
    assert "parse gate" not in shown[0].lower()


def test_provider_failure_labels_the_count_as_baseline_not_after(app):
    payload = {
        "aborted": "detection failed: provider returned HTTP 500",
        "iterations": [],
    }
    assert app._fix_count_label(payload) == "baseline failed checks"


def test_the_drift_gate_is_drawn_before_the_rescan(app):
    """The station order is the argument, not a layout preference: drift is checked before the
    rescan precisely so a deletion cannot score."""
    import ui_theme

    names = [name for name, _hint in ui_theme.STATIONS]
    assert names.index("drift") < names.index("rescan") < names.index("returned")
    assert names.index("parse") < names.index("drift")


# --------------------------------------------------------------------------------------
# "not verified" is never dressed up as a result
# --------------------------------------------------------------------------------------


def test_unknown_severity_is_not_the_palest_chip():
    """Checkov's community build reports `unknown` for most checks. Rendering it as the faintest
    thing on screen would contradict the caption that sits directly beneath it."""
    import ui_theme

    assert ui_theme.SEVERITY_TONE["unknown"] == ui_theme.SEVERITY_TONE["high"], (
        "`unknown` must carry the signal colour — it means the scanner declined to say, not "
        "that the finding is minor."
    )
    assert ui_theme.SEVERITY_TONE["unknown"] != ui_theme.SEVERITY_TONE["info"]


def test_the_view_types_no_measured_number(app_source: str):
    """`app.py`'s own docstring promises this: evaluation figures are read from
    `eval/results/RESULTS.md` at runtime. A figure typed into the page cannot go stale loudly,
    so it must not be typed in at all."""
    forbidden = [
        (r"\b\d+\s+of\s+\d+\b", "an 'N of M runs' style figure"),
        (r"\b\d+(?:\.\d+)?\s*%", "a percentage"),
    ]
    for pattern, description in forbidden:
        found = re.findall(pattern, app_source)
        assert not found, (
            f"app.py contains {description}: {found}. Measured numbers belong in "
            "eval/results/RESULTS.md, which the page renders at load."
        )


def test_the_results_page_reads_from_disk_rather_than_restating(app, app_source: str):
    assert app.RESULTS_MD.parent.name == "results"
    assert "RESULTS_MD.read_text" in app_source
    assert "RESULTS_MD.is_file()" in app_source


def test_the_fixture_list_is_read_at_runtime(app):
    """A hardcoded list would silently hide fixtures added to `samples/`."""
    listed = {path.name for path in app._list_samples()}
    on_disk = {
        path.name
        for path in (REPO_ROOT / "samples").iterdir()
        if path.is_file() and not path.name.startswith(".") and path.suffix != ".md"
    }
    assert listed <= on_disk
    assert listed, "no fixtures were listed from samples/"


# --------------------------------------------------------------------------------------
# the before/after comparison must not invent its own idea of "resolved"
# --------------------------------------------------------------------------------------


def _finding(rule: str, resource: str, line: int = 1, file: str = "/wd/x.tf"):
    from iac_agent.types import Finding

    return Finding(
        rule_id=rule,
        severity="unknown",
        resource=resource,
        message=f"{rule} says no",
        scanner="checkov",
        file=file,
        line=line,
        guideline="",
    )


def test_the_comparison_table_classifies_from_the_loops_own_key_sets(app):
    """`resolved` and `introduced` are decided in `iac_agent.loop`. The page labels rows from
    those sets and from nothing else — if it recomputed the comparison it could disagree with
    the counts printed directly above it, which is the failure this project is about."""
    from iac_agent.types import IaCType

    baseline = [_finding("CKV_AWS_1", "aws_s3_bucket.b"), _finding("CKV_AWS_2", "aws_s3_bucket.b")]
    final = [_finding("CKV_AWS_2", "aws_s3_bucket.b"), _finding("CKV_AWS_9", "aws_s3_bucket.b")]

    rows = app._change_rows(
        baseline,
        final,
        resolved={("CKV_AWS_1", "aws_s3_bucket.b")},
        introduced={("CKV_AWS_9", "aws_s3_bucket.b")},
        iac_type=IaCType.TERRAFORM,
        workdir=Path("/wd"),
    )
    by_rule = {row["rule"]: row["status"] for row in rows}
    assert by_rule == {
        "CKV_AWS_1": "resolved",
        "CKV_AWS_2": "still failing",
        "CKV_AWS_9": "introduced",
    }


def test_the_comparison_table_joins_dockerfile_findings_across_scan_locations(app):
    """The baseline is scanned where the input was written and the candidate in the loop's
    output directory, so Checkov names the same Dockerfile instruction two different ways. The
    page must use `finding_key` — the package's own normalisation — or every finding would look
    resolved and every surviving one newly introduced."""
    from iac_agent.types import IaCType

    rows = app._change_rows(
        [_finding("CKV_DOCKER_1", "/wd/Dockerfile.EXPOSE", file="/wd/Dockerfile")],
        [_finding("CKV_DOCKER_1", "/wd/out/fixed.Dockerfile.EXPOSE", file="/wd/out/fixed.Dockerfile")],
        resolved=set(),
        introduced=set(),
        iac_type=IaCType.DOCKERFILE,
        workdir=Path("/wd"),
    )
    assert [row["status"] for row in rows] == ["still failing"]


def test_every_status_the_comparison_emits_has_a_sort_position(app):
    """A status missing from `CHANGE_ORDER` would raise at sort time, in the middle of
    rendering a paid run's result."""
    from iac_agent.types import IaCType

    rows = app._change_rows(
        [_finding("CKV_AWS_1", "r"), _finding("CKV_AWS_2", "r")],
        [_finding("CKV_AWS_2", "r"), _finding("CKV_AWS_3", "r")],
        resolved={("CKV_AWS_1", "r")},
        introduced={("CKV_AWS_3", "r")},
        iac_type=IaCType.TERRAFORM,
        workdir=Path("/wd"),
    )
    assert {row["status"] for row in rows} <= set(app.CHANGE_ORDER)
    # Worst news first: what the rewrite created, then what it left, then what it fixed.
    assert [row["status"] for row in rows] == ["introduced", "still failing", "resolved"]


# --------------------------------------------------------------------------------------
# a scratch path is not a resource name
# --------------------------------------------------------------------------------------


def test_only_paths_inside_the_run_directory_are_shortened(app):
    """Checkov names a Dockerfile finding after the file it was in, so scanning out of a
    temporary directory puts sixty characters of machine path in the resource column. Anything
    the scanner reports that is *not* inside this run's own scratch directory is left alone —
    shortening it would be editing the scanner's answer."""
    workdir = Path("/wd")
    assert app._display_resource("/wd/Dockerfile.ADD", workdir) == "Dockerfile.ADD"
    assert app._display_resource("/wd/out/fixed.Dockerfile.ADD", workdir) == "fixed.Dockerfile.ADD"
    assert app._display_resource("aws_s3_bucket.public", workdir) == "aws_s3_bucket.public"
    assert app._display_resource("/elsewhere/Dockerfile.ADD", workdir) == "/elsewhere/Dockerfile.ADD"
    assert app._display_resource("", workdir) == ""


# --------------------------------------------------------------------------------------
# the design doc is a specification, so it has to still be true
# --------------------------------------------------------------------------------------


def _hex_pairs(pattern: str, text: str) -> dict[str, tuple[str, str]]:
    return {
        m.group(1): (m.group(2).upper(), m.group(3).upper())
        for m in re.finditer(pattern, text, re.M)
    }


def test_the_documented_palette_is_the_palette_in_the_code():
    """`docs/UI_DESIGN.md` §3 is a token table, not prose about one: a reader is entitled to
    copy a hex out of it. It drifted twice — `paper` was documented as a colour that appears
    nowhere in the repository, and two severity values outlived a change made in the same
    commit that documented the change. Cheaper to check than to notice."""
    ui = (REPO_ROOT / "ui_theme.py").read_text(encoding="utf-8")
    doc = (REPO_ROOT / "docs" / "UI_DESIGN.md").read_text(encoding="utf-8")
    cfg = (REPO_ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")

    documented = _hex_pairs(
        r"^\|\s*`([a-z-]+)`\s*\|\s*`(#[0-9A-Fa-f]{6})`\s*\|\s*`(#[0-9A-Fa-f]{6})`", doc
    )
    assert documented, "§3's token table did not parse — has its shape changed?"

    for token, (light, dark) in documented.items():
        if token == "paper":
            # The page ground is Streamlit's, not ours: it lives in the theme file.
            actual = re.search(r'backgroundColor\s*=\s*"(#[0-9A-Fa-f]{6})"', cfg)
            assert actual, "no backgroundColor in .streamlit/config.toml"
            assert actual.group(1).upper() == light, (
                f"§3 documents paper as {light}, but config.toml sets {actual.group(1)}"
            )
            continue
        found = re.search(
            rf"^\s*--ix-{re.escape(token)}\s*:\s*light-dark\((#[0-9A-Fa-f]{{6}}),\s*"
            rf"(#[0-9A-Fa-f]{{6}})\)",
            ui,
            re.M,
        )
        assert found, f"§3 documents a `{token}` token that ui_theme.py does not define"
        assert (found.group(1).upper(), found.group(2).upper()) == (light, dark), (
            f"§3 documents `{token}` as {light}/{dark}; ui_theme.py has "
            f"{found.group(1)}/{found.group(2)}"
        )


def test_the_documented_severity_ramp_is_the_ramp_in_the_code():
    import ui_theme

    doc = (REPO_ROOT / "docs" / "UI_DESIGN.md").read_text(encoding="utf-8")
    ramp = re.search(
        r"`critical (#[0-9A-Fa-f]{6})` → `high (#[0-9A-Fa-f]{6})` → "
        r"`medium (#[0-9A-Fa-f]{6})` → `low (#[0-9A-Fa-f]{6})` → `info (#[0-9A-Fa-f]{6})`",
        doc,
    )
    assert ramp, "§3's severity ramp sentence did not parse"
    for index, severity in enumerate(("critical", "high", "medium", "low", "info"), start=1):
        actual = re.search(
            r"light-dark\((#[0-9A-Fa-f]{6})", ui_theme.SEVERITY_TONE[severity][0]
        )
        assert actual and actual.group(1).upper() == ramp.group(index).upper(), (
            f"§3 documents `{severity}` as {ramp.group(index)}; SEVERITY_TONE has "
            f"{actual.group(1) if actual else '?'}"
        )


def test_the_api_key_is_never_read_into_the_page(app_source: str):
    """`_fix_availability` reports whether a key is *available*; it must never put the value on
    screen. Only the presence check may touch the environment variable."""
    reads = re.findall(r'os\.getenv\("OPENAI_API_KEY"\)', app_source)
    assert len(reads) == 1, "OPENAI_API_KEY should be touched exactly once, as a presence check"
    assert 'os.environ["OPENAI_API_KEY"]' not in app_source
