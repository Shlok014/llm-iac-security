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
    learns a new rejection, this test is where you find out the rail needs a station for it."""
    emitted = set(re.findall(r'rejected_because[ =]+.{0,20}?f?"([a-z_]+):', LOOP_PATH.read_text()))
    emitted |= set(re.findall(r'= "([a-z_]+): ', LOOP_PATH.read_text()))
    handled = {prefix.rstrip(":") for prefix, *_ in app.REJECTION_KINDS}
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


def test_the_api_key_is_never_read_into_the_page(app_source: str):
    """`_fix_availability` reports whether a key is *available*; it must never put the value on
    screen. Only the presence check may touch the environment variable."""
    reads = re.findall(r'os\.getenv\("OPENAI_API_KEY"\)', app_source)
    assert len(reads) == 1, "OPENAI_API_KEY should be touched exactly once, as a presence check"
    assert 'os.environ["OPENAI_API_KEY"]' not in app_source
