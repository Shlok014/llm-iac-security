"""Tests for the CLI's exit-code contract.

The four codes are a documented interface, not an implementation detail — CI keys on them, and
`.github/workflows/ci.yml` asserts them on every push. The separation that matters is `1` from
`2`: *the tool answered and the answer is bad* versus *the tool did not answer*. A pipeline that
cannot tell those apart has the project's founding bug again, one layer up.

`scan` must never construct a model client, so every test here runs with no API key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iac_agent.cli import EXIT_FINDINGS, EXIT_LLM, EXIT_OK, EXIT_TOOLING, main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

CLEAN_TF = 'variable "region" {\n  type = string\n}\n'


def test_exit_codes_are_the_documented_four() -> None:
    assert (EXIT_OK, EXIT_FINDINGS, EXIT_TOOLING, EXIT_LLM) == (0, 1, 2, 3)


def test_findings_exit_1() -> None:
    assert main(["scan", str(SAMPLES / "s3_public.tf")]) == EXIT_FINDINGS


def test_dockerfile_findings_exit_1() -> None:
    """Also guards the filename routing: as `.tf` this file scores 0 and would exit 0."""
    assert main(["scan", str(SAMPLES / "vulnerable.Dockerfile")]) == EXIT_FINDINGS


def test_clean_file_exits_0(tmp_path: Path) -> None:
    clean = tmp_path / "clean.tf"
    clean.write_text(CLEAN_TF)
    assert main(["scan", str(clean)]) == EXIT_OK


def test_missing_file_exits_2_not_1(tmp_path: Path) -> None:
    """`2`, never `1` — a file we could not read is not a file with findings."""
    assert main(["scan", str(tmp_path / "nope.tf")]) == EXIT_TOOLING


def test_unsupported_filetype_exits_2(tmp_path: Path) -> None:
    weird = tmp_path / "config.yaml"
    weird.write_text("a: 1\n")
    assert main(["scan", str(weird)]) == EXIT_TOOLING


def test_unknown_scanner_exits_2(tmp_path: Path) -> None:
    clean = tmp_path / "clean.tf"
    clean.write_text(CLEAN_TF)
    try:
        code = main(["scan", str(clean), "--scanner", "not-a-scanner"])
    except SystemExit as exc:  # argparse rejects the choice itself, also with 2
        code = exc.code
    assert code == EXIT_TOOLING


def test_scan_needs_no_api_key() -> None:
    """The entry point for anyone evaluating the repo. Must cost nothing and need nothing."""
    assert main(["scan", str(SAMPLES / "s3_public.tf")]) == EXIT_FINDINGS


def test_json_output_parses(capsys: pytest.CaptureFixture[str]) -> None:
    main(["scan", str(SAMPLES / "s3_public.tf"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload


def test_json_output_carries_the_findings(capsys: pytest.CaptureFixture[str]) -> None:
    main(["scan", str(SAMPLES / "s3_public.tf"), "--json"])
    blob = json.dumps(json.loads(capsys.readouterr().out))
    assert "CKV" in blob, "expected checkov rule ids in the machine-readable output"


def test_version_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == EXIT_OK
    assert capsys.readouterr().out.strip()


def test_no_arguments_does_not_crash() -> None:
    """argparse exits 2 on a missing subcommand; it must not raise."""
    try:
        code = main([])
    except SystemExit as exc:
        code = exc.code
    assert code in (0, 2)


def test_fix_without_credentials_fails_cleanly_not_with_a_traceback() -> None:
    """Absent credentials is a normal condition, not a crash.

    `tests/conftest.py` blocks construction of a real OpenAI client, so this exercises the
    no-credentials path without touching the network. Deleting the env var alone would not be
    enough — `python-dotenv` re-reads `.env` and the call would go through for real.
    """
    try:
        code = main(["fix", str(SAMPLES / "s3_public.tf")])
    except SystemExit as exc:
        code = exc.code
    assert code in (EXIT_TOOLING, EXIT_LLM), "expected a typed failure, got %r" % (code,)


def test_the_network_guard_is_actually_armed() -> None:
    """Guard the guard: if conftest stops blocking, the suite could spend money silently."""
    import openai

    from tests.conftest import LiveAPICallInTests

    with pytest.raises(LiveAPICallInTests):
        openai.OpenAI(api_key="sk-not-a-real-key")


# ---------------------------------------------------------------------------
# a file the scanner could not fully parse is not a clean file
# ---------------------------------------------------------------------------

# Valid HCL up to the point it stops: a real half-written file, a bad merge, a stray brace.
# hcl2 rejects it, Terraform would reject it, and checkov reports a parsing error and
# evaluates nothing.
TRUNCATED_TF = """resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_iam_policy" "wide" {
  name   = "wide"
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = "*"
"""


@pytest.mark.slow
def test_a_file_that_does_not_parse_exits_2_not_0(tmp_path: Path) -> None:
    """The founding bug, one layer up.

    `validity.py` names this case exactly — "a file Terraform cannot parse and a file with zero
    misconfigurations produce the same number" — and the scan path used to produce the same
    *exit code* for them too. It printed `1 parse errors` and then exited 0, so a CI job gated
    on this tool passed a Terraform file Terraform cannot read.
    """
    target = tmp_path / "truncated.tf"
    target.write_text(TRUNCATED_TF, encoding="utf-8")
    assert main(["scan", str(target)]) == EXIT_TOOLING


@pytest.mark.slow
def test_the_parse_failure_is_reported_not_just_counted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2 alone would leave the reader guessing which of the two reasons applied."""
    target = tmp_path / "truncated.tf"
    target.write_text(TRUNCATED_TF, encoding="utf-8")
    main(["scan", str(target)])
    assert "did not parse cleanly" in capsys.readouterr().out


@pytest.mark.slow
def test_json_carries_the_unparsed_files_so_a_pipeline_can_act_on_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "truncated.tf"
    target.write_text(TRUNCATED_TF, encoding="utf-8")
    main(["scan", "--json", str(target)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == EXIT_TOOLING
    assert payload["summary"]["partially_parsed"] == 1
    assert payload["unparsed"] and payload["unparsed"][0]["parse_errors"] >= 1


@pytest.mark.slow
def test_a_fully_parsed_file_with_findings_still_exits_1(tmp_path: Path) -> None:
    """Guard against over-correcting: parse errors must not swallow the ordinary case."""
    assert main(["scan", str(SAMPLES / "s3_public.tf")]) == EXIT_FINDINGS


@pytest.mark.slow
def test_zero_findings_from_zero_checks_is_reported_differently(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """"0 failed, 0 passed" and "0 failed, 46 passed" are not the same claim.

    On real repositories the first is common — files holding only variables or outputs, and
    resources this scanner's community build has no policy for — and both used to roll up into
    an identical "0 finding(s)" line that reads as a verdict. Not an error: a `variables.tf`
    with nothing to check is a legitimate zero, and exiting 2 on it would make the tool
    unusable against a real module. It just has to say which zero it is.
    """
    nothing = tmp_path / "variables.tf"
    nothing.write_text('variable "region" {\n  type = string\n}\n', encoding="utf-8")
    assert main(["scan", str(nothing)]) == EXIT_OK
    assert "no policy was evaluated" in capsys.readouterr().out

    assert main(["scan", str(SAMPLES / "secure" / "secure_s3.tf")]) == EXIT_OK
    assert "no policy was evaluated" not in capsys.readouterr().out


@pytest.mark.slow
def test_the_secure_fixtures_prove_we_looked_not_just_that_we_found_nothing(
    capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 0 is documented as "we looked, and it is clean". The negative controls are the only
    fixtures that demonstrate the first half, which is why CI's clean case uses one."""
    main(["scan", "--json", str(SAMPLES / "secure" / "secure_s3.tf")])
    payload = json.loads(capsys.readouterr().out)
    evaluated = sum(s["passed"] + s["failed"] for t in payload["targets"] for s in t["scans"])
    assert payload["exit_code"] == EXIT_OK
    assert evaluated > 0, "a clean verdict from zero evaluated checks is not a clean verdict"
    assert payload["summary"]["no_checks_evaluated"] == 0
