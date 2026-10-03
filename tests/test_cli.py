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

from iac_agent.types import IaCType
from iac_agent.cli import _drift_document

import pytest

from iac_agent.cli import EXIT_FINDINGS, EXIT_LLM, EXIT_OK, EXIT_TOOLING, main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_cli_reports_dockerfile_structural_drift(tmp_path: Path) -> None:
    source = tmp_path / "Dockerfile"
    source.write_text('FROM python:3.12\nCOPY . /app\nCMD ["python", "app.py"]\n')

    class View:
        best_code = "FROM scratch\n"
        baseline_scan = None

        def drift(self):
            return None

    doc = _drift_document(View(), source, IaCType.DOCKERFILE)
    assert doc["available"] is True
    assert doc["drifted"] is True
    assert doc["docker_drops"]


def test_cli_does_not_call_a_dockerfile_structure_check_resource_drift(tmp_path: Path) -> None:
    source = tmp_path / "Dockerfile"
    source.write_text('FROM python:3.12\nCOPY . /app\nCMD ["python", "app.py"]\n')

    class View:
        best_code = 'FROM python:3.13\nCOPY . /app\nCMD ["python", "app.py"]\n'
        baseline_scan = None

        def drift(self):
            return None

    doc = _drift_document(View(), source, IaCType.DOCKERFILE)
    assert doc["available"] is True
    assert doc["drifted"] is False
    assert "Dockerfile" in doc["summary"]


def test_cli_reports_terraform_instance_control_drift(tmp_path: Path) -> None:
    source = tmp_path / "service.tf"
    source.write_text('resource "aws_instance" "web" { count = 1 ami = "ami-example" }\n')

    class View:
        best_code = 'resource "aws_instance" "web" { count = 0 ami = "ami-example" }\n'
        baseline_scan = None

        def drift(self):
            return None

    doc = _drift_document(View(), source, IaCType.TERRAFORM)
    assert doc["drifted"] is True
    assert "aws_instance.web count changed" in doc["terraform_changes"]

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
