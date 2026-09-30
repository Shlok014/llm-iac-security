"""The fail-closed regression suite.

This is the most important test file in the package. The original implementation ran
Checkov as `python3 -m checkov`, which cannot work — the package ships no `__main__`
module — so the scanner never executed. That alone would have been obvious, except the
same code treated empty stdout as "no issues found". The result was a tool that reported
a clean security pass on every input, forever, with no error anywhere.

Every test below exists to prove that a scanner which did not run, crashed, timed out,
was not installed, or emitted something we cannot parse, produces a `ScannerError` and
never a `ScanResult`. An absent result is not a passing result.

The suite is hermetic by default: `subprocess.run` and binary resolution are both
monkeypatched, so nothing here needs checkov, trivy, a network, or an API key. The single
test that shells out for real is marked `slow` and is deselected unless asked for.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from iac_agent import scanners
from iac_agent.scanners import (
    _CHECKOV_OK_CODES,
    _TIMEOUT_S,
    _TRIVY_OK_CODES,
    CheckovScanner,
    TrivyScanner,
    _load_json,
    _resolve,
    _run,
    get_scanner,
    scanner_path,
)
from iac_agent.types import IaCType, ScannerError

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass
class FakeCompleted:
    """Stand-in for subprocess.CompletedProcess — only the fields _run reads."""

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def fake_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
    raises: BaseException | None = None,
) -> list[tuple[list[str], dict[str, Any]]]:
    """Replace subprocess.run and record every invocation."""
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def _fake(cmd: list[str], **kwargs: Any) -> FakeCompleted:
        calls.append((list(cmd), kwargs))
        if raises is not None:
            raise raises
        return FakeCompleted(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(scanners.subprocess, "run", _fake)
    return calls


@pytest.fixture
def stub_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend both binaries are installed, so scan() tests never touch the filesystem."""
    monkeypatch.setattr(scanners, "_resolve", lambda binary: f"/fake/bin/{binary}")


@pytest.fixture
def tf_file(tmp_path: Path) -> Path:
    p = tmp_path / "s3_public.tf"
    p.write_text('resource "aws_s3_bucket" "example" {\n  acl = "public-read"\n}\n')
    return p


@pytest.fixture
def docker_file(tmp_path: Path) -> Path:
    p = tmp_path / "vulnerable.Dockerfile"
    p.write_text("FROM ubuntu:latest\nUSER root\n")
    return p


# Shaped from real `checkov -f ... -o json --compact --quiet` output.
CHECKOV_DOC: dict[str, Any] = {
    "check_type": "terraform",
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_20",
                "bc_check_id": "BC_AWS_S3_1",
                "check_name": "Ensure the S3 bucket does not allow READ permissions to everyone",
                "check_result": {"result": "FAILED"},
                "file_path": "/s3_public.tf",
                "file_line_range": [1, 4],
                "resource": "aws_s3_bucket.example",
                "severity": "HIGH",
                "guideline": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/s3-1",
            },
            {
                # Community checks carry no severity and no guideline. Both must degrade
                # to a defined value rather than None leaking into the report.
                "check_id": "CKV2_AWS_62",
                "check_name": "Ensure S3 buckets should have event notifications enabled",
                "check_result": {"result": "FAILED"},
                "file_line_range": [1, 4],
                "resource": "aws_s3_bucket.example",
                "severity": None,
                "guideline": None,
            },
        ],
        "passed_checks": [{"check_id": "CKV_AWS_21", "resource": "aws_s3_bucket.example"}],
    },
    "summary": {
        "passed": 3,
        "failed": 2,
        "skipped": 0,
        "parsing_errors": 0,
        "resource_count": 1,
        "checkov_version": "3.2.489",
    },
}

# Shaped from real `trivy config --quiet --format json` output. Note the first Result
# entry: Trivy emits a directory-level entry with no Misconfigurations key at all.
TRIVY_DOC: dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "s3_public.tf",
    "ArtifactType": "filesystem",
    "Results": [
        {"Target": ".", "Class": "config", "Type": "terraform", "MisconfSummary": {"Successes": 39, "Failures": 0}},
        {
            "Target": "s3_public.tf",
            "Class": "config",
            "Type": "terraform",
            "MisconfSummary": {"Successes": 1, "Failures": 2},
            "Misconfigurations": [
                {
                    "Type": "Terraform Security Check",
                    "ID": "AVD-AWS-0086",
                    "Title": "S3 Access block should block public ACL",
                    "Severity": "HIGH",
                    "Status": "FAIL",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0086",
                    "CauseMetadata": {"Resource": "aws_s3_bucket.example", "StartLine": 1, "EndLine": 4},
                },
                {
                    # No Status key: Trivy omits it in some report versions. Absent must
                    # mean FAIL, never PASS.
                    "ID": "AVD-AWS-0087",
                    "Title": "S3 Access block should block public policy",
                    "Severity": "CRITICAL",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0087",
                    "CauseMetadata": {"Resource": "aws_s3_bucket.example", "StartLine": 1},
                },
                {
                    "ID": "AVD-AWS-0088",
                    "Title": "Unencrypted S3 bucket",
                    "Severity": "HIGH",
                    "Status": "PASS",
                    "CauseMetadata": {"Resource": "aws_s3_bucket.example", "StartLine": 1},
                },
            ],
        },
    ],
}

PYTHON_TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "/usr/bin/checkov", line 5, in <module>\n'
    "    from checkov.main import run\n"
    "ModuleNotFoundError: No module named 'checkov.main'\n"
)


# ---------------------------------------------------------------------------
# _load_json — emptiness is not success
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", "\n\n\t  \n"])
def test_load_json_rejects_empty_output(raw: str) -> None:
    """THE regression. Empty stdout used to mean 'no issues found'."""
    with pytest.raises(ScannerError, match="no output"):
        _load_json(raw, "checkov")


def test_load_json_empty_message_explains_the_refusal() -> None:
    with pytest.raises(ScannerError) as exc:
        _load_json("", "checkov")
    assert "not a passing result" in str(exc.value)


def test_load_json_rejects_a_python_traceback() -> None:
    """A crashing scanner writes a traceback to stdout; that is not zero findings."""
    with pytest.raises(ScannerError, match="no JSON"):
        _load_json(PYTHON_TRACEBACK, "checkov")


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("no issues found", id="prose"),
        pytest.param("PASS", id="single-word"),
        pytest.param("<html><body>403 Forbidden</body></html>", id="html-proxy-page"),
        pytest.param("---\nfoo: bar\n", id="yaml"),
    ],
)
def test_load_json_rejects_non_json_output(raw: str) -> None:
    with pytest.raises(ScannerError, match="no JSON"):
        _load_json(raw, "trivy")


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param('{"results": ', id="truncated-object"),
        pytest.param('[{"a": 1}', id="truncated-array"),
        pytest.param("{'results': 'python repr'}", id="not-json-syntax"),
    ],
)
def test_load_json_rejects_malformed_json(raw: str) -> None:
    """Truncated output means the scanner died mid-write. Fail, do not salvage."""
    with pytest.raises(ScannerError, match="not valid JSON"):
        _load_json(raw, "checkov")


def test_load_json_parses_an_object() -> None:
    assert _load_json('{"summary": {"failed": 2}}', "checkov") == {"summary": {"failed": 2}}


def test_load_json_parses_a_list() -> None:
    assert _load_json('[{"check_type": "terraform"}]', "checkov") == [{"check_type": "terraform"}]


def test_load_json_skips_leading_banner_noise() -> None:
    """Both tools occasionally print a version or update banner before the JSON."""
    raw = 'WARNING: a new version of trivy is available\n{"Results": []}'
    assert _load_json(raw, "trivy") == {"Results": []}


# ---------------------------------------------------------------------------
# _resolve — a missing binary is an error, not an empty result
# ---------------------------------------------------------------------------


def _fake_venv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_binary: str | None) -> Path:
    """Point sys.executable at a throwaway bin/ dir, optionally containing a binary."""
    bindir = tmp_path / "venv" / "bin"
    bindir.mkdir(parents=True)
    (bindir / "python").write_text("")
    if with_binary:
        target = bindir / with_binary
        target.write_text("#!/bin/sh\nexit 0\n")
        target.chmod(0o755)
    monkeypatch.setattr(scanners.sys, "executable", str(bindir / "python"))
    return bindir


def test_resolve_prefers_the_interpreters_own_bin_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PATH may hold a broken system checkov; the venv's is the one we pinned."""
    bindir = _fake_venv(tmp_path, monkeypatch, with_binary="checkov")
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "/usr/local/bin/checkov")
    assert _resolve("checkov") == str(bindir / "checkov")


def test_resolve_falls_back_to_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_venv(tmp_path, monkeypatch, with_binary=None)
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "/usr/local/bin/trivy")
    assert _resolve("trivy") == "/usr/local/bin/trivy"


def test_resolve_ignores_a_non_executable_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bindir = _fake_venv(tmp_path, monkeypatch, with_binary=None)
    (bindir / "checkov").write_text("not executable")
    (bindir / "checkov").chmod(0o644)
    monkeypatch.setattr(scanners.shutil, "which", lambda _: None)
    with pytest.raises(ScannerError):
        _resolve("checkov")


def test_resolve_raises_when_the_binary_is_missing_everywhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_venv(tmp_path, monkeypatch, with_binary=None)
    monkeypatch.setattr(scanners.shutil, "which", lambda _: None)
    with pytest.raises(ScannerError, match="not found") as exc:
        _resolve("checkov")
    assert "checkov" in str(exc.value)


# ---------------------------------------------------------------------------
# scanner_path — the pre-flight question, which must never raise
# ---------------------------------------------------------------------------


def test_scanner_path_returns_none_rather_than_raising_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Callers ask this *before* running anything, to avoid offering a scanner that cannot
    work. A raising probe would be worse than no probe: it would turn a UI that wanted to warn
    into a UI that crashes on load."""
    _fake_venv(tmp_path, monkeypatch, with_binary=None)
    monkeypatch.setattr(scanners.shutil, "which", lambda _: None)
    assert scanner_path("checkov") is None
    assert scanner_path("trivy") is None


def test_scanner_path_agrees_with_the_lookup_a_real_scan_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It must be the *same* lookup as `_resolve`, or the page could report a scanner as
    available and then fail to run it — the one outcome the pre-flight check exists to
    prevent."""
    _fake_venv(tmp_path, monkeypatch, with_binary="checkov")
    assert scanner_path("checkov") == _resolve("checkov")


def test_scanner_path_is_case_insensitive_like_get_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_venv(tmp_path, monkeypatch, with_binary="checkov")
    assert scanner_path("CHECKOV") == _resolve("checkov")


# ---------------------------------------------------------------------------
# _run — exit codes, timeouts, exec failures
# ---------------------------------------------------------------------------


def test_run_returns_stdout_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_run(monkeypatch, stdout='{"ok": true}', returncode=0)
    assert _run(["/fake/bin/checkov"], _CHECKOV_OK_CODES) == '{"ok": true}'


def test_run_accepts_checkov_exit_1_as_findings_not_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Checkov exits 1 when a check fails. That is the normal, expected path."""
    fake_run(monkeypatch, stdout='{"summary": {}}', returncode=1)
    assert _run(["/fake/bin/checkov"], _CHECKOV_OK_CODES) == '{"summary": {}}'


def test_run_rejects_trivy_exit_1(monkeypatch: pytest.MonkeyPatch) -> None:
    """Trivy is invoked without --exit-code, so anything but 0 is a real failure."""
    fake_run(monkeypatch, stdout="", returncode=1)
    with pytest.raises(ScannerError):
        _run(["/fake/bin/trivy"], _TRIVY_OK_CODES)


@pytest.mark.parametrize("code", [2, 3, 127, -9, 130])
def test_run_rejects_unexpected_exit_codes(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    """Exit 2 is a bad flag or a missing dependency — emphatically not 'clean'."""
    fake_run(monkeypatch, stdout="", stderr="usage: checkov [-h]", returncode=code)
    with pytest.raises(ScannerError, match="not a clean result"):
        _run(["/fake/bin/checkov"], _CHECKOV_OK_CODES)


def test_run_error_includes_the_scanner_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_run(monkeypatch, stderr="error: unrecognized arguments: --framework", returncode=2)
    with pytest.raises(ScannerError, match="unrecognized arguments") as exc:
        _run(["/fake/bin/checkov"], _CHECKOV_OK_CODES)
    assert "exited 2" in str(exc.value)


def test_run_falls_back_to_stdout_when_stderr_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_run(monkeypatch, stdout="something went wrong on stdout", returncode=2)
    with pytest.raises(ScannerError, match="something went wrong on stdout"):
        _run(["/fake/bin/checkov"], _CHECKOV_OK_CODES)


def test_run_converts_a_timeout_into_a_scanner_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung scanner must not be indistinguishable from a fast clean scan."""
    fake_run(monkeypatch, raises=subprocess.TimeoutExpired(cmd="checkov", timeout=_TIMEOUT_S))
    with pytest.raises(ScannerError, match="timed out"):
        _run(["/fake/bin/checkov"], _CHECKOV_OK_CODES)


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(FileNotFoundError(2, "No such file or directory"), id="enoent"),
        pytest.param(PermissionError(13, "Permission denied"), id="eacces"),
        pytest.param(OSError("Exec format error"), id="exec-format"),
    ],
)
def test_run_converts_os_errors_into_scanner_errors(
    monkeypatch: pytest.MonkeyPatch, exc: OSError
) -> None:
    fake_run(monkeypatch, raises=exc)
    with pytest.raises(ScannerError, match="could not execute"):
        _run(["/fake/bin/checkov"], _CHECKOV_OK_CODES)


def test_run_passes_the_expected_subprocess_options(monkeypatch: pytest.MonkeyPatch) -> None:
    """check=False matters: an exception here would bypass our own exit-code policy."""
    calls = fake_run(monkeypatch, stdout="{}")
    _run(["/fake/bin/checkov", "-f", "x.tf"], _CHECKOV_OK_CODES)
    _, kwargs = calls[0]
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["check"] is False
    assert kwargs["timeout"] == _TIMEOUT_S


# ---------------------------------------------------------------------------
# CheckovScanner — happy path
# ---------------------------------------------------------------------------


def test_checkov_parses_findings(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout=json.dumps(CHECKOV_DOC), returncode=1)
    result = CheckovScanner().scan(tf_file)

    assert result.scanner == "checkov"
    assert result.target == tf_file
    assert result.iac_type is IaCType.TERRAFORM
    assert result.failed_count == 2
    assert [f.rule_id for f in result.failed] == ["CKV_AWS_20", "CKV2_AWS_62"]
    assert result.passed_count == 3
    assert result.parse_errors == 0
    assert result.parsed_cleanly is True


def test_checkov_finding_fields_are_normalised(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout=json.dumps(CHECKOV_DOC), returncode=1)
    first, second = CheckovScanner().scan(tf_file).failed

    assert first.severity == "high"  # lowercased for cross-scanner comparison
    assert first.resource == "aws_s3_bucket.example"
    assert first.message.startswith("Ensure the S3 bucket")
    assert first.scanner == "checkov"
    assert first.file == str(tf_file)
    assert first.line == 1  # first element of file_line_range
    assert first.guideline.startswith("https://")

    # None severity/guideline must not survive into the report.
    assert second.severity == "unknown"
    assert second.guideline == ""


def test_checkov_accepts_a_list_wrapped_document(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    """Checkov emits a list when more than one framework produced a report."""
    fake_run(monkeypatch, stdout=json.dumps([CHECKOV_DOC]), returncode=1)
    assert CheckovScanner().scan(tf_file).failed_count == 2


@pytest.mark.parametrize("output", ["{}", "[]", '{"summary": {}, "results": {}}'])
def test_checkov_rejects_json_without_a_complete_scan_result(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path, output: str
) -> None:
    fake_run(monkeypatch, stdout=output)
    with pytest.raises(ScannerError, match="shape"):
        CheckovScanner().scan(tf_file)


def test_checkov_surfaces_parsing_errors(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    """Zero findings on an unparseable file is the fail-open shape; parsed_cleanly says so."""
    doc = {"results": {"failed_checks": []}, "summary": {"passed": 0, "parsing_errors": 1}}
    fake_run(monkeypatch, stdout=json.dumps(doc), returncode=0)
    result = CheckovScanner().scan(tf_file)
    assert result.failed_count == 0
    assert result.parsed_cleanly is False


def test_checkov_command_line_for_terraform(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    calls = fake_run(monkeypatch, stdout=json.dumps(CHECKOV_DOC), returncode=1)
    CheckovScanner().scan(tf_file)
    cmd, _ = calls[0]

    assert cmd[0].endswith("checkov")  # the console script, never `python -m checkov`
    assert "-m" not in cmd
    assert cmd[cmd.index("-f") + 1] == str(tf_file)
    assert cmd[cmd.index("-o") + 1] == "json"
    assert cmd[cmd.index("--framework") + 1] == "terraform"


def test_checkov_command_line_for_dockerfile(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, docker_file: Path
) -> None:
    """The framework flag follows the detected type, or Dockerfile rules never run."""
    calls = fake_run(monkeypatch, stdout=json.dumps(DEGENERATE_CHECKOV), returncode=0)
    result = CheckovScanner().scan(docker_file)
    cmd, _ = calls[0]

    assert cmd[cmd.index("--framework") + 1] == "dockerfile"
    assert result.iac_type is IaCType.DOCKERFILE


def test_checkov_explicit_iac_type_overrides_detection(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tmp_path: Path
) -> None:
    """Lets a caller scan a temp file whose name would not route on its own."""
    odd = tmp_path / "scratch.txt"
    odd.write_text("FROM ubuntu:latest\n")
    calls = fake_run(monkeypatch, stdout=json.dumps(DEGENERATE_CHECKOV), returncode=0)
    result = CheckovScanner().scan(odd, iac_type=IaCType.DOCKERFILE)
    cmd, _ = calls[0]

    assert cmd[cmd.index("--framework") + 1] == "dockerfile"
    assert result.iac_type is IaCType.DOCKERFILE


# ---------------------------------------------------------------------------
# CheckovScanner — every failure mode fails closed
# ---------------------------------------------------------------------------


def test_checkov_empty_stdout_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    """Exit 0 with no output is exactly what the broken `python3 -m checkov` produced."""
    fake_run(monkeypatch, stdout="", returncode=0)
    with pytest.raises(ScannerError, match="no output"):
        CheckovScanner().scan(tf_file)


def test_checkov_traceback_stdout_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout=PYTHON_TRACEBACK, returncode=1)
    with pytest.raises(ScannerError, match="no JSON"):
        CheckovScanner().scan(tf_file)


def test_checkov_exit_2_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout="", stderr="checkov: error: bad flag", returncode=2)
    with pytest.raises(ScannerError, match="not a clean result"):
        CheckovScanner().scan(tf_file)


def test_checkov_exit_2_raises_even_with_valid_json_on_stdout(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    """Parseable output from a crashed run is still untrustworthy."""
    fake_run(monkeypatch, stdout=json.dumps(CHECKOV_DOC), returncode=2)
    with pytest.raises(ScannerError):
        CheckovScanner().scan(tf_file)


def test_checkov_timeout_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, raises=subprocess.TimeoutExpired(cmd="checkov", timeout=_TIMEOUT_S))
    with pytest.raises(ScannerError, match="timed out"):
        CheckovScanner().scan(tf_file)


def test_checkov_missing_binary_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tf_file: Path
) -> None:
    """Not installed must be loud. The original code reported it as a clean scan."""
    _fake_venv(tmp_path, monkeypatch, with_binary=None)
    monkeypatch.setattr(scanners.shutil, "which", lambda _: None)
    with pytest.raises(ScannerError, match="not found"):
        CheckovScanner().scan(tf_file)


def test_checkov_exec_failure_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, raises=FileNotFoundError(2, "No such file or directory"))
    with pytest.raises(ScannerError, match="could not execute"):
        CheckovScanner().scan(tf_file)


@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param("[1, 2, 3]", id="list-of-scalars"),
        pytest.param('["a string"]', id="list-of-strings"),
        pytest.param("[[]]", id="nested-list"),
    ],
)
def test_checkov_unexpected_json_shape_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path, stdout: str
) -> None:
    fake_run(monkeypatch, stdout=stdout, returncode=0)
    with pytest.raises(ScannerError, match="unexpected JSON shape"):
        CheckovScanner().scan(tf_file)


def test_checkov_missing_target_file_raises(stub_resolve: None, tmp_path: Path) -> None:
    with pytest.raises(ScannerError, match="not a file"):
        CheckovScanner().scan(tmp_path / "does_not_exist.tf")


def test_checkov_directory_target_raises(stub_resolve: None, tmp_path: Path) -> None:
    with pytest.raises(ScannerError, match="not a file"):
        CheckovScanner().scan(tmp_path)


DEGENERATE_CHECKOV = {
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "parsing_errors": 0,
    "resource_count": 0,
    "checkov_version": "3.2.489",
}


def test_checkov_framework_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, docker_file: Path
) -> None:
    """A framework mismatch must not read as a clean scan.

    Regression test for a real fail-open: `--file x.Dockerfile --framework terraform` makes
    checkov log "There are no runners to run", exit 0, and emit a bare summary with no
    "results" key. Verified against checkov 3.2.489 on samples/vulnerable.Dockerfile, which
    has 5 genuine findings and was reported as 0 before this was fixed.
    """
    fake_run(
        monkeypatch,
        stdout=json.dumps(DEGENERATE_CHECKOV),
        stderr="[ERROR] There are no runners to run. This can happen if you specify a file "
        "type and a framework that are not compatible",
        returncode=0,
    )
    with pytest.raises(ScannerError, match="without examining the file"):
        CheckovScanner().scan(docker_file, iac_type=IaCType.TERRAFORM)


def test_checkov_empty_but_valid_file_is_a_clean_pass(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    """The other half of the contract: the same JSON with a quiet stderr IS a clean result.

    A file such as `variable "x" { type = string }` legitimately has nothing to check and
    produces byte-identical output to the mismatch case. stderr is the only discriminator,
    which is why the guard keys on it rather than on the report shape.
    """
    fake_run(monkeypatch, stdout=json.dumps(DEGENERATE_CHECKOV), stderr="", returncode=0)
    result = CheckovScanner().scan(tf_file)
    assert result.failed_count == 0
    assert result.parsed_cleanly


# ---------------------------------------------------------------------------
# TrivyScanner
# ---------------------------------------------------------------------------


def test_trivy_parses_findings(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout=json.dumps(TRIVY_DOC), returncode=0)
    result = TrivyScanner().scan(tf_file)

    assert result.scanner == "trivy"
    assert result.iac_type is IaCType.TERRAFORM
    assert [f.rule_id for f in result.failed] == ["AVD-AWS-0086", "AVD-AWS-0087"]
    assert result.failed_count == 2
    assert result.passed_count == 1  # only the explicit PASS misconfiguration
    assert result.parsed_cleanly is True


def test_trivy_finding_fields_are_normalised(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout=json.dumps(TRIVY_DOC), returncode=0)
    first = TrivyScanner().scan(tf_file).failed[0]

    assert first.severity == "high"
    assert first.resource == "aws_s3_bucket.example"
    assert first.message == "S3 Access block should block public ACL"
    assert first.scanner == "trivy"
    assert first.file == str(tf_file)
    assert first.line == 1  # CauseMetadata.StartLine
    assert first.guideline.startswith("https://avd.aquasec.com")


def test_trivy_missing_status_counts_as_a_failure(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    """Absent status defaults to FAIL. Defaulting to PASS would hide real findings."""
    fake_run(monkeypatch, stdout=json.dumps(TRIVY_DOC), returncode=0)
    ids = [f.rule_id for f in TrivyScanner().scan(tf_file).failed]
    assert "AVD-AWS-0087" in ids


def test_trivy_result_entry_without_misconfigurations(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    """The directory-level Result entry has no Misconfigurations key at all."""
    doc = {"Results": [{"Target": ".", "MisconfSummary": {"Successes": 39, "Failures": 0}}]}
    fake_run(monkeypatch, stdout=json.dumps(doc), returncode=0)
    assert TrivyScanner().scan(tf_file).failed_count == 0


def test_trivy_command_line(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    calls = fake_run(monkeypatch, stdout=json.dumps(TRIVY_DOC), returncode=0)
    TrivyScanner().scan(tf_file)
    cmd, _ = calls[0]

    assert cmd[0].endswith("trivy")
    assert cmd[1] == "config"
    assert cmd[cmd.index("--format") + 1] == "json"
    assert cmd[-1] == str(tf_file)


def test_trivy_empty_stdout_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout="", returncode=0)
    with pytest.raises(ScannerError, match="no output"):
        TrivyScanner().scan(tf_file)


def test_trivy_non_json_stdout_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout="FATAL\tinit error: DB error", returncode=0)
    with pytest.raises(ScannerError, match="no JSON"):
        TrivyScanner().scan(tf_file)


def test_trivy_nonzero_exit_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout="", stderr="FATAL unable to initialize scanner", returncode=1)
    with pytest.raises(ScannerError, match="not a clean result"):
        TrivyScanner().scan(tf_file)


def test_trivy_timeout_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, raises=subprocess.TimeoutExpired(cmd="trivy", timeout=_TIMEOUT_S))
    with pytest.raises(ScannerError, match="timed out"):
        TrivyScanner().scan(tf_file)


def test_trivy_missing_binary_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tf_file: Path
) -> None:
    _fake_venv(tmp_path, monkeypatch, with_binary=None)
    monkeypatch.setattr(scanners.shutil, "which", lambda _: None)
    with pytest.raises(ScannerError, match="not found"):
        TrivyScanner().scan(tf_file)


def test_trivy_unexpected_json_shape_raises(
    monkeypatch: pytest.MonkeyPatch, stub_resolve: None, tf_file: Path
) -> None:
    fake_run(monkeypatch, stdout='[{"Results": []}]', returncode=0)
    with pytest.raises(ScannerError, match="unexpected JSON shape"):
        TrivyScanner().scan(tf_file)


def test_trivy_missing_target_file_raises(stub_resolve: None, tmp_path: Path) -> None:
    with pytest.raises(ScannerError, match="not a file"):
        TrivyScanner().scan(tmp_path / "nope.tf")


# ---------------------------------------------------------------------------
# The whole matrix, stated once: no failure mode may yield a ScanResult
# ---------------------------------------------------------------------------

FAILURE_MODES = [
    pytest.param({"stdout": "", "returncode": 0}, id="empty-stdout-exit-0"),
    pytest.param({"stdout": "   \n ", "returncode": 0}, id="whitespace-stdout"),
    pytest.param({"stdout": PYTHON_TRACEBACK, "returncode": 1}, id="traceback"),
    pytest.param({"stdout": "no issues found", "returncode": 0}, id="prose"),
    pytest.param({"stdout": '{"results":', "returncode": 0}, id="truncated-json"),
    pytest.param({"stdout": "", "returncode": 2}, id="exit-2"),
    pytest.param({"stdout": "{}", "returncode": 127}, id="exit-127"),
    pytest.param({"raises": subprocess.TimeoutExpired(cmd="x", timeout=1)}, id="timeout"),
    pytest.param({"raises": FileNotFoundError(2, "missing")}, id="binary-vanished"),
    pytest.param({"raises": PermissionError(13, "denied")}, id="not-executable"),
]


@pytest.mark.parametrize("scanner_name", ["checkov", "trivy"])
@pytest.mark.parametrize("kwargs", FAILURE_MODES)
def test_no_failure_mode_ever_produces_a_scan_result(
    monkeypatch: pytest.MonkeyPatch,
    stub_resolve: None,
    tf_file: Path,
    scanner_name: str,
    kwargs: dict[str, Any],
) -> None:
    """The single invariant this package is built around, asserted exhaustively."""
    fake_run(monkeypatch, **kwargs)
    scanner = get_scanner(scanner_name)
    with pytest.raises(ScannerError):
        scanner.scan(tf_file)


# ---------------------------------------------------------------------------
# get_scanner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "cls"), [("checkov", CheckovScanner), ("trivy", TrivyScanner)]
)
def test_get_scanner_returns_the_right_instance(name: str, cls: type) -> None:
    scanner = get_scanner(name)
    assert isinstance(scanner, cls)
    assert scanner.name == name


@pytest.mark.parametrize("name", ["CHECKOV", "Checkov", "TrIvY"])
def test_get_scanner_is_case_insensitive(name: str) -> None:
    assert get_scanner(name).name == name.lower()


@pytest.mark.parametrize("name", ["tfsec", "", "semgrep", "check0v"])
def test_unknown_scanner_raises_and_lists_what_exists(name: str) -> None:
    with pytest.raises(ScannerError, match="unknown scanner") as exc:
        get_scanner(name)
    assert "checkov" in str(exc.value) and "trivy" in str(exc.value)


# ---------------------------------------------------------------------------
# The one real end-to-end check (deselected by default: `pytest -m slow`)
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_real_checkov_on_s3_public_finds_exactly_eight() -> None:
    """Pins the measured baseline against a real checkov run.

    Also the end-to-end proof that the console script is invoked correctly: under the
    original `python3 -m checkov` this returns 0 findings, not 8.
    """
    target = SAMPLES / "s3_public.tf"
    if not target.is_file():
        pytest.skip(f"sample not present: {target}")

    result = get_scanner("checkov").scan(target)

    assert result.failed_count == 8
    assert result.parsed_cleanly is True
    assert result.passed_count > 0
    assert result.iac_type is IaCType.TERRAFORM
    assert all(f.rule_id.startswith("CKV") for f in result.failed)
    assert all(f.resource for f in result.failed)
