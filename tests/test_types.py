"""Tests for the shared type vocabulary.

The headline regression here is `IaCType.output_name`. The original pipeline wrote every
remediated file to `fixed.tf`, including remediated Dockerfiles. Both Checkov and Trivy
select their Dockerfile rulesets by *filename*, so a Dockerfile named `fixed.tf` was
scanned with Terraform rules, produced zero findings, and was reported as fully fixed —
while the real file still had every one of its original misconfigurations.

The rest of the module is small enough to test exhaustively, and worth it: `Finding.key()`
and `ScanResult.keys()` are the arithmetic behind every before/after delta the tool reports.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from iac_agent.types import (
    Finding,
    IaCAgentError,
    IaCType,
    LLMError,
    ScannerError,
    ScanResult,
    UnsupportedFileError,
    detect_iac_type,
)

# ---------------------------------------------------------------------------
# detect_iac_type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "foo.tf",
        "main.tf",
        "vulnerable_main.tf",
        "s3_public.tf",
        "fixed.tf",
        "MAIN.TF",
        "/abs/path/to/ec2_open.tf",
        "relative/dir/network.tf",
    ],
)
def test_terraform_files_route_to_terraform(name: str) -> None:
    assert detect_iac_type(name) is IaCType.TERRAFORM


@pytest.mark.parametrize(
    "name",
    [
        "Dockerfile",
        "dockerfile",
        "vulnerable.Dockerfile",
        "docker_insecure.Dockerfile",
        "foo.DOCKERFILE",
        "Dockerfile.prod",
        "/abs/path/to/Dockerfile",
        "samples/vulnerable.Dockerfile",
    ],
)
def test_dockerfiles_route_to_dockerfile(name: str) -> None:
    """Matched by filename substring, because that is exactly what the scanners do."""
    assert detect_iac_type(name) is IaCType.DOCKERFILE


@pytest.mark.parametrize(
    "name",
    [
        "foo.yaml",
        "playbook.yml",
        "template.json",
        "notes.txt",
        "main.tfvars",
        "script.py",
        "README.md",
        "",
    ],
)
def test_unsupported_files_raise(name: str) -> None:
    """Routing must refuse rather than guess — a wrong framework scans clean."""
    with pytest.raises(UnsupportedFileError):
        detect_iac_type(name)


def test_unsupported_error_names_the_file_and_the_supported_set() -> None:
    with pytest.raises(UnsupportedFileError, match="playbook.yml") as exc:
        detect_iac_type("some/dir/playbook.yml")
    assert ".tf" in str(exc.value)


def test_accepts_str_and_path_identically() -> None:
    assert detect_iac_type("samples/s3_public.tf") is detect_iac_type(Path("samples/s3_public.tf"))
    assert detect_iac_type("samples/vulnerable.Dockerfile") is detect_iac_type(
        Path("samples/vulnerable.Dockerfile")
    )


def test_only_the_filename_is_considered_not_the_directory() -> None:
    """A `dockerfiles/` parent directory must not turn a YAML file into a Dockerfile."""
    with pytest.raises(UnsupportedFileError):
        detect_iac_type("dockerfiles/compose.yaml")


# ---------------------------------------------------------------------------
# IaCType properties — the output_name regression
# ---------------------------------------------------------------------------


def test_output_name_terraform() -> None:
    assert IaCType.TERRAFORM.output_name == "fixed.tf"


def test_output_name_dockerfile_is_not_a_tf_file() -> None:
    """Regression: remediated Dockerfiles were written as `fixed.tf`.

    Scanners then applied Terraform rules and reported 0 findings on a file that still
    had all 6 of its original Dockerfile misconfigurations.
    """
    assert IaCType.DOCKERFILE.output_name == "Dockerfile"
    assert not IaCType.DOCKERFILE.output_name.endswith(".tf")


@pytest.mark.parametrize("kind", list(IaCType))
def test_output_name_round_trips_through_detection(kind: IaCType) -> None:
    """The property that actually protects the pipeline.

    Whatever a remediated file is written as, re-detecting its type must give back the
    type we started with — otherwise the verification scan uses the wrong ruleset.
    """
    assert detect_iac_type(kind.output_name) is kind


@pytest.mark.parametrize(
    ("kind", "framework"),
    [(IaCType.TERRAFORM, "terraform"), (IaCType.DOCKERFILE, "dockerfile")],
)
def test_checkov_framework_names(kind: IaCType, framework: str) -> None:
    """These strings are passed verbatim to `checkov --framework`."""
    assert kind.checkov_framework == framework


def test_is_a_str_enum_so_it_interpolates_and_compares_as_its_value() -> None:
    assert IaCType.TERRAFORM == "terraform"
    assert IaCType("dockerfile") is IaCType.DOCKERFILE
    assert f"{IaCType.DOCKERFILE.value}" == "dockerfile"


def test_fence_tags_cover_the_tags_models_actually_emit() -> None:
    assert set(IaCType.TERRAFORM.fence_tags) >= {"hcl", "terraform", "tf"}
    assert set(IaCType.DOCKERFILE.fence_tags) >= {"dockerfile", "docker"}


@pytest.mark.parametrize("kind", list(IaCType))
def test_fence_tags_are_lowercase_and_bare(kind: IaCType) -> None:
    """They are concatenated onto '```', so a stray backtick would be self-defeating."""
    for tag in kind.fence_tags:
        assert tag == tag.lower()
        assert "`" not in tag


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def _finding(**overrides: object) -> Finding:
    base = {
        "rule_id": "CKV_AWS_20",
        "severity": "high",
        "resource": "aws_s3_bucket.example",
        "message": "S3 bucket allows public READ",
        "scanner": "checkov",
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def test_finding_optional_fields_default() -> None:
    f = _finding()
    assert f.file == ""
    assert f.line is None
    assert f.guideline == ""


def test_finding_is_frozen() -> None:
    """Findings are evidence; nothing downstream may rewrite them in place."""
    f = _finding()
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.severity = "low"  # type: ignore[misc]


def test_key_is_rule_id_and_resource() -> None:
    assert _finding().key() == ("CKV_AWS_20", "aws_s3_bucket.example")


def test_key_ignores_cosmetic_differences() -> None:
    """Checkov and Trivy word the same finding differently; identity must not depend on it."""
    a = _finding(message="one wording", severity="high", line=1, scanner="checkov")
    b = _finding(message="another wording", severity="critical", line=99, scanner="trivy")
    assert a.key() == b.key()
    assert a != b


@pytest.mark.parametrize(
    ("field", "value"),
    [("rule_id", "CKV_AWS_21"), ("resource", "aws_s3_bucket.other")],
)
def test_key_distinguishes_identity_fields(field: str, value: str) -> None:
    assert _finding().key() != _finding(**{field: value}).key()


def test_key_is_hashable_and_usable_in_a_set() -> None:
    assert len({_finding().key(), _finding(message="different").key()}) == 1


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


def _result(findings: list[Finding], **overrides: object) -> ScanResult:
    base = {
        "scanner": "checkov",
        "target": Path("samples/s3_public.tf"),
        "iac_type": IaCType.TERRAFORM,
        "failed": findings,
    }
    base.update(overrides)
    return ScanResult(**base)  # type: ignore[arg-type]


def test_empty_result_defaults() -> None:
    r = ScanResult(scanner="checkov", target=Path("x.tf"), iac_type=IaCType.TERRAFORM)
    assert r.failed == []
    assert r.failed_count == 0
    assert r.passed_count == 0
    assert r.parsed_cleanly is True


def test_default_failed_lists_are_not_shared_between_instances() -> None:
    """`field(default_factory=list)` rather than a mutable default — verify it stays that way."""
    a = ScanResult(scanner="checkov", target=Path("a.tf"), iac_type=IaCType.TERRAFORM)
    b = ScanResult(scanner="checkov", target=Path("b.tf"), iac_type=IaCType.TERRAFORM)
    a.failed.append(_finding())
    assert b.failed == []


def test_failed_count_tracks_the_list() -> None:
    assert _result([_finding(), _finding(rule_id="CKV_AWS_21")]).failed_count == 2


def test_parsed_cleanly_is_false_when_the_scanner_could_not_parse() -> None:
    """A parse error is not a pass: zero findings on an unparsed file means nothing."""
    r = _result([], parse_errors=1)
    assert r.parsed_cleanly is False
    assert r.failed_count == 0


def test_keys_returns_the_set_of_finding_identities() -> None:
    r = _result([_finding(), _finding(rule_id="CKV_AWS_21")])
    assert r.keys() == {
        ("CKV_AWS_20", "aws_s3_bucket.example"),
        ("CKV_AWS_21", "aws_s3_bucket.example"),
    }


def test_keys_deduplicates_but_failed_count_does_not() -> None:
    """Two scanners can report the same rule on the same resource; the delta counts it once."""
    r = _result([_finding(scanner="checkov"), _finding(scanner="trivy")])
    assert r.failed_count == 2
    assert len(r.keys()) == 1


def test_before_after_set_arithmetic() -> None:
    """The actual remediation report: what got fixed, what survived, what we introduced."""
    before = _result(
        [
            _finding(rule_id="CKV_AWS_20"),
            _finding(rule_id="CKV_AWS_21"),
            _finding(rule_id="CKV_AWS_18"),
        ]
    )
    after = _result([_finding(rule_id="CKV_AWS_18"), _finding(rule_id="CKV_AWS_57")])

    assert before.keys() - after.keys() == {
        ("CKV_AWS_20", "aws_s3_bucket.example"),
        ("CKV_AWS_21", "aws_s3_bucket.example"),
    }
    assert after.keys() - before.keys() == {("CKV_AWS_57", "aws_s3_bucket.example")}
    assert before.keys() & after.keys() == {("CKV_AWS_18", "aws_s3_bucket.example")}


def test_empty_result_keys_is_an_empty_set() -> None:
    assert _result([]).keys() == set()


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("err", [ScannerError, LLMError, UnsupportedFileError])
def test_every_error_is_catchable_as_the_package_base(err: type[Exception]) -> None:
    """One `except IaCAgentError` at the CLI boundary must catch everything we raise."""
    assert issubclass(err, IaCAgentError)
    with pytest.raises(IaCAgentError):
        raise err("boom")


def test_package_base_is_an_exception_not_a_bare_object() -> None:
    assert issubclass(IaCAgentError, Exception)


def test_errors_are_distinct_types() -> None:
    """A scanner crash and a model failure need different operator responses."""
    assert not issubclass(ScannerError, LLMError)
    assert not issubclass(LLMError, ScannerError)
    assert not issubclass(UnsupportedFileError, ScannerError)
