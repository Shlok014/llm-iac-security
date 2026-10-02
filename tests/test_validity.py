"""Tests for the validity gate and the semantic-drift metric.

These two are the project's differentiating claims, so they get the most adversarial tests in
the suite. Both exist to close a route to a *fake* zero: the validity gate stops a model from
scoring well by emitting something that is not a file, and drift stops it from scoring well by
deleting the resource the finding was about.

A metric that cannot fire is not a metric, so several of these assert the *positive* case —
that drift is genuinely detected — rather than only that clean input passes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iac_agent.types import IaCType
from iac_agent.validity import (
    check_validity,
    compute_drift,
    drift_touches_flaw,
    extract_resources,
)

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# The 8 resource addresses in samples/vulnerable_main.tf, in declaration order.
EXPECTED_ADDRS = [
    "aws_s3_bucket.public_bucket",
    "aws_s3_bucket_policy.public_policy",
    "aws_security_group.insecure_sg",
    "aws_instance.bad_instance",
    "aws_db_instance.bad_rds",
    "aws_iam_user.danger_user",
    "aws_iam_policy.over_permissive_policy",
    "aws_iam_user_policy_attachment.attach_danger",
]

TWO_BUCKETS = """
resource "aws_s3_bucket" "a" {
  bucket = "one"
}
resource "aws_s3_bucket" "b" {
  bucket = "two"
}
"""

ONE_BUCKET = """
resource "aws_s3_bucket" "a" {
  bucket = "one"
}
"""


# --------------------------------------------------------------------------------------
# resource extraction
# --------------------------------------------------------------------------------------


def test_extracts_every_resource_from_the_richest_fixture() -> None:
    addrs = [r.address for r in extract_resources(SAMPLES / "vulnerable_main.tf")]
    assert addrs == EXPECTED_ADDRS


def test_dockerfiles_have_no_addressable_resources() -> None:
    """Dockerfiles have no resource addresses; their structural gate is separate."""
    assert extract_resources(SAMPLES / "vulnerable.Dockerfile") == []


# --------------------------------------------------------------------------------------
# the validity gate
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture",
    ["vulnerable_main.tf", "ec2_open.tf", "s3_public.tf", "vulnerable_network.tf"],
)
def test_real_terraform_fixtures_pass(fixture: str) -> None:
    assert check_validity(SAMPLES / fixture, IaCType.TERRAFORM).ok


@pytest.mark.parametrize("fixture", ["vulnerable.Dockerfile", "docker_insecure.Dockerfile"])
def test_real_dockerfile_fixtures_pass(fixture: str) -> None:
    assert check_validity(SAMPLES / fixture, IaCType.DOCKERFILE).ok


def test_empty_output_is_rejected() -> None:
    """The highest-severity fake zero: an empty file scans clean under every scanner."""
    assert not check_validity("", IaCType.TERRAFORM).ok
    assert not check_validity("   \n\n  ", IaCType.TERRAFORM).ok


def test_unparseable_hcl_is_rejected() -> None:
    result = check_validity('resource "aws_s3_bucket" "x" { bucket = ', IaCType.TERRAFORM)
    assert not result.ok
    assert result.reason


def test_fenced_output_is_rejected() -> None:
    """A model that fences its answer produces a file that scans clean as a Dockerfile."""
    fenced = '```hcl\nresource "aws_s3_bucket" "x" {\n  bucket = "b"\n}\n```'
    assert not check_validity(fenced, IaCType.DOCKERFILE).ok


def test_dockerfile_without_from_is_rejected() -> None:
    assert not check_validity("RUN echo hi\nUSER app\n", IaCType.DOCKERFILE).ok


def test_dockerfile_with_leading_arg_is_accepted() -> None:
    """Docker permits ARG before FROM, so the gate must too."""
    assert check_validity("ARG TAG=3.12\nFROM python:${TAG}\nUSER app\n", IaCType.DOCKERFILE).ok


def test_dockerfile_unknown_instruction_is_not_a_valid_remediation() -> None:
    result = check_validity("FROM python:3.12\nNOT_A_DOCKER_INSTRUCTION remove-app\n", IaCType.DOCKERFILE)
    assert not result.ok
    assert result.reason == "unknown_instruction"


def test_dockerfile_required_instruction_argument_cannot_be_empty() -> None:
    result = check_validity("FROM python:3.12\nCOPY\n", IaCType.DOCKERFILE)
    assert not result.ok


@pytest.mark.parametrize(
    "text",
    [
        "FROM --platform=linux/amd64\n",
        "FROM --platform=linux/amd64 AS final\n",
        "FROM python:3.12\nCOPY source\n",
    ],
)
def test_dockerfile_requires_image_and_copy_destination(text: str) -> None:
    assert not check_validity(text, IaCType.DOCKERFILE).ok


def test_dockerfile_allows_tabs_between_instruction_and_arguments() -> None:
    assert check_validity("FROM\tpython:3.12\nCOPY\t. /app\n", IaCType.DOCKERFILE).ok


@pytest.mark.parametrize(
    "candidate",
    [
        "FROM scratch\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
        "FROM python:3.13\nCMD [\"python\", \"app.py\"]\n",
        "FROM python:3.13\nCOPY . /app\n",
    ],
)
def test_dockerfile_structure_drops_are_detected(candidate: str) -> None:
    from eval.serialise import drift_to_dict

    original = "FROM python:3.12\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n"
    drift = compute_drift(original, candidate, IaCType.DOCKERFILE)
    assert drift.drifted
    assert drift.docker_drops
    assert drift_to_dict(drift)["docker_drops"] == drift.docker_drops


def test_dockerfile_security_changes_can_keep_its_application_structure() -> None:
    original = "FROM python:3.12\nCOPY . /app\nUSER root\nCMD [\"python\", \"app.py\"]\n"
    fixed = "FROM python:3.13\nCOPY --chown=app . /app\nUSER app\nCMD [\"python\", \"app.py\"]\n"
    assert not compute_drift(original, fixed, IaCType.DOCKERFILE).drifted


# --------------------------------------------------------------------------------------
# drift — the positive cases matter most
# --------------------------------------------------------------------------------------


def test_identical_input_does_not_drift() -> None:
    original = (SAMPLES / "vulnerable_main.tf").read_text()
    assert not compute_drift(original, original, IaCType.TERRAFORM).drifted


def test_deletion_is_detected() -> None:
    drift = compute_drift(TWO_BUCKETS, ONE_BUCKET, IaCType.TERRAFORM)
    assert drift.drifted
    assert "aws_s3_bucket.b" in [r.address for r in drift.deleted]


def test_type_count_drop_is_detected() -> None:
    """Two buckets becoming one is drift even though the type still appears."""
    drift = compute_drift(TWO_BUCKETS, ONE_BUCKET, IaCType.TERRAFORM)
    assert "aws_s3_bucket" in drift.type_count_drops


def test_rename_is_detected() -> None:
    """Renames break `terraform state` continuity — a destroy/recreate on next apply."""
    renamed = ONE_BUCKET.replace('"a"', '"a_renamed"')
    drift = compute_drift(ONE_BUCKET, renamed, IaCType.TERRAFORM)
    assert drift.drifted


def test_additions_alone_are_not_drift() -> None:
    """Securing a public bucket correctly *requires* adding resources."""
    drift = compute_drift(ONE_BUCKET, TWO_BUCKETS, IaCType.TERRAFORM)
    assert [r.address for r in drift.added]
    assert not drift.drifted


def test_wholesale_replacement_is_drift() -> None:
    """The file replaced by one unrelated secure resource — a perfect finding delta."""
    replacement = 'resource "aws_s3_bucket" "totally_different" {\n  bucket = "x"\n}\n'
    drift = compute_drift(TWO_BUCKETS, replacement, IaCType.TERRAFORM)
    assert drift.drifted


def test_drift_touches_flaw_identifies_the_deleted_flawed_resource() -> None:
    """The 'fixed it by deleting it' detector, on the exact shape seen in a live run.

    In the first live evaluation the model removed aws_s3_bucket_policy.public_policy rather
    than restricting its principal. Findings dropped; nothing was secured.
    """
    original = (SAMPLES / "vulnerable_main.tf").read_text()
    without_rds = original.replace(
        'resource "aws_db_instance" "bad_rds" {', 'resource "aws_db_instance" "renamed_rds" {'
    )
    drift = compute_drift(original, without_rds, IaCType.TERRAFORM)
    lost = drift_touches_flaw(drift, {"aws_db_instance.bad_rds"})
    assert "aws_db_instance.bad_rds" in lost


def test_drift_touches_flaw_ignores_unflagged_resources() -> None:
    """Deleting a resource that carried no finding is drift, but not a masked fix."""
    drift = compute_drift(TWO_BUCKETS, ONE_BUCKET, IaCType.TERRAFORM)
    assert drift.drifted
    assert drift_touches_flaw(drift, {"aws_db_instance.something_else"}) == []
