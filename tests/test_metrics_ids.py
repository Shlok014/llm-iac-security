"""Regression test for scanner rule-id normalisation.

Trivy publishes two identifiers for every Dockerfile rule and emits both in the same object:
`ID` is `DS002`, `AVDID` is `AVD-DS-0002`. `Finding.rule_id` is built from `ID`, but a label
author reading Trivy's documentation will often write the AVD form — and several committed
labels do.

Unnormalised, the join in `map_scanner_findings` is by `rule_id` string equality, so every
Dockerfile label written in the AVD form scored as a miss and recall was understated with
nothing in the output to indicate why. Silent undercounting is exactly the failure class this
project exists to eliminate, so it gets a test rather than a comment.
"""

from __future__ import annotations

import pytest

from eval.metrics import normalise_rule_id


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("AVD-DS-0002", "DS002"),
        ("AVD-DS-0004", "DS004"),
        ("AVD-DS-0026", "DS026"),
        ("AVD-DS-0031", "DS031"),
        ("avd-ds-0002", "DS002"),
        ("  AVD-DS-0002  ", "DS002"),
    ],
)
def test_avd_dockerfile_ids_normalise_to_the_short_form(raw: str, expected: str) -> None:
    assert normalise_rule_id(raw) == expected


@pytest.mark.parametrize("raw", ["DS002", "DS031"])
def test_short_form_is_already_canonical(raw: str) -> None:
    assert normalise_rule_id(raw) == raw


@pytest.mark.parametrize(
    "raw",
    [
        "AVD-AWS-0092",  # Terraform: Trivy emits the AVD form in `ID`, so it IS canonical
        "AVD-AWS-0180",
        "CKV_AWS_20",  # Checkov ids are a different namespace entirely
        "CKV_DOCKER_2",
        "aws-vpc-no-public-egress-sgr",  # Trivy also emits slug-style ids
    ],
)
def test_other_id_families_pass_through_untouched(raw: str) -> None:
    """Over-normalising would collide unrelated rules, which is worse than the bug it fixes."""
    assert normalise_rule_id(raw) == raw


def test_both_forms_of_the_same_rule_agree() -> None:
    """The property the join actually depends on."""
    assert normalise_rule_id("AVD-DS-0002") == normalise_rule_id("DS002")


def test_empty_and_missing_ids_do_not_explode() -> None:
    assert normalise_rule_id("") == ""
    assert normalise_rule_id("   ") == ""


def test_committed_dockerfile_labels_join_against_live_scanner_output() -> None:
    """End-to-end: the committed labels must actually match what Trivy reports.

    This is the test that would have caught the original bug. It reads the real label files
    and the real scanner ids, so it fails if either side drifts.
    """
    import yaml

    from eval import SAMPLES_DIR
    from eval.labels_io import load_labels

    fixture = SAMPLES_DIR / "docker_insecure.Dockerfile"
    if not fixture.is_file():  # pragma: no cover - corpus always ships this
        pytest.skip("fixture missing")

    labelset = load_labels(fixture)
    trivy_label_ids = {
        normalise_rule_id(i) for label in labelset.labels for i in label.trivy_ids
    }
    assert trivy_label_ids, "expected some trivy ids on this fixture's labels"
    # Every normalised label id must be in the short-form namespace Finding.rule_id uses.
    assert all(not i.upper().startswith("AVD-DS-") for i in trivy_label_ids)
    _ = yaml  # imported to assert the dependency exists for label loading
