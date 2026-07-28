"""Every scanner rule id in every label file must actually fire on its fixture.

This is the test that enforces the project's most important data rule: **a rule id is copied
from live scanner output, never written from memory.** The submitted report's results table
cited `CKV_AWS_3` for security groups (it is EBS encryption) and `CKV_AWS_7` for IAM wildcards
(it is CMK rotation) — see `ERRATA.md` E2. Prose can be wrong quietly; this cannot.

It caught five real phantom ids in the committed labels when first written, all of them the
same underlying mistake: Trivy publishes two identifiers per rule and emits them in different
fields, so `AVD-AWS-0104` (the `AVDID`) was recorded where `aws-vpc-no-public-egress-sgr` (the
`ID`, which is what `Finding.rule_id` carries) was needed. Both are real; only one joins.

Marked slow because it shells out to both scanners for every fixture.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from eval.metrics import normalise_rule_id

REPO = Path(__file__).resolve().parent.parent
LABELS_DIR = REPO / "eval" / "labels"
LABEL_FILES = sorted(LABELS_DIR.glob("*.labels.yaml"))

CATEGORIES = {
    "public-exposure", "secrets", "encryption", "iam-overprivilege",
    "network-open", "supply-chain", "container-hardening",
}
SEVERITIES = {"critical", "high", "medium", "low"}


def _live_rule_ids(fixture: Path, framework: str) -> set[str]:
    """Every rule id both scanners actually report for this fixture, normalised."""
    ids: set[str] = set()

    checkov = Path(sys.executable).parent / "checkov"
    proc = subprocess.run(
        [str(checkov), "-f", str(fixture), "-o", "json", "--compact", "--quiet",
         "--framework", framework],
        capture_output=True, text=True, timeout=300, check=False,
    )
    start = proc.stdout.find("{")
    if start != -1:
        doc = json.loads(proc.stdout[start:])
        doc = doc[0] if isinstance(doc, list) else doc
        ids |= {c["check_id"] for c in doc.get("results", {}).get("failed_checks", [])}

    proc = subprocess.run(
        ["trivy", "config", "--quiet", "--format", "json", str(fixture)],
        capture_output=True, text=True, timeout=300, check=False,
    )
    if proc.stdout.strip():
        for result in json.loads(proc.stdout).get("Results", []) or []:
            ids |= {m["ID"] for m in (result.get("Misconfigurations") or [])}

    return {normalise_rule_id(i) for i in ids}


@pytest.mark.parametrize("label_file", LABEL_FILES, ids=lambda p: p.name)
def test_label_file_is_well_formed(label_file: Path) -> None:
    doc = yaml.safe_load(label_file.read_text())
    assert doc["schema_version"] == 1
    assert (REPO / doc["fixture"]).is_file(), f"fixture missing: {doc['fixture']}"
    assert doc["framework"] in {"terraform", "dockerfile"}

    seen: set[str] = set()
    for label in doc.get("labels") or []:
        assert label["id"] not in seen, f"duplicate label id {label['id']}"
        seen.add(label["id"])
        assert label["category"] in CATEGORIES, f"{label['id']}: bad category"
        assert label["severity_expected"] in SEVERITIES, f"{label['id']}: bad severity"
        assert label.get("description"), f"{label['id']}: needs a description"


@pytest.mark.parametrize("label_file", LABEL_FILES, ids=lambda p: p.name)
def test_detectable_flag_matches_the_id_lists(label_file: Path) -> None:
    """`detectable_by_scanner` is the claim that drives the LLM-value-add subset.

    If it is true with no ids, the label is unfalsifiable; if false with ids, the
    scanner-invisible subset is understated and the project's central claim about where an
    LLM adds value is overstated in its own favour.
    """
    doc = yaml.safe_load(label_file.read_text())
    for label in doc.get("labels") or []:
        has_ids = bool(label.get("checkov_ids") or label.get("trivy_ids"))
        assert label["detectable_by_scanner"] == has_ids, (
            f"{label['id']}: detectable_by_scanner={label['detectable_by_scanner']} "
            f"but has_ids={has_ids}"
        )


@pytest.mark.slow
@pytest.mark.parametrize("label_file", LABEL_FILES, ids=lambda p: p.name)
def test_every_claimed_rule_id_actually_fires(label_file: Path) -> None:
    doc = yaml.safe_load(label_file.read_text())
    labels = doc.get("labels") or []
    if not labels:
        return  # secure negative controls legitimately have none

    fixture = REPO / doc["fixture"]
    live = _live_rule_ids(fixture, doc["framework"])

    phantom = [
        (label["id"], rule_id)
        for label in labels
        for rule_id in (label.get("checkov_ids") or []) + (label.get("trivy_ids") or [])
        if normalise_rule_id(rule_id) not in live
    ]
    assert not phantom, (
        f"{label_file.name}: rule ids that do not fire on {doc['fixture']}: {phantom}. "
        "Copy ids from live scanner output; never write them from memory (ERRATA.md E2)."
    )


@pytest.mark.slow
@pytest.mark.parametrize(
    "label_file", [p for p in LABEL_FILES if p.name.startswith("secure_")], ids=lambda p: p.name
)
def test_secure_controls_report_no_findings(label_file: Path) -> None:
    """The negative controls must stay clean, or precision on safe code becomes unmeasurable."""
    doc = yaml.safe_load(label_file.read_text())
    fixture = REPO / doc["fixture"]
    if not fixture.is_file():
        pytest.skip(f"{doc['fixture']} not present")
    assert not (doc.get("labels") or []), "a secure control must have no planted flaws"
    assert not _live_rule_ids(fixture, doc["framework"]), (
        f"{doc['fixture']} is meant to be a clean negative control but scanners report findings"
    )
