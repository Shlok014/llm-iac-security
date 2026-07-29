"""Ground truth: the recall denominator, and the hand verdicts on what it fails to cover.

Kept in YAML under `eval/labels/` so it is reviewable separately from the code that scores
against it, and loaded here rather than parsed ad hoc at each call site so that every
refusal is in one place. The refusals are the point of this module: an unknown
`schema_version`, a duplicate label id, or a `detectable_by_scanner` flag that disagrees
with the id lists all raise `LabelError` instead of yielding a smaller label set. A recall
denominator that is quietly wrong is worse than a crash, because it still prints a number.

`Adjudication` and `load_adjudications` live here too. They are ground truth of the second
kind — hand-written verdicts on findings the labels do not cover — and `docs/EVALUATION.md`
threat T9 records that they are written by the system's own author.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from iac_agent.types import IaCType, ScanResult

from . import ADJUDICATION_YAML, LABELS_DIR, SCANNER_NAMES, fixture_key
from .matching import normalise_text, terraform_resource_matches

LABEL_SCHEMA_VERSION = 1

# The bucket vocabulary from docs/EVALUATION.md §5.2. `hallucination` is the only one that
# stays a false positive under both precision figures.
ADJUDICATION_BUCKETS = ("real_unlabelled", "phrasing_miss", "hallucination")


@dataclass(frozen=True)
class Label:
    """One deliberately-planted flaw. See eval/labels/README.md for the authoring rules."""

    id: str
    resource: str
    lines: tuple[int, ...]
    description: str
    category: str
    severity_expected: str
    checkov_ids: tuple[str, ...]
    trivy_ids: tuple[str, ...]
    detectable_by_scanner: bool
    aliases: tuple[str, ...]
    fixture: str
    framework: IaCType

    def scanner_ids(self, scanner: str) -> tuple[str, ...]:
        return self.checkov_ids if scanner == "checkov" else self.trivy_ids


@dataclass(frozen=True)
class LabelSet:
    fixture: str
    framework: IaCType
    labels: tuple[Label, ...]

    def __len__(self) -> int:
        return len(self.labels)

    @property
    def detectable(self) -> tuple[Label, ...]:
        return tuple(label for label in self.labels if label.detectable_by_scanner)


class LabelError(Exception):
    """A label file could not be trusted. Never downgraded to an empty label set."""


def load_labels(fixture: str | Path, labels_dir: Path | None = None) -> LabelSet:
    """Load `<stem>.labels.yaml` for a fixture.

    Refuses an unknown `schema_version` rather than guessing at the field set: a label
    file half-understood produces a recall denominator that is quietly wrong, which is
    worse than a crash.
    """
    stem = Path(fixture).stem
    path = (labels_dir or LABELS_DIR) / f"{stem}.labels.yaml"
    if not path.is_file():
        raise LabelError(f"no ground truth for {fixture}: expected {path}")

    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    version = int(doc.get("schema_version") or 0)
    if version != LABEL_SCHEMA_VERSION:
        raise LabelError(
            f"{path.name} declares schema_version {version}; this loader understands "
            f"{LABEL_SCHEMA_VERSION} only. Refusing to guess at the field set."
        )

    framework = IaCType(str(doc.get("framework", "terraform")))
    fixture_id = str(doc.get("fixture") or fixture_key(fixture))

    labels: list[Label] = []
    seen: set[str] = set()
    for raw in doc.get("labels") or []:
        lid = str(raw.get("id") or "").strip()
        if not lid:
            raise LabelError(f"{path.name}: a label has no id")
        if lid in seen:
            raise LabelError(f"{path.name}: duplicate label id {lid!r} (must be unique per file)")
        seen.add(lid)
        checkov_ids = tuple(str(x) for x in (raw.get("checkov_ids") or []))
        trivy_ids = tuple(str(x) for x in (raw.get("trivy_ids") or []))
        detectable = bool(raw.get("detectable_by_scanner"))
        if detectable != bool(checkov_ids or trivy_ids):
            # The schema says this field is redundant *on purpose*; if the redundancy
            # ever disagrees, the file is wrong and silently believing either half would
            # move the "LLM finds what scanners cannot" number.
            raise LabelError(
                f"{path.name}: {lid} has detectable_by_scanner={detectable} but "
                f"{len(checkov_ids)} checkov ids and {len(trivy_ids)} trivy ids"
            )
        labels.append(
            Label(
                id=lid,
                resource=str(raw.get("resource") or ""),
                lines=tuple(int(x) for x in (raw.get("lines") or [])),
                description=str(raw.get("description") or ""),
                category=str(raw.get("category") or ""),
                severity_expected=str(raw.get("severity_expected") or ""),
                checkov_ids=checkov_ids,
                trivy_ids=trivy_ids,
                detectable_by_scanner=detectable,
                aliases=tuple(str(x) for x in (raw.get("aliases") or [])),
                fixture=fixture_id,
                framework=framework,
            )
        )
    return LabelSet(fixture=fixture_id, framework=framework, labels=tuple(labels))


def load_all_labels(
    fixtures: Iterable[str | Path], labels_dir: Path | None = None
) -> dict[str, LabelSet]:
    return {fixture_key(f): load_labels(f, labels_dir) for f in fixtures}


def verify_label_ids(
    labelsets: Mapping[str, LabelSet],
    baseline: Mapping[str, Mapping[str, ScanResult]],
) -> list[str]:
    """Check that every label's scanner ids actually fire on that fixture.

    This is the weak half of the "ids are copied from output, never written from memory"
    rule (docs/EVALUATION.md §3.2), and the weakness is specific: it verifies that the ids
    *exist in the scan*, not that they are attached to the right label. The strong half
    stays an authoring discipline.

    A label lists **acceptable identifiers, not a single canonical one** — Trivy's `ID`
    field is sometimes a legacy slug rather than the `AVD-...` id, and the labels record
    both. So the check is "at least one id from each non-empty list appears", not "all
    of them do". Requiring all would fail on every correctly-authored Trivy label.
    """
    violations: list[str] = []
    for fixture, labelset in sorted(labelsets.items()):
        scans = baseline.get(fixture) or {}
        for scanner in SCANNER_NAMES:
            scan = scans.get(scanner)
            if scan is None:
                continue
            present = {f.rule_id for f in scan.failed}
            for label in labelset.labels:
                ids = label.scanner_ids(scanner)
                if ids and not (set(ids) & present):
                    violations.append(
                        f"{fixture}:{label.id}: none of {scanner}_ids {list(ids)} appear "
                        f"in the {scanner} baseline for this fixture"
                    )
    return violations


@dataclass(frozen=True)
class Adjudication:
    """One hand-written verdict on an LLM finding that matched no label."""

    fixture: str
    bucket: str
    resource: str = ""
    issue_contains: str = ""
    variant: str = ""
    rationale: str = ""

    def applies_to(self, finding: Mapping[str, Any], fixture: str, variant: str) -> bool:
        if self.fixture and self.fixture != fixture:
            return False
        if self.variant and self.variant != variant:
            return False
        if self.resource and not terraform_resource_matches(
            str(finding.get("resource", "")), self.resource
        ):
            return False
        if self.issue_contains:
            hay = normalise_text(
                f"{finding.get('issue', '')} {finding.get('recommendation', '')}"
            )
            if normalise_text(self.issue_contains) not in hay:
                return False
        return True


def load_adjudications(path: Path | None = None) -> list[Adjudication]:
    """Load the hand-authored adjudication file, if it exists.

    Absent file means "nothing adjudicated" — which is honest, because the strict
    precision figure is computed regardless and is the defensible floor. The file is
    hand-written and committed precisely so that a reader can dispute each verdict; see
    docs/EVALUATION.md §5.2 and threat T9, which notes that this adjudication is performed
    by the system's own author.
    """
    p = path or ADJUDICATION_YAML
    if not p.is_file():
        return []
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out: list[Adjudication] = []
    for raw in doc.get("entries") or []:
        bucket = str(raw.get("bucket") or "").strip()
        if bucket not in ADJUDICATION_BUCKETS:
            raise LabelError(
                f"{p.name}: unknown adjudication bucket {bucket!r}; "
                f"expected one of {ADJUDICATION_BUCKETS}"
            )
        out.append(
            Adjudication(
                fixture=str(raw.get("fixture") or ""),
                bucket=bucket,
                resource=str(raw.get("resource") or ""),
                issue_contains=str(raw.get("issue_contains") or ""),
                variant=str(raw.get("variant") or ""),
                rationale=str(raw.get("rationale") or ""),
            )
        )
    return out
