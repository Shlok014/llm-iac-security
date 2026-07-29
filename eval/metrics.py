"""Every number this project publishes, with its formula and its denominator.

The rule this module is written to enforce: **a metric whose denominator is not stated is
not a measurement.** The original report's "high detection accuracy" had no denominator,
no dataset size and no baseline, and it was produced by a pipeline whose validation step
had never once executed. Each function below states its formula in its docstring, names
the population it divides by, and says what it cannot see.

Four metric families, plus the baseline that all four have to justify themselves against:

1. `finding_delta`   — scanner-relative. Did the remediated file trip fewer rules? Counts
                       every rule violation, planted or incidental. `introduced` is a
                       first-class output and is **never netted against `resolved`**.
2. `detection_metrics` — ground-truth-relative. Did the LLM find the flaws a human
                       planted? Denominator is the label file, never the scanner output.
3. `validity_rate`   — did the model's output parse at all, measured over *attempts*
                       rather than over accepted outputs (which is 100% by construction).
4. `drift_metrics`   — did the finding count drop because the resource was secured, or
                       because it stopped existing?
5. `scanner_baseline` / `scanner_recall` — what checkov and trivy find on the originals
                       with no LLM at all. The absence of this baseline is the single
                       biggest hole in the project's original report: an LLM pipeline that
                       costs money and can hallucinate has to beat two tools that run in a
                       second for free.

An arithmetic subtlety that matters, stated once here and repeated where it bites:
`Finding.key()` is `(rule_id, resource)`, and **that is not injective over findings**.
Trivy raises `DS031` three times on three `ENV` lines of a Dockerfile, all with an empty
`CauseMetadata.Resource`, so three findings collapse to one key. Consequently
`before_count - after_count != resolved - introduced` in general — `docs/EVALUATION.md`
§5.1 asserts that identity, and it holds only when keys are unique within a file. Both
figures are therefore reported side by side rather than one being derived from the other.

Serialisation, ground truth, string matching and the RESULTS.md renderer were split out of
this module — into `eval.serialise`, `eval.labels_io`, `eval.matching` and `eval.render` —
so that what is left here is only the arithmetic. Nothing about the numbers changed; the
split exists so that a reader auditing a formula does not have to scroll past four hundred
lines of markdown emission to find the next one.
"""

from __future__ import annotations

import math
import re
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from iac_agent.types import Finding, IaCType, ScanResult

from . import BASELINE_JSON, RESULTS_JSON, RESULTS_MD, SCANNER_NAMES
from .labels_io import (
    Adjudication,
    LabelSet,
    load_adjudications,
    load_labels,
    verify_label_ids,
)
from .matching import (
    _content_tokens,
    dockerfile_resource_matches,
    resource_matches,
    semantic_matches,
    terraform_resource_matches,
)
from .serialise import scan_from_dict


# --------------------------------------------------------------------------------------
# descriptive statistics — deliberately not inferential ones
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Stat:
    """mean with [min, max] over repeat runs. **Descriptive, not inferential.**

    Six fixtures and a handful of repeats is far too small to support confidence
    intervals, standard errors, significance tests, or any claim that one configuration
    beats another. The range answers exactly one question — *how much does this number
    move when nothing changes?* — and if it turns out to be wide relative to the gap
    between two conditions, the honest reading is that this harness cannot tell them
    apart. No error bar in this project implies a sampling distribution.
    """

    n: int
    mean: float | None
    minimum: float | None
    maximum: float | None
    values: tuple[float, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "mean": self.mean,
            "min": self.minimum,
            "max": self.maximum,
            "values": list(self.values),
        }


def describe(values: Iterable[float | int | None]) -> Stat:
    vals = [float(v) for v in values if v is not None and not _is_nan(v)]
    if not vals:
        return Stat(n=0, mean=None, minimum=None, maximum=None, values=())
    return Stat(
        n=len(vals),
        mean=statistics.fmean(vals),
        minimum=min(vals),
        maximum=max(vals),
        values=tuple(vals),
    )


def _is_nan(v: Any) -> bool:
    return isinstance(v, float) and math.isnan(v)


def fmt_stat(stat: Stat | Mapping[str, Any] | None, digits: int = 3, pct: bool = False) -> str:
    """Render a Stat as `mean [min, max]`, collapsing to a bare value when n <= 1."""
    if stat is None:
        return "n/a"
    if isinstance(stat, Mapping):
        n, mean, lo, hi = (
            int(stat.get("n") or 0),
            stat.get("mean"),
            stat.get("min"),
            stat.get("max"),
        )
    else:
        n, mean, lo, hi = stat.n, stat.mean, stat.minimum, stat.maximum
    if not n or mean is None:
        return "n/a"

    def one(v: float) -> str:
        return f"{v * 100:.1f}%" if pct else f"{v:.{digits}f}"

    if n == 1 or (lo == hi):
        return one(mean)
    return f"{one(mean)} [{one(lo)}, {one(hi)}]"


def safe_ratio(numerator: float, denominator: float) -> float | None:
    """A rate with an empty denominator is `None`, never 0.0 and never 1.0.

    Returning a number here is how "we measured nothing" becomes indistinguishable from
    "we measured zero" — the same class of fail-open the scanner layer refuses.
    """
    return None if not denominator else numerator / denominator


# --------------------------------------------------------------------------------------
# metric 1 — finding delta
# --------------------------------------------------------------------------------------


def scanner_resource(resource: str, target: str | Path = "") -> str:
    """Path-independent form of a scanner's `resource` string.

    **This exists because of a measured defect in the naive delta.** Checkov identifies a
    Dockerfile finding by ``<absolute path of the file it scanned>.<INSTRUCTION>`` — e.g.
    ``/repo/samples/docker_insecure.Dockerfile.EXPOSE``. The before-scan runs on the
    fixture and the after-scan runs on the remediated copy under
    ``eval/results/artifacts/...``, so **every** `(rule_id, resource)` key differs between
    the two even when the finding is literally unchanged.

    Measured, on `docker_insecure.Dockerfile` with a fix that only appended a `USER`
    instruction: `before = 5, after = 4`, but the raw key sets gave `resolved = 5` and
    `introduced = 4`. Every surviving finding was counted as one resolution plus one new
    misconfiguration. `introduced` is the column that is supposed to catch a model writing
    new problems into a file, so a spurious value there is not cosmetic — it is the metric
    lying in the direction that makes the run look eventful.

    Two strips, in order, because `target` reaches this function two ways: as the absolute
    path the scanner was invoked with (live `ScanResult`), and as the repo-relative path
    `rel_path` writes into `results.json` (replayed `ScanResult`). The first is an exact
    prefix match; the second cuts at the target's *filename*, which is still precise
    because the filename is what the scanner concatenated the instruction onto.

    Terraform resources (`aws_s3_bucket.example`) and Trivy's Dockerfile resources (empty)
    contain no such filename and are returned unchanged.
    """
    res = str(resource or "")
    t = str(target or "")
    if not res or not t:
        return res
    if res.startswith(t):
        return res[len(t):].lstrip(".").strip()
    name = Path(t).name
    idx = res.find(name)
    if name and idx != -1:
        return res[idx + len(name):].lstrip(".").strip()
    return res


def delta_keys(scan: ScanResult) -> set[tuple[str, str]]:
    """`ScanResult.keys()` with the scan path removed from each resource. See above."""
    return {(f.rule_id, scanner_resource(f.resource, scan.target)) for f in scan.failed}


@dataclass(frozen=True)
class RuleDelta:
    rule_id: str
    before: int
    after: int

    @property
    def resolved(self) -> int:
        return max(0, self.before - self.after)


@dataclass
class DeltaResult:
    """Before/after scanner arithmetic for one (fixture, scanner) pair.

    Formulas, over `ScanResult`s of the original and the remediated file::

        before_count = |before.failed|              # findings, not keys
        after_count  = |after.failed|
        delta_pct    = (before_count - after_count) / before_count

        resolved   = |before.keys() - after.keys()|
        introduced = |after.keys()  - before.keys()|
        persisted  = |before.keys() & after.keys()|

    `introduced` is reported separately and **never netted against `resolved`**, because
    `before - after = resolved - introduced` makes a run that resolves 40 and introduces
    10 arithmetically indistinguishable from one that resolves 30 and introduces 0. The
    first wrote ten new misconfigurations into the user's infrastructure. (And the two
    sides of that identity can differ anyway — see the module docstring on non-injective
    keys.)

    Counts every rule violation, planted or incidental, because the scanner does not know
    the difference and neither does a user running this on their own repository.
    """

    scanner: str
    fixture: str
    before_count: int
    after_count: int
    resolved: int
    introduced: int
    persisted: int
    introduced_keys: tuple[tuple[str, str], ...] = ()
    resolved_keys: tuple[tuple[str, str], ...] = ()
    per_rule: tuple[RuleDelta, ...] = ()
    remediation_valid: bool = True

    @property
    def delta_pct(self) -> float | None:
        return safe_ratio(self.before_count - self.after_count, self.before_count)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "fixture": self.fixture,
            "before": self.before_count,
            "after": self.after_count,
            "delta_pct": self.delta_pct,
            "resolved": self.resolved,
            "introduced": self.introduced,
            "persisted": self.persisted,
            "introduced_keys": [list(k) for k in self.introduced_keys],
            "resolved_keys": [list(k) for k in self.resolved_keys],
            "per_rule": [
                {"rule_id": r.rule_id, "before": r.before, "after": r.after, "resolved": r.resolved}
                for r in self.per_rule
            ],
            "remediation_valid": self.remediation_valid,
        }


def finding_delta(
    before: ScanResult,
    after: ScanResult,
    fixture: str = "",
    remediation_valid: bool = True,
) -> DeltaResult:
    """Compute the before/after delta for one fixture and one scanner. See `DeltaResult`.

    Keys come from `delta_keys`, not from `ScanResult.keys()`: the raw key embeds the
    scanned file's path for Checkov Dockerfile findings, and the remediated file is by
    definition at a different path.
    """
    before_keys, after_keys = delta_keys(before), delta_keys(after)
    rule_ids = {f.rule_id for f in before.failed} | {f.rule_id for f in after.failed}
    per_rule = tuple(
        RuleDelta(
            rule_id=rid,
            before=sum(1 for f in before.failed if f.rule_id == rid),
            after=sum(1 for f in after.failed if f.rule_id == rid),
        )
        for rid in sorted(rule_ids)
    )
    return DeltaResult(
        scanner=before.scanner,
        fixture=fixture,
        before_count=before.failed_count,
        after_count=after.failed_count,
        resolved=len(before_keys - after_keys),
        introduced=len(after_keys - before_keys),
        persisted=len(before_keys & after_keys),
        introduced_keys=tuple(sorted(after_keys - before_keys)),
        resolved_keys=tuple(sorted(before_keys - after_keys)),
        per_rule=per_rule,
        remediation_valid=remediation_valid,
    )


def aggregate_deltas(deltas: Sequence[DeltaResult], scanner: str) -> dict[str, Any]:
    """Corpus totals for one scanner.

    Summed per fixture rather than computed over a union of key sets, because
    `Finding.key()` is only unique *within* a file: two Dockerfiles both produce
    `("DS002", "")`, and unioning would silently merge them into one finding.
    """
    rows = [d for d in deltas if d.scanner == scanner]
    before = sum(d.before_count for d in rows)
    after = sum(d.after_count for d in rows)
    per_rule: dict[str, list[int]] = {}
    for d in rows:
        for r in d.per_rule:
            slot = per_rule.setdefault(r.rule_id, [0, 0])
            slot[0] += r.before
            slot[1] += r.after
    return {
        "scanner": scanner,
        "fixtures": len(rows),
        "before": before,
        "after": after,
        "delta_pct": safe_ratio(before - after, before),
        "resolved": sum(d.resolved for d in rows),
        "introduced": sum(d.introduced for d in rows),
        "persisted": sum(d.persisted for d in rows),
        "invalid_remediations": sum(1 for d in rows if not d.remediation_valid),
        "per_rule": [
            {"rule_id": rid, "before": b, "after": a, "resolved": max(0, b - a)}
            for rid, (b, a) in sorted(per_rule.items(), key=lambda kv: (-(kv[1][0] - kv[1][1]), kv[0]))
        ],
    }


# --------------------------------------------------------------------------------------
# metric 2 — detection precision and recall
# --------------------------------------------------------------------------------------


@dataclass
class DetectionMetrics:
    """Precision and recall against the ground truth, for one fixture and one variant.

    Two counting units, because recall and precision have different natural ones::

        TP_label   = labels matched by at least one finding
        FN         = |labels| - TP_label
        TP_finding = findings matching at least one label
        FP_strict  = |findings| - TP_finding

        recall            = TP_label   / |labels|
        precision_strict  = TP_finding / |findings|

    Recall is label-wise so that reporting the same flaw three times cannot inflate it.
    Precision is finding-wise so that verbose output is penalised.

    **The denominator of recall is PLANTED labels only.** Incidental scanner findings —
    controls the fixture never claimed to configure, which are the majority of what the
    scanners report on the Terraform fixtures — are excluded from precision and recall
    entirely, while still counting fully in the finding delta. Using a scanner-derived
    denominator would make recall a measure of agreement with Checkov's current ruleset,
    which moves whenever Checkov ships a policy even though the fixture never changed.

    **False positives are reported two ways.** `precision_strict` calls every unmatched
    finding wrong, which is too harsh — an unmatched finding may be a real flaw the
    annotator missed, and penalising the model for out-thoroughness measures the annotator.
    So unmatched findings that are *plausible* (they correspond to a real, unlabelled
    scanner finding, or a hand adjudication says so) are counted separately::

        precision_adjudicated          = TP_finding / (|findings| - |plausible|)
        precision_adjudicated_credited = (TP_finding + |plausible|) / |findings|

    Both forms appear in the project's own documents — `eval/labels/README.md` excludes
    plausible findings from both numerator and denominator, `docs/EVALUATION.md` §5.2
    credits them in the numerator — so both are computed rather than one being quietly
    chosen. `hallucination` verdicts are never plausible under either.
    """

    fixture: str
    variant: str
    n_labels: int
    tp_label: int
    n_findings: int
    tp_finding: int
    plausible: int
    hallucinated: int
    matched_label_ids: tuple[str, ...] = ()
    missed_label_ids: tuple[str, ...] = ()
    unmatched_findings: tuple[dict[str, Any], ...] = ()
    pairs: tuple[tuple[int, str, str], ...] = ()  # (finding index, label id, alias hit)

    @property
    def fn(self) -> int:
        return self.n_labels - self.tp_label

    @property
    def fp_strict(self) -> int:
        return self.n_findings - self.tp_finding

    @property
    def recall(self) -> float | None:
        return safe_ratio(self.tp_label, self.n_labels)

    @property
    def precision_strict(self) -> float | None:
        return safe_ratio(self.tp_finding, self.n_findings)

    @property
    def precision_adjudicated(self) -> float | None:
        return safe_ratio(self.tp_finding, self.n_findings - self.plausible)

    @property
    def precision_adjudicated_credited(self) -> float | None:
        return safe_ratio(self.tp_finding + self.plausible, self.n_findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "fixture": self.fixture,
            "variant": self.variant,
            "labels": self.n_labels,
            "tp_label": self.tp_label,
            "fn": self.fn,
            "recall": self.recall,
            "findings": self.n_findings,
            "tp_finding": self.tp_finding,
            "fp_strict": self.fp_strict,
            "plausible_unmatched": self.plausible,
            "hallucinated": self.hallucinated,
            "precision_strict": self.precision_strict,
            "precision_adjudicated": self.precision_adjudicated,
            "precision_adjudicated_credited": self.precision_adjudicated_credited,
            "matched_label_ids": list(self.matched_label_ids),
            "missed_label_ids": list(self.missed_label_ids),
            "unmatched_findings": [dict(f) for f in self.unmatched_findings],
            "pairs": [list(p) for p in self.pairs],
        }


def _is_plausible(
    finding: Mapping[str, Any],
    unmapped_scanner_findings: Sequence[Finding],
    framework: IaCType,
) -> bool:
    """Heuristic: does this unmatched LLM finding describe a real, unlabelled scanner finding?

    Requires resource compatibility *and* at least two shared content words with the
    scanner check's name. Deliberately conservative — a wrong "plausible" verdict inflates
    the adjudicated precision, which is already the less trustworthy of the two figures.
    A hand entry in `eval/results/adjudication.yaml` overrides this in either direction.
    """
    llm_tokens = _content_tokens(
        f"{finding.get('issue', '')} {finding.get('recommendation', '')}"
    )
    if not llm_tokens:
        return False
    for sf in unmapped_scanner_findings:
        if framework is IaCType.DOCKERFILE:
            compatible = dockerfile_resource_matches(str(finding.get("resource", "")), sf.resource)
        else:
            compatible = terraform_resource_matches(str(finding.get("resource", "")), sf.resource)
        if not compatible:
            continue
        if len(llm_tokens & _content_tokens(sf.message)) >= 2:
            return True
    return False


def detection_metrics(
    findings: Sequence[Mapping[str, Any]],
    labelset: LabelSet,
    variant: str = "",
    unmapped_scanner_findings: Sequence[Finding] = (),
    adjudications: Sequence[Adjudication] = (),
) -> DetectionMetrics:
    """Match LLM findings to labels and count. See `DetectionMetrics` for the formulas.

    Matching is many-to-many by design (docs/EVALUATION.md §5.2): one verbose finding may
    satisfy two labels, and two findings may both satisfy one. That favours recall, and
    saying so is cheaper than pretending an assignment problem was solved here.
    """
    matched_labels: dict[str, str] = {}
    matched_findings: set[int] = set()
    pairs: list[tuple[int, str, str]] = []

    for idx, finding in enumerate(findings):
        for label in labelset.labels:
            if not resource_matches(str(finding.get("resource", "")), label):
                continue
            alias = semantic_matches(finding, label)
            if alias is None:
                continue
            matched_findings.add(idx)
            matched_labels.setdefault(label.id, alias)
            pairs.append((idx, label.id, alias))

    unmatched: list[dict[str, Any]] = []
    plausible = 0
    hallucinated = 0
    for idx, finding in enumerate(findings):
        if idx in matched_findings:
            continue
        verdicts = [
            a.bucket
            for a in adjudications
            if a.applies_to(finding, labelset.fixture, variant)
        ]
        if "hallucination" in verdicts:
            bucket = "hallucination"
        elif verdicts:
            bucket = verdicts[0]
        elif _is_plausible(finding, unmapped_scanner_findings, labelset.framework):
            bucket = "real_unlabelled"
        else:
            bucket = "hallucination"
        if bucket == "hallucination":
            hallucinated += 1
        else:
            plausible += 1
        unmatched.append({**dict(finding), "adjudication": bucket})

    return DetectionMetrics(
        fixture=labelset.fixture,
        variant=variant,
        n_labels=len(labelset),
        tp_label=len(matched_labels),
        n_findings=len(findings),
        tp_finding=len(matched_findings),
        plausible=plausible,
        hallucinated=hallucinated,
        matched_label_ids=tuple(sorted(matched_labels)),
        missed_label_ids=tuple(
            sorted(label.id for label in labelset.labels if label.id not in matched_labels)
        ),
        unmatched_findings=tuple(unmatched),
        pairs=tuple(pairs),
    )


def aggregate_detection(rows: Sequence[DetectionMetrics]) -> dict[str, Any]:
    """Corpus totals: sum the counts, then divide. Never average the per-fixture rates.

    Averaging rates would give `s3_public.tf` — one label — the same weight as
    `vulnerable_main.tf` — twelve. Summing the counts first weights each fixture by how
    much ground truth it actually contributes.
    """
    n_labels = sum(r.n_labels for r in rows)
    tp_label = sum(r.tp_label for r in rows)
    n_findings = sum(r.n_findings for r in rows)
    tp_finding = sum(r.tp_finding for r in rows)
    plausible = sum(r.plausible for r in rows)
    hallucinated = sum(r.hallucinated for r in rows)
    return {
        "labels": n_labels,
        "tp_label": tp_label,
        "fn": n_labels - tp_label,
        "recall": safe_ratio(tp_label, n_labels),
        "findings": n_findings,
        "tp_finding": tp_finding,
        "fp_strict": n_findings - tp_finding,
        "plausible_unmatched": plausible,
        "hallucinated": hallucinated,
        "precision_strict": safe_ratio(tp_finding, n_findings),
        "precision_adjudicated": safe_ratio(tp_finding, n_findings - plausible),
        "precision_adjudicated_credited": safe_ratio(tp_finding + plausible, n_findings),
    }


# --------------------------------------------------------------------------------------
# metric 3 — validity rate
# --------------------------------------------------------------------------------------


def validity_rate(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """``validity_rate = generated outputs that parse / generation attempts``.

    **Measured over attempts, including ones a refinement loop discarded.** A loop that
    refuses to accept a fix that does not parse makes validity measured on *accepted*
    outputs 100% by construction, which is a statement about the loop and not about the
    model. A run that produced four unparseable drafts before a valid one has a validity
    rate of 20%, not 100%.

    "Parses" is `iac_agent.validity.check_validity`: an `hcl2` parse for Terraform, a
    first-instruction-is-FROM check for Dockerfiles. It is a **syntax gate, not
    `terraform validate`** — it does not resolve references, check provider schemas, or
    check required arguments, so a file can pass this and still be undeployable.
    """
    attempts = 0
    valid = 0
    by_framework: dict[str, list[int]] = {}
    reasons: dict[str, int] = {}

    for record in records:
        framework = str(record.get("iac_type") or "unknown")
        slot = by_framework.setdefault(framework, [0, 0])
        for attempt in record.get("attempts") or []:
            attempts += 1
            slot[0] += 1
            ok = bool(attempt.get("valid"))
            if ok:
                valid += 1
                slot[1] += 1
            reasons[str(attempt.get("reason") or "unknown")] = (
                reasons.get(str(attempt.get("reason") or "unknown"), 0) + 1
            )

    return {
        "attempts": attempts,
        "valid": valid,
        "rate": safe_ratio(valid, attempts),
        "by_framework": {
            k: {"attempts": v[0], "valid": v[1], "rate": safe_ratio(v[1], v[0])}
            for k, v in sorted(by_framework.items())
        },
        "reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
    }


# --------------------------------------------------------------------------------------
# metric 4 — semantic drift
# --------------------------------------------------------------------------------------


def drift_metrics(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """``drift_rate = drifted outputs / valid remediations``, plus the number that matters.

    The failure mode: the cheapest way to make a finding on `aws_db_instance.bad_rds`
    disappear is to delete the resource. The finding delta is then perfect, the file
    parses, precision and recall are unchanged, and the user's database is gone. Every
    other metric in this module is blind to that; the delta actively rewards it.

    `drifted` is `bool(deleted or renamed or type_count_drops)` — additions never set it,
    because fixing a public bucket correctly *requires* adding a public-access-block
    resource, and a metric that punished the correct fix would reward the lazy one.
    Renames do set it: Terraform keys state on the address, so renaming a resource
    destroys and recreates it on the next apply.

    ``flaw_touching_drift`` counts outputs where `drift_touches_flaw()` returned a
    non-empty list — the resources that *carried findings* and then stopped existing.
    That is the "fixed it by deleting it" number, and a non-zero value means the
    corresponding contribution to the finding delta is fraudulent.

    Denominators are stated twice on purpose. Dockerfiles have no addressable resources,
    so `extract_resources` returns `[]` and a Dockerfile can never drift; including them
    in the denominator would dilute the rate with outputs that are structurally incapable
    of moving it. The Terraform-only rate is the headline; the all-output rate is given
    beside it.
    """
    valid_all = 0
    valid_tf = 0
    drifted_all = 0
    drifted_tf = 0
    flaw_touching = 0
    lost: list[str] = []
    deleted = renamed = added = 0
    events: list[dict[str, Any]] = []

    for record in records:
        if not record.get("remediation_valid"):
            continue
        drift = record.get("drift")
        is_tf = str(record.get("iac_type")) == IaCType.TERRAFORM.value
        valid_all += 1
        if is_tf:
            valid_tf += 1
        if not drift:
            continue

        deleted += len(drift.get("deleted") or [])
        renamed += len(drift.get("renamed") or [])
        added += len(drift.get("added") or [])
        if drift.get("drifted"):
            drifted_all += 1
            if is_tf:
                drifted_tf += 1
        touched = list(record.get("drift_touches_flaw") or [])
        if touched:
            flaw_touching += 1
            lost.extend(touched)
        if drift.get("drifted") or touched:
            events.append(
                {
                    "fixture": record.get("fixture"),
                    "variant": record.get("variant"),
                    "run_index": record.get("run_index"),
                    "summary": drift.get("summary", ""),
                    "flaw_carrying_lost": touched,
                }
            )

    return {
        "valid_remediations": valid_all,
        "valid_terraform_remediations": valid_tf,
        "drifted_outputs": drifted_all,
        "drift_rate": safe_ratio(drifted_all, valid_all),
        "drift_rate_terraform": safe_ratio(drifted_tf, valid_tf),
        "flaw_touching_outputs": flaw_touching,
        "flaw_touching_rate": safe_ratio(flaw_touching, valid_tf),
        "flaw_carrying_resources_lost": sorted(set(lost)),
        "resources_deleted": deleted,
        "resources_renamed": renamed,
        "resources_added": added,
        "events": events,
    }


# --------------------------------------------------------------------------------------
# the baseline every other number has to beat
# --------------------------------------------------------------------------------------


_AVD_DOCKER_ALIAS = re.compile(r"^AVD-DS-0*(\d+)$", re.IGNORECASE)


def normalise_rule_id(rule_id: str) -> str:
    """Canonicalise a scanner rule id so a label and a finding can be compared.

    Trivy publishes two identifiers for every Dockerfile rule and emits them in different
    fields of the same object: `ID` is `DS002`, `AVDID` is `AVD-DS-0002`. Both are real and
    both appear in Trivy's own documentation, so a label author reading the docs and a
    `Finding` built from `ID` can disagree while both being correct.

    Left unnormalised the mismatch is *silent*: `map_scanner_findings` joins on `rule_id`,
    so every Dockerfile label written in the AVD form scores as a miss and recall is
    understated with nothing in the output to indicate why. That is the quiet-wrong-number
    failure this project exists to avoid, so the join is made tolerant rather than the
    label files being made to guess a format.

    Terraform ids are unaffected — Trivy emits `AVD-AWS-0092` in the `ID` field there, so
    the AVD form *is* canonical for those and passes through untouched.
    """
    text = (rule_id or "").strip()
    match = _AVD_DOCKER_ALIAS.match(text)
    return f"DS{int(match.group(1)):03d}" if match else text


def map_scanner_findings(
    scan: ScanResult, labelset: LabelSet, scanner: str
) -> tuple[int, set[str]]:
    """Split a scan into findings that map onto a planted label and those that do not.

    Returns `(mapped_finding_count, label_ids_hit)`.

    Mapping is by `rule_id` alone, not by `(rule_id, resource)`: the two scanners
    attribute the same flaw to different resources — for `IAM-POLICY-ATTACHED-TO-USER`
    Checkov reports `aws_iam_user_policy_attachment.attach_danger` while Trivy reports
    `aws_iam_user.danger_user` — so a resource-sensitive join would score a correct label
    as a miss.

    One finding is consumed by at most one label (`eval/labels/README.md`), while one
    label may consume many findings — Trivy raises `DS031` once per credential-bearing
    `ENV` line and a single label covers all three.
    """
    mapped = 0
    hit: set[str] = set()
    for finding in scan.failed:
        found = normalise_rule_id(finding.rule_id)
        for label in labelset.labels:
            if found in {normalise_rule_id(i) for i in label.scanner_ids(scanner)}:
                mapped += 1
                hit.add(label.id)
                break
    return mapped, hit


def scanner_baseline(
    scans: Mapping[str, Mapping[str, ScanResult]],
    labelsets: Mapping[str, LabelSet],
) -> dict[str, Any]:
    """What Checkov and Trivy find with no LLM in the loop, and how much of it is planted.

    Produces, per scanner:

    * `total` — failed checks over the corpus. This is the *floor*. Both scanners run in
      about a second, need no API key and cost nothing; any claim on behalf of a pipeline
      that costs money and can hallucinate has to be a claim about something these two do
      not already do for free.
    * `mapped` / `total` — how many of those findings correspond to a planted flaw. The
      rest are incidental (omitted controls), which is most of the Terraform output.
    * `recall` — ``labels this scanner detects / planted labels``. The same denominator
      the LLM is scored against, so the two are directly comparable. Reported over all
      labels and over the `detectable_by_scanner` subset, because a scanner cannot be
      blamed for a flaw no rule in either tool covers.

    And, across both, the `union` recall — the only honest reference for "the LLM finds
    things static analysis cannot". Comparing against one scanner would credit the LLM for
    every flaw the other already catches for free.
    """
    out: dict[str, Any] = {"per_scanner": {}, "per_fixture": {}, "labels": {}}

    total_labels = sum(len(ls) for ls in labelsets.values())
    total_detectable = sum(len(ls.detectable) for ls in labelsets.values())
    out["labels"] = {
        "total": total_labels,
        "detectable_by_scanner": total_detectable,
        "not_detectable_by_scanner": total_labels - total_detectable,
        "per_fixture": {
            f: {"total": len(ls), "detectable": len(ls.detectable)}
            for f, ls in sorted(labelsets.items())
        },
    }

    union_hits: set[tuple[str, str]] = set()
    for scanner in SCANNER_NAMES:
        total = mapped = 0
        hits: set[tuple[str, str]] = set()
        per_fixture: dict[str, dict[str, Any]] = {}
        for fixture, by_scanner in sorted(scans.items()):
            scan = by_scanner.get(scanner)
            if scan is None:
                continue
            labelset = labelsets.get(fixture)
            if labelset is None:
                continue
            m, hit = map_scanner_findings(scan, labelset, scanner)
            total += scan.failed_count
            mapped += m
            hits |= {(fixture, lid) for lid in hit}
            per_fixture[fixture] = {
                "findings": scan.failed_count,
                "mapped": m,
                "incidental": scan.failed_count - m,
                "labels_hit": sorted(hit),
                "labels": len(labelset),
            }
        union_hits |= hits
        detectable_hits = sum(
            1
            for f, lid in hits
            if any(
                label.id == lid and label.detectable_by_scanner
                for label in labelsets[f].labels
            )
        )
        out["per_scanner"][scanner] = {
            "findings": total,
            "mapped_to_labels": mapped,
            "incidental": total - mapped,
            "labels_detected": len(hits),
            "recall_all_labels": safe_ratio(len(hits), total_labels),
            "recall_detectable_only": safe_ratio(detectable_hits, total_detectable),
            "per_fixture": per_fixture,
        }

    out["per_scanner"]["union"] = {
        # Deliberately not a finding count. Checkov's 70 and Trivy's 57 are counts of rule
        # violations under two different rulesets that overlap heavily on the same flaws;
        # adding them would inflate the corpus by an unknown factor. The union is only
        # meaningful at the *label* level, which is what the recall figures below use.
        "findings": None,
        "labels_detected": len(union_hits),
        "recall_all_labels": safe_ratio(len(union_hits), total_labels),
        "recall_detectable_only": safe_ratio(len(union_hits), total_detectable),
        "note": (
            "The union is the reference for 'the LLM finds what scanners cannot'. "
            "recall_detectable_only should be 1.0 by construction if the labels are "
            "correct — detectable_by_scanner is defined as 'some rule in one of these "
            "two tools fires on it', so a value below 1.0 means a label's ids are wrong."
        ),
    }
    out["per_fixture"] = {
        fixture: {
            scanner: (scans[fixture][scanner].failed_count if scanner in scans[fixture] else None)
            for scanner in SCANNER_NAMES
        }
        for fixture in sorted(scans)
    }
    return out


# --------------------------------------------------------------------------------------
# report assembly
# --------------------------------------------------------------------------------------


def _scans_from_json(block: Mapping[str, Any]) -> dict[str, dict[str, ScanResult]]:
    return {
        fixture: {scanner: scan_from_dict(sd) for scanner, sd in by_scanner.items()}
        for fixture, by_scanner in block.items()
    }


def compute_report(
    results: Mapping[str, Any] | None,
    baseline_doc: Mapping[str, Any] | None,
    labels_dir: Path | None = None,
    adjudications: Sequence[Adjudication] | None = None,
) -> dict[str, Any]:
    """Recompute every table from stored raw data. No network, no scanner, no model call.

    This is what makes `run_eval.py report` free: `results.json` holds the raw before/after
    scans and the raw LLM findings, `eval/cache/` holds the raw model responses, and every
    published number is a pure function of those two plus `eval/labels/`.
    """
    adjudications = list(adjudications if adjudications is not None else load_adjudications())
    report: dict[str, Any] = {
        "metadata": dict((results or {}).get("metadata") or {}),
        "baseline": {},
        "label_id_violations": [],
        "delta": {},
        "detection": {},
        "leakage": {},
        "validity": {},
        "drift": {},
        "per_fixture": {},
        "warnings": [],
    }

    # ---- baselines (scanner-only) ----
    baseline_blocks: dict[str, Any] = {}
    for source in (baseline_doc, results):
        block = (source or {}).get("baseline") or {}
        for variant, per_fixture in block.items():
            baseline_blocks.setdefault(variant, per_fixture)
    if baseline_doc and "metadata" in baseline_doc and not report["metadata"]:
        report["metadata"] = dict(baseline_doc["metadata"])

    all_fixtures = sorted({f for v in baseline_blocks.values() for f in v})
    labelsets = {f: load_labels(f, labels_dir) for f in all_fixtures} if all_fixtures else {}

    for variant, per_fixture in sorted(baseline_blocks.items()):
        scans = _scans_from_json(per_fixture)
        report["baseline"][variant] = scanner_baseline(scans, labelsets)
        report["label_id_violations"].extend(
            f"[{variant}] {v}" for v in verify_label_ids(labelsets, scans)
        )

    # ---- LLM runs ----
    runs = list((results or {}).get("runs") or [])
    if not runs:
        report["warnings"].append(
            "No LLM runs found. Only the scanner-only baseline is reported; every "
            "delta / detection / validity / drift table is absent rather than zero."
        )
        return report

    variants = sorted({str(r.get("variant")) for r in runs})
    for variant in variants:
        rows = [r for r in runs if r.get("variant") == variant]
        indices = sorted({int(r.get("run_index", 0)) for r in rows})

        # -- metric 1: delta, per repeat then described --
        per_scanner: dict[str, dict[str, Any]] = {}
        for scanner in SCANNER_NAMES:
            repeats: list[dict[str, Any]] = []
            for idx in indices:
                deltas = []
                for record in (r for r in rows if int(r.get("run_index", 0)) == idx):
                    before = (record.get("before") or {}).get(scanner)
                    after = (record.get("after") or {}).get(scanner)
                    if before is None or after is None:
                        continue
                    deltas.append(
                        finding_delta(
                            scan_from_dict(before),
                            scan_from_dict(after),
                            fixture=str(record.get("fixture")),
                            remediation_valid=bool(record.get("remediation_valid")),
                        )
                    )
                if deltas:
                    repeats.append(aggregate_deltas(deltas, scanner))
            if not repeats:
                continue
            per_scanner[scanner] = {
                "before": describe(r["before"] for r in repeats).as_dict(),
                "after": describe(r["after"] for r in repeats).as_dict(),
                "delta_pct": describe(r["delta_pct"] for r in repeats).as_dict(),
                "resolved": describe(r["resolved"] for r in repeats).as_dict(),
                "introduced": describe(r["introduced"] for r in repeats).as_dict(),
                "persisted": describe(r["persisted"] for r in repeats).as_dict(),
                "invalid_remediations": describe(
                    r["invalid_remediations"] for r in repeats
                ).as_dict(),
                "per_rule": repeats[0]["per_rule"],
                "repeats": repeats,
            }
        report["delta"][variant] = per_scanner

        # -- metric 2: detection, per repeat then described --
        repeats_detection: list[dict[str, Any]] = []
        per_fixture_detection: dict[str, Any] = {}
        for idx in indices:
            rowset: list[DetectionMetrics] = []
            for record in (r for r in rows if int(r.get("run_index", 0)) == idx):
                fixture = str(record.get("fixture"))
                labelset = labelsets.get(fixture) or load_labels(fixture, labels_dir)
                unmapped = _unmapped_scanner_findings(record, labelset)
                dm = detection_metrics(
                    list(record.get("llm_findings") or []),
                    labelset,
                    variant=variant,
                    unmapped_scanner_findings=unmapped,
                    adjudications=adjudications,
                )
                rowset.append(dm)
                if idx == indices[0]:
                    per_fixture_detection[fixture] = dm.as_dict()
            if rowset:
                repeats_detection.append(aggregate_detection(rowset))
        if repeats_detection:
            report["detection"][variant] = {
                "labels": describe(r["labels"] for r in repeats_detection).as_dict(),
                "tp_label": describe(r["tp_label"] for r in repeats_detection).as_dict(),
                "fn": describe(r["fn"] for r in repeats_detection).as_dict(),
                "recall": describe(r["recall"] for r in repeats_detection).as_dict(),
                "findings": describe(r["findings"] for r in repeats_detection).as_dict(),
                "tp_finding": describe(r["tp_finding"] for r in repeats_detection).as_dict(),
                "fp_strict": describe(r["fp_strict"] for r in repeats_detection).as_dict(),
                "plausible_unmatched": describe(
                    r["plausible_unmatched"] for r in repeats_detection
                ).as_dict(),
                "hallucinated": describe(r["hallucinated"] for r in repeats_detection).as_dict(),
                "precision_strict": describe(
                    r["precision_strict"] for r in repeats_detection
                ).as_dict(),
                "precision_adjudicated": describe(
                    r["precision_adjudicated"] for r in repeats_detection
                ).as_dict(),
                "precision_adjudicated_credited": describe(
                    r["precision_adjudicated_credited"] for r in repeats_detection
                ).as_dict(),
                "per_fixture": per_fixture_detection,
            }

        report["validity"][variant] = validity_rate(rows)
        report["drift"][variant] = drift_metrics(rows)

    # ---- leakage: the commented-vs-stripped gap ----
    commented = (report["detection"].get("commented") or {}).get("recall") or {}
    stripped = (report["detection"].get("stripped") or {}).get("recall") or {}
    if commented.get("mean") is not None and stripped.get("mean") is not None:
        report["leakage"] = {
            "recall_commented": commented,
            "recall_stripped": stripped,
            "label_leak": commented["mean"] - stripped["mean"],
            "note": (
                "label_leak = recall(commented) - recall(stripped). A large positive gap "
                "means the headline detection number was mostly comment comprehension. "
                "A gap near zero means the model read the code. The stripped variant is "
                "less contaminated, not provably clean: string literals such as heredoc "
                "bodies and resource names like `insecure_sg` still leak."
            ),
        }
    else:
        report["warnings"].append(
            "Label leakage not measured: it needs detection results for BOTH the "
            "commented and stripped variants (run with --variant both)."
        )

    return report


def _unmapped_scanner_findings(
    record: Mapping[str, Any], labelset: LabelSet
) -> list[Finding]:
    """Scanner findings on this fixture that no label claims — the incidental population.

    Used only to decide whether an unmatched LLM finding is plausible. An LLM finding that
    lines up with one of these is a true observation about the file that this ground truth
    does not adjudicate: neither credit nor penalty.
    """
    out: list[Finding] = []
    for scanner in SCANNER_NAMES:
        raw = (record.get("before") or {}).get(scanner)
        if not raw:
            continue
        scan = scan_from_dict(raw)
        claimed = {
            rid for label in labelset.labels for rid in label.scanner_ids(scanner)
        }
        for f in scan.failed:
            if f.rule_id in claimed:
                continue
            # Path-stripped, so `dockerfile_resource_matches` sees `EXPOSE` rather than an
            # absolute filename it cannot recognise as an instruction.
            out.append(
                Finding(
                    rule_id=f.rule_id,
                    severity=f.severity,
                    resource=scanner_resource(f.resource, scan.target),
                    message=f.message,
                    scanner=f.scanner,
                    file=f.file,
                    line=f.line,
                    guideline=f.guideline,
                )
            )
    return out


# --------------------------------------------------------------------------------------
# `python -m eval.metrics` — recompute the tables, touch nothing else
# --------------------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - thin wrapper
    import argparse
    import json

    # Imported here, not at module scope: `eval.render` imports `fmt_stat` from this
    # module, so a top-level import back into it would be a cycle. Only this entry point
    # needs the renderer; every measurement function below is independent of it.
    from .render import render_results_md

    parser = argparse.ArgumentParser(
        prog="python -m eval.metrics",
        description="Recompute eval/results/RESULTS.md from stored raw results. "
        "No network, no scanner runs, no model calls.",
    )
    parser.add_argument("--results", type=Path, default=RESULTS_JSON)
    parser.add_argument("--baseline", type=Path, default=BASELINE_JSON)
    parser.add_argument("--out", type=Path, default=RESULTS_MD)
    args = parser.parse_args(argv)

    results = json.loads(args.results.read_text()) if args.results.is_file() else None
    baseline = json.loads(args.baseline.read_text()) if args.baseline.is_file() else None
    if results is None and baseline is None:
        print(f"nothing to report: neither {args.results} nor {args.baseline} exists")
        return 1

    report = compute_report(results, baseline)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_results_md(report), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
