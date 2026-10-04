"""The bounded refinement loop — the part that makes the word "agentic" true.

The original pipeline was three sequential model calls: detect, fix, print. It displayed
the scanner's verdict on the "fixed" file and then discarded it. Nothing in the system
ever read its own output and decided what to do next, so the loop that would have caught
a bad remediation did not exist. What earns the term *agentic* is not the number of model
calls; it is that the system observes the consequences of its own action through an
oracle it does not control (a static scanner), judges the result, and conditions its next
action on that judgement — under explicit termination conditions rather than a fixed
script length.

Four decisions here are load-bearing, and each exists because the obvious alternative
produces a number that looks better and means less:

1. **Best-so-far, never last-attempt.** A later iteration can be strictly worse than an
   earlier one, and the feedback mechanism makes that *more* likely: handed a list of
   surviving findings, a model will sometimes rewrite regions it had already fixed.
   Returning the final state would report a regression the tool caused and then hid. The
   incumbent is replaced only on *strict* improvement, so a tie keeps the earlier and
   smaller-diff candidate.

2. **The gates run before the scanner, not after.** A candidate that fails the validity
   gate is never written and never scanned, because an unparseable file and a perfectly
   secure file produce the same finding count. An invalid candidate is a *failed*
   iteration whose parser error becomes the next prompt's repair guidance.

3. **`introduced` is reported separately and never netted against `resolved`.** A run that
   fixes ten findings and creates four is not a run that fixed six; it is a run that needs
   a human to look at four new problems. `net_reduction` exists for headline reporting and
   is deliberately not the same number as `len(resolved)`.

4. **Finding keys are normalised before differencing.** Measured on Checkov 3.2.489: the
   `resource` field for Dockerfile findings embeds the path the scanner was pointed at, so
   the same content yields `samples/vulnerable.Dockerfile.ADD` at the input path and
   `Dockerfile.ADD` in the work directory. Differencing raw keys across those two paths
   reports every baseline finding as resolved and every surviving finding as newly
   introduced — a 100% false resolution rate. `_finding_key` strips the path prefix.
   Terraform addresses (`aws_s3_bucket.example`) are path-independent, which is exactly
   why this hazard is invisible if only Terraform is tested.

Two deviations from `docs/LLD.md` §7, both deliberate and both narrowing:

* Candidates are written into a private temporary directory for scanning, and `output_dir`
  receives **only the returned best candidate**, once, at the end. The LLD has each
  iteration overwrite `workdir/<output_name>`, which leaves the *last* attempt on disk
  while `LoopResult.best` names an earlier one — the on-disk file would then contradict
  the returned result. The filename still comes from `IaCType.output_name` and nowhere
  else (§3.3): a remediated Dockerfile written as `fixed.tf` gets Terraform rules applied
  to it and reports a clean pass.
* An `LLMError` mid-run is recorded as a rejected `IterationRecord` rather than vanishing,
  so the audit trail shows what the run cost and where it stopped.

`ScannerError` from the **baseline** scan propagates: with no measurement of what was
wrong to begin with there is nothing to improve against, and a run that cannot establish
its own denominator must abort rather than report zero. A `ScannerError` on a *candidate*
rescan is evidence about that candidate, so it is caught, recorded, and the loop continues.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .llm import LLMClient, ModelConfig, distill_failures
from .scanners import Scanner, get_scanner
from .types import (
    Finding,
    IaCType,
    LLMError,
    ScannerError,
    ScanResult,
    detect_iac_type,
)
from .validity import (
    DriftReport,
    ValidityError,
    ValidityResult,
    check_validity,
    compute_drift,
    extract_resources,
)

__all__ = [
    "StopReason",
    "IterationRecord",
    "LoopResult",
    "run_loop",
    "NOT_SCANNED",
]

# `IterationRecord.failed_count` when the candidate was never scanned. Deliberately not 0:
# a rejected candidate that reported "0 findings" would be indistinguishable from a
# converged one in any report that sorts or sums this field. It is negative so that a
# naive `min()` over it is obviously wrong rather than subtly wrong, and every internal
# comparison guards on `scan is not None` first.
NOT_SCANNED = -1

# Pseudo rule-ids for feedback that did not come from a scanner. They travel through
# `LLMClient.generate_fix(scanner_failures=...)`, which renders each entry as
# "- [rule_id] on `resource`: name".
_FEEDBACK_PARSE_ERROR = "OUTPUT_NOT_PARSEABLE"
_FEEDBACK_DRIFT = "RESOURCE_DELETED"


class StopReason(str, Enum):
    """Why the loop stopped. Every exit is one of these — there is no implicit fall-through.

    `str` mixin so a reason serialises to a readable value in the evaluation harness's
    JSON without a custom encoder.
    """

    CONVERGED = "converged"      # scanner reports zero failures on an accepted candidate
    MAX_ITERS = "max_iters"      # ran out of permitted attempts
    NO_PROGRESS = "no_progress"  # stopped beating the incumbent; further spend is waste
    TOKEN_BUDGET = "token_budget"  # cost ceiling reached


@dataclass
class IterationRecord:
    """One attempt, kept whether it succeeded or not.

    A rejected iteration is a *result*, not noise: "the model deleted the RDS instance
    twice" is the most interesting thing a run can tell you, and it is invisible if only
    accepted candidates are recorded.
    """

    index: int
    code: str
    validity: ValidityResult
    scan: ScanResult | None = None
    drift: DriftReport | None = None
    # Normalised (rule_id, resource) pairs — see `_finding_key`. Empty when unscanned.
    keys: frozenset[tuple[str, str]] = frozenset()
    accepted: bool = False
    rejected_because: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    # Set after the run: which record was returned, and which one the loop stopped on.
    is_best: bool = False
    stop_reason: StopReason | None = None

    @property
    def was_scanned(self) -> bool:
        return self.scan is not None

    @property
    def failed_count(self) -> int:
        """Scanner failures, or `NOT_SCANNED` when the gates rejected this candidate."""
        return self.scan.failed_count if self.scan is not None else NOT_SCANNED

    def describe(self) -> str:
        if self.scan is not None:
            state = f"{self.scan.failed_count} failed"
        else:
            state = f"not scanned ({self.rejected_because or 'no scan'})"
        verdict = "accepted" if self.accepted else "rejected"
        return f"iter {self.index}: {verdict}, {state}, {self.total_tokens} tokens"


@dataclass
class LoopResult:
    """Everything a reader needs to decide whether to believe the headline number.

    `best` is a reference to an element of `iterations`, or to `baseline_record` when no
    candidate was ever accepted — identity comparison against `iterations` is meaningful
    and is the intended way to ask "did anything actually get accepted?".
    """

    target: Path
    iac_type: IaCType
    scanner: str
    baseline: ScanResult
    baseline_record: IterationRecord
    iterations: list[IterationRecord]
    best: IterationRecord
    stop_reason: StopReason
    total_tokens: int
    detect_tokens: int = 0
    issues: list[dict] = field(default_factory=list)
    # Non-empty when the run ended on an error rather than on a planned stop condition.
    # The stop reason is still one of the four; this says what actually happened.
    aborted_because: str = ""
    # Recorded when the drift gate could not run (the *original* file does not parse), so
    # a caller never mistakes "no drift detected" for "drift was checked".
    drift_gate_note: str = ""
    output_path: Path | None = None

    # -- headline numbers --------------------------------------------------------------

    @property
    def baseline_failed(self) -> int:
        return self.baseline.failed_count

    @property
    def final_failed(self) -> int:
        """Failures in the returned candidate. Never worse than `baseline_failed`."""
        return self.best.scan.failed_count if self.best.scan is not None else NOT_SCANNED

    @property
    def best_code(self) -> str:
        """The code actually being returned — the original source if nothing was accepted."""
        return self.best.code

    @property
    def drift(self) -> DriftReport | None:
        """Drift of the returned candidate. None for Dockerfiles (no addressable units)."""
        return self.best.drift

    @property
    def validity(self) -> ValidityResult:
        return self.best.validity

    @property
    def resolved(self) -> set[tuple[str, str]]:
        """Findings present at baseline and absent from the returned candidate."""
        return set(self.baseline_record.keys - self.best.keys)

    @property
    def introduced(self) -> set[tuple[str, str]]:
        """Findings the remediation *created*.

        Reported on its own and never subtracted from `resolved`: a fix that trades four
        old findings for four new ones is not a no-op, it is four new things to review.
        """
        return set(self.best.keys - self.baseline_record.keys)

    @property
    def net_reduction(self) -> int:
        """Headline delta, from counts rather than keys.

        Counts and key-set sizes can legitimately disagree — two findings from the same
        rule on the same resource share a key (measured: Trivy reports DS031 three times
        on `vulnerable.Dockerfile`, collapsing to one key). Counts are the honest number
        for "how much dropped"; keys are for identifying *which* findings changed.
        """
        if self.best.scan is None:
            return 0
        return self.baseline.failed_count - self.best.scan.failed_count

    @property
    def converged(self) -> bool:
        return self.stop_reason is StopReason.CONVERGED

    @property
    def accepted_any(self) -> bool:
        return self.best is not self.baseline_record

    def summary(self) -> str:
        drift = self.drift.summary() if self.drift is not None else "drift n/a"
        return (
            f"{self.target.name} [{self.scanner}] "
            f"{self.baseline_failed} -> {self.final_failed} failed "
            f"({len(self.resolved)} resolved, {len(self.introduced)} introduced) "
            f"in {len(self.iterations)} iteration(s); {self.stop_reason.value}; "
            f"{self.total_tokens} tokens; {drift}"
        )


# --------------------------------------------------------------------------------------
# finding identity
# --------------------------------------------------------------------------------------


def _dockerfile_resource(resource: str, source_file: str) -> str:
    """Strip the scanner's path prefix off a Dockerfile finding's resource.

    Checkov emits `<path it was given>.<INSTRUCTION>` — `samples/vulnerable.Dockerfile.ADD`
    at the input path, `Dockerfile.ADD` for byte-identical content in the work directory.
    Reducing both to `ADD` is what makes before/after set arithmetic mean anything for
    Dockerfiles. Trivy emits an empty resource for Dockerfiles, which passes through
    unchanged and leaves `rule_id` as the whole of the identity.
    """
    res = resource.strip()
    if not res:
        return ""
    head, sep, tail = res.rpartition(".")
    if not sep:
        return res
    # Only strip when the prefix really is the file we scanned; a resource that happens to
    # contain a dot for another reason must survive intact.
    if "dockerfile" in head.lower() or (source_file and head.endswith(Path(source_file).name)):
        return tail
    return res


def finding_key(finding: Finding, iac_type: IaCType) -> tuple[str, str]:
    """Public spelling of `_finding_key`, for callers that need to join against the key sets.

    `LoopResult.resolved` and `.introduced` are sets of these keys and nothing else, so a caller
    that wants to say *which* finding was resolved — rather than how many — has to be able to
    compute the same key for a `Finding` it holds. Recomputing the normalisation outside this
    module is exactly the duplication that produced the bug `_dockerfile_resource` documents, so
    it is exported instead.
    """
    return _finding_key(finding, iac_type)


def _finding_key(finding: Finding, iac_type: IaCType) -> tuple[str, str]:
    """Path-independent identity for a finding, so keys join across scan locations."""
    if iac_type is IaCType.DOCKERFILE:
        return (finding.rule_id, _dockerfile_resource(finding.resource, finding.file))
    return finding.key()


def _keys_of(scan: ScanResult, iac_type: IaCType) -> frozenset[tuple[str, str]]:
    return frozenset(_finding_key(f, iac_type) for f in scan.failed)


# --------------------------------------------------------------------------------------
# feedback construction
# --------------------------------------------------------------------------------------


def _feedback_from_invalid(validity: ValidityResult) -> list[dict]:
    """Turn a parser error into repair guidance for the next attempt.

    `generate_fix` takes `scanner_failures`, whose renderer wants rule_id/name/resource,
    so a non-scanner failure is expressed in the same shape rather than in a second
    channel that `llm.py` does not have.
    """
    return [
        {
            "rule_id": _FEEDBACK_PARSE_ERROR,
            "name": (
                f"Your previous reply was rejected before it could be scanned "
                f"({validity.reason}): {validity.detail}. Return the complete file as raw "
                f"code with no fences and no commentary."
            ),
            "resource": "",
        }
    ]


def _feedback_from_drift(lost: list[str]) -> list[dict]:
    """Name the deleted resources explicitly; a generic "don't delete things" does not land."""
    return [
        {
            "rule_id": _FEEDBACK_DRIFT,
            "name": (
                "Your previous reply removed or renamed this resource instead of securing "
                "it. Restore it under exactly this address and fix its configuration."
            ),
            "resource": addr,
        }
        for addr in lost
    ]


def _feedback_from_control_changes(changes: list[str]) -> list[dict]:
    """Tell the model which Terraform identity control it must restore."""
    return [
        {
            "rule_id": _FEEDBACK_DRIFT,
            "name": (
                "The rewrite changed a Terraform instance control or module source. "
                "Restore the original count, for_each, or source value and secure the "
                "resource without changing its deployment identity."
            ),
            "resource": change,
        }
        for change in changes
    ]


# --------------------------------------------------------------------------------------
# stop conditions
# --------------------------------------------------------------------------------------


def _evaluate_stop(
    *,
    best: IterationRecord,
    iterations_run: int,
    max_iters: int,
    stall_count: int,
    patience: int,
    tokens_spent: int,
    token_budget: int | None,
) -> StopReason | None:
    """First matching condition wins, and the order is deliberate.

    `CONVERGED` outranks everything so that reaching zero findings on the last permitted
    iteration reports convergence rather than exhaustion. `MAX_ITERS` outranks the two
    "stop early" reasons because running out of attempts is a fact about the run, while a
    stall or a budget hit is a judgement about whether to keep going — and there is
    nothing left to keep going with.
    """
    if best.accepted and best.scan is not None and best.scan.failed_count == 0:
        return StopReason.CONVERGED
    if iterations_run >= max_iters:
        return StopReason.MAX_ITERS
    if stall_count > patience:
        return StopReason.NO_PROGRESS
    if token_budget is not None and tokens_spent >= token_budget:
        return StopReason.TOKEN_BUDGET
    return None


# --------------------------------------------------------------------------------------
# the loop
# --------------------------------------------------------------------------------------


def run_loop(
    path: str | Path,
    scanner: Scanner | str = "checkov",
    client: LLMClient | None = None,
    cfg: ModelConfig | None = None,
    *,
    max_iters: int = 3,
    token_budget: int | None = 60_000,
    output_dir: str | Path | None = None,
    patience: int = 1,
    workdir: str | Path | None = None,
    on_step: Callable[[str, IterationRecord | None], None] | None = None,
) -> LoopResult:
    """Scan, fix, verify, and refine until one of four explicit stop conditions fires.

    `client` must be supplied. It carries the injection seam (`complete_fn`), so passing
    it explicitly is what makes "this run cannot reach the network" a checkable property
    rather than a hope.

    `patience` is the number of consecutive non-improving iterations tolerated before
    `NO_PROGRESS`; the default of 1 means two in a row stop the loop. One bad iteration is
    common — a malformed reply, one over-eager deletion — and the model often recovers when
    handed the parser error or the named deletion. Two in a row is a pattern, not noise.

    `workdir` is an alias for `output_dir` (the name used in docs/LLD.md §7.1).

    `on_step` is called as the run progresses, with a stage name and the record it concerns:
    `("baseline", baseline_record)` once the file has been scanned, `("detected", None)` once
    the model has read it, and `("iteration", record)` as each candidate settles. It exists
    because a remediation run takes tens of seconds of model calls and a caller that cannot say
    what is happening has to show a frozen box. Stage names are identifiers, not sentences: the
    caller chooses the wording, exactly as it does for everything else in `LoopResult`.

    The input file is never modified: this function is read-only with respect to `path`.
    """
    if client is None:
        raise ValueError(
            "run_loop requires an LLMClient. Pass one with complete_fn injected to run "
            "without an API key."
        )
    if max_iters < 1:
        raise ValueError(f"max_iters must be >= 1, got {max_iters}")
    if patience < 0:
        raise ValueError(f"patience must be >= 0, got {patience}")

    target = Path(path)
    out_dir = Path(output_dir) if output_dir is not None else (
        Path(workdir) if workdir is not None else None
    )
    scan_with: Scanner = get_scanner(scanner) if isinstance(scanner, str) else scanner

    def _step(stage: str, record: IterationRecord | None = None) -> None:
        """Report progress, without letting the reporting break the run.

        A caller's progress line is not worth losing a paid run over: by the time the third
        iteration is reported, real money has been spent, and a typo in someone's status
        handler must not be able to throw that away. The loop's contract is the result.
        """
        if on_step is None:
            return
        try:
            on_step(stage, record)
        except Exception:  # a reporting callback must never abort the work it reports on
            pass

    iac_type = detect_iac_type(target)          # once; threaded through every scanner call
    source = target.read_text(encoding="utf-8", errors="replace")

    # Baseline. A ScannerError here is fatal by design (see module docstring).
    baseline = scan_with.scan(target, iac_type=iac_type)
    baseline_record = IterationRecord(
        index=0,
        code=source,
        validity=check_validity(source, iac_type),
        scan=baseline,
        drift=None,  # the original cannot drift from itself
        keys=_keys_of(baseline, iac_type),
        accepted=True,  # "change nothing" is always an admissible answer
    )
    _step("baseline", baseline_record)

    def _finish(
        *,
        best: IterationRecord,
        iterations: list[IterationRecord],
        stop_reason: StopReason,
        total_tokens: int,
        detect_tokens: int,
        issues: list[dict],
        aborted: str,
        drift_note: str,
    ) -> LoopResult:
        best.is_best = True
        result = LoopResult(
            target=target,
            iac_type=iac_type,
            scanner=scan_with.name,
            baseline=baseline,
            baseline_record=baseline_record,
            iterations=iterations,
            best=best,
            stop_reason=stop_reason,
            total_tokens=total_tokens,
            detect_tokens=detect_tokens,
            issues=issues,
            aborted_because=aborted,
            drift_gate_note=drift_note,
        )
        if out_dir is not None:
            # Only the returned best candidate is persisted, and only under the name the
            # scanners key their rules off. Writing every attempt here would leave the
            # last one on disk while `best` named an earlier one.
            out_dir.mkdir(parents=True, exist_ok=True)
            dest = out_dir / iac_type.output_name
            dest.write_text(best.code, encoding="utf-8")
            result.output_path = dest
        return result

    # A clean file is not sent to the model at all. That is a correctness property before
    # it is a saving: there is no way to damage a good file if we never rewrite it.
    if baseline.failed_count == 0:
        baseline_record.stop_reason = StopReason.CONVERGED
        return _finish(
            best=baseline_record,
            iterations=[],
            stop_reason=StopReason.CONVERGED,
            total_tokens=0,
            detect_tokens=0,
            issues=[],
            aborted="",
            drift_note="",
        )

    # Drift is always measured against the *original* structure. If the original does not
    # parse we say so rather than reporting "no drift", which would read as a verified
    # result instead of an unmeasured one.
    drift_note = ""
    try:
        extract_resources(source, iac_type)
    except ValidityError as exc:
        drift_note = f"drift gate disabled: original does not parse ({exc})"

    # Snapshot as ints, never as a reference: `LLMClient.usage` is a single TokenUsage
    # instance mutated in place by `add()`, so holding the object and subtracting from it
    # later measures nothing. Deltas also mean a caller may reuse one client across runs.
    start_total = client.usage.total_tokens

    def _spent() -> int:
        return client.usage.total_tokens - start_total

    iterations: list[IterationRecord] = []
    best = baseline_record
    best_count = baseline.failed_count
    stall_count = 0
    aborted = ""
    stop_reason: StopReason | None = None

    # Detection is a property of the original file and does not change across iterations;
    # re-running it per iteration would spend tokens re-deriving a constant.
    issues: list[dict] = []
    detect_tokens = 0
    try:
        issues = client.detect_vulnerabilities(source, iac_type, cfg=cfg)
    except LLMError as exc:
        aborted = f"detection failed: {exc}"
    detect_tokens = _spent()
    if not aborted:
        _step("detected")

    if aborted:
        # No candidate was ever produced, so the honest reason is "made no progress".
        # `aborted_because` carries what actually happened.
        return _finish(
            best=best,
            iterations=[],
            stop_reason=StopReason.NO_PROGRESS,
            total_tokens=_spent(),
            detect_tokens=detect_tokens,
            issues=issues,
            aborted=aborted,
            drift_note=drift_note,
        )

    # Iteration 1 is seeded with both channels of evidence: the model's own reading of the
    # file, and the checks a scanner already proved fail on it. The second is the one the
    # old pipeline threw away.
    feedback: list[dict] = distill_failures(baseline)

    with tempfile.TemporaryDirectory(prefix="iac-loop-") as tmp:
        candidate_path = Path(tmp) / iac_type.output_name

        for index in range(1, max_iters + 1):
            # Budget is checked before spending, so it bounds cost rather than describing it.
            if token_budget is not None and _spent() >= token_budget:
                stop_reason = StopReason.TOKEN_BUDGET
                break

            before_prompt = client.usage.prompt_tokens
            before_completion = client.usage.completion_tokens
            before_total = client.usage.total_tokens

            try:
                candidate = client.generate_fix(
                    source, issues, iac_type, cfg=cfg, scanner_failures=feedback
                )
            except LLMError as exc:
                # Recorded rather than swallowed: a failed call still cost money and still
                # occupies an iteration slot.
                record = IterationRecord(
                    index=index,
                    code="",
                    validity=ValidityResult(False, "llm_error", str(exc)),
                    rejected_because=f"llm_error: {exc}",
                    prompt_tokens=client.usage.prompt_tokens - before_prompt,
                    completion_tokens=client.usage.completion_tokens - before_completion,
                    total_tokens=client.usage.total_tokens - before_total,
                )
                iterations.append(record)
                _step("iteration", record)
                aborted = f"model call failed on iteration {index}: {exc}"
                stall_count += 1
                stop_reason = (
                    _evaluate_stop(
                        best=best,
                        iterations_run=len(iterations),
                        max_iters=max_iters,
                        stall_count=stall_count,
                        patience=patience,
                        tokens_spent=_spent(),
                        token_budget=token_budget,
                    )
                    or StopReason.NO_PROGRESS
                )
                break

            record = IterationRecord(
                index=index,
                code=candidate,
                validity=check_validity(candidate, iac_type),
                prompt_tokens=client.usage.prompt_tokens - before_prompt,
                completion_tokens=client.usage.completion_tokens - before_completion,
                total_tokens=client.usage.total_tokens - before_total,
            )
            iterations.append(record)

            # -- gate 1: does it parse? ------------------------------------------------
            if not record.validity.ok:
                record.rejected_because = (
                    f"invalid: {record.validity.reason}: {record.validity.detail}"
                )
                feedback = _feedback_from_invalid(record.validity)

            # -- gate 2: is it still the same infrastructure? --------------------------
            elif not drift_note:
                try:
                    record.drift = compute_drift(source, candidate, iac_type)
                except ValidityError as exc:
                    # check_validity passed but the resource walk did not: we cannot verify
                    # the candidate kept its resources, so we do not accept it.
                    record.rejected_because = f"drift_unmeasurable: {exc}"
                    feedback = _feedback_from_invalid(
                        ValidityResult(False, "hcl_parse_error", str(exc))
                    )
                else:
                    if iac_type is IaCType.DOCKERFILE and record.drift.drifted:
                        record.rejected_because = "drift: " + record.drift.summary()
                        feedback = [{
                            "rule_id": "DOCKERFILE_STRUCTURE_CHANGED",
                            "name": (
                                "The rewrite removed application structure or changed base "
                                "image family. Preserve the original stages, each stage's copy "
                                "sources, and startup presence while fixing security settings."
                            ),
                            "resource": record.drift.summary(),
                        }]
                    elif iac_type is IaCType.TERRAFORM:
                        # A scanner finding is not the measure of a resource's value.
                        # Deleting an unflagged database or job is still destructive.
                        lost = sorted(
                            {r.address for r in record.drift.deleted}
                            | {before.address for before, _ in record.drift.renamed}
                        )
                        changes = record.drift.terraform_changes
                        if lost or changes:
                            record.rejected_because = "drift: " + record.drift.summary()
                            feedback = _feedback_from_drift(lost)
                            feedback.extend(_feedback_from_control_changes(changes))

            if record.rejected_because:
                # Never scanned and never written. A file we know is malformed, or one we
                # know deleted the resource that carried the finding, would scan *better*
                # than the truth.
                stall_count += 1
            else:
                # -- write, then rescan ------------------------------------------------
                candidate_path.write_text(candidate, encoding="utf-8")
                try:
                    scan = scan_with.scan(candidate_path, iac_type=iac_type)
                except ScannerError as exc:
                    # Evidence about this candidate, not about the run: keep going.
                    record.rejected_because = f"scan_failed: {exc}"
                    stall_count += 1
                else:
                    record.scan = scan
                    record.keys = _keys_of(scan, iac_type)
                    record.accepted = True
                    if scan.failed_count < best_count:
                        best, best_count = record, scan.failed_count
                        stall_count = 0
                    else:
                        # A tie is not evidence of improvement, and preferring the earlier
                        # of two equal results keeps the returned diff smaller.
                        stall_count += 1
                    # Next round targets checks a scanner just proved still fail, not the
                    # model's opinion of what it already fixed.
                    feedback = distill_failures(scan)

            # Reported here, once, after every gate has had its say — so a caller never sees a
            # candidate described before the loop has finished deciding about it.
            _step("iteration", record)

            stop_reason = _evaluate_stop(
                best=best,
                iterations_run=len(iterations),
                max_iters=max_iters,
                stall_count=stall_count,
                patience=patience,
                tokens_spent=_spent(),
                token_budget=token_budget,
            )
            if stop_reason is not None:
                break

    # The loop body always sets a reason before breaking, and the `for` cannot fall through
    # without `_evaluate_stop` seeing `iterations_run >= max_iters`. Belt and braces.
    if stop_reason is None:
        stop_reason = StopReason.MAX_ITERS

    if iterations:
        iterations[-1].stop_reason = stop_reason
    else:
        baseline_record.stop_reason = stop_reason

    total = client.usage.total_tokens - start_total
    # Sanity: usage counters are cumulative and monotone, so a negative delta means the
    # caller reset the client mid-run. Report zero rather than a nonsense negative budget.
    if total < 0:  # pragma: no cover - only reachable via reset_usage() during a run
        total = 0

    return _finish(
        best=best,
        iterations=iterations,
        stop_reason=stop_reason,
        total_tokens=total,
        detect_tokens=detect_tokens,
        issues=issues,
        aborted=aborted,
        drift_note=drift_note,
    )
