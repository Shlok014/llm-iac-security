"""Tests for the refinement loop: stop conditions, errors, and the two gates.

The loop is what makes the project's central claim true — it observes the consequences of its
own output through an oracle it does not control, and decides whether that output was an
improvement. Every test here drives it with a scripted fake model, so the suite needs no API
key and costs nothing.

The bias in these tests is toward proving the loop *refuses* things. A loop that accepts
everything still produces falling finding counts; the value is in what it declines.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from iac_agent.llm import LLMClient, LLMResponse, ModelConfig, TokenUsage
from iac_agent.loop import StopReason, run_loop

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

DETECT = json.dumps(
    {
        "findings": [
            {
                "issue": "Resource is publicly exposed",
                "severity": "high",
                "resource": "",
                "recommendation": "Restrict access.",
            }
        ]
    }
)

# A Dockerfile that genuinely satisfies Checkov's dockerfile policies — pinned digest,
# non-root user, healthcheck. Used for the CONVERGED case because reaching zero findings is
# actually attainable for Dockerfiles, unlike Terraform where Checkov always wants more.
SECURE_DOCKERFILE = """FROM python:3.12-slim@sha256:\
aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff00000000111111112
RUN adduser --disabled-password --gecos "" appuser
WORKDIR /app
COPY --chown=appuser:appuser . /app
USER appuser
HEALTHCHECK --interval=30s CMD python -c "print('ok')"
CMD ["python", "-m", "app"]
"""


def scripted(*responses: object):
    """A fake complete_fn returning each response in turn, repeating the last one."""
    state = {"i": 0}

    def _fn(messages, **_):
        i = min(state["i"], len(responses) - 1)
        state["i"] += 1
        return responses[i]

    return _fn


def run(fixture: str, *responses: object, **kwargs):
    defaults = dict(scanner="checkov", cfg=ModelConfig(), max_iters=2, token_budget=None)
    defaults.update(kwargs)
    with tempfile.TemporaryDirectory() as td:
        return run_loop(
            SAMPLES / fixture,
            client=LLMClient(complete_fn=scripted(*responses)),
            output_dir=td,
            **defaults,
        )


def _best_count(result) -> int | None:
    return result.best.scan.failed_count if (result.best and result.best.scan) else None


# --------------------------------------------------------------------------------------
# stop conditions and provider errors
# --------------------------------------------------------------------------------------


def test_converged_when_findings_reach_zero() -> None:
    result = run("vulnerable.Dockerfile", DETECT, SECURE_DOCKERFILE)
    assert result.baseline.failed_count == 5
    assert _best_count(result) == 0
    assert result.stop_reason is StopReason.CONVERGED


def test_no_progress_when_the_model_returns_the_input_unchanged() -> None:
    original = (SAMPLES / "s3_public.tf").read_text()
    result = run("s3_public.tf", DETECT, original, max_iters=3)
    assert result.stop_reason is StopReason.NO_PROGRESS
    assert _best_count(result) == result.baseline.failed_count


def test_detection_provider_error_is_not_reported_as_no_progress() -> None:
    from iac_agent.types import LLMError

    def fail_provider(_messages, **_kwargs):
        raise LLMError("provider returned HTTP 500")

    with tempfile.TemporaryDirectory() as td:
        result = run_loop(
            SAMPLES / "s3_public.tf", scanner="checkov",
            client=LLMClient(complete_fn=fail_provider),
            cfg=ModelConfig(), max_iters=1, output_dir=td,
        )
    assert result.stop_reason is StopReason.ERROR
    assert result.aborted_because.startswith("detection failed:")
    assert result.iterations == []


def test_rewrite_provider_error_is_not_reported_as_iteration_cap() -> None:
    from iac_agent.types import LLMError

    calls = 0

    def fail_rewrite(_messages, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return DETECT
        raise LLMError("provider returned HTTP 500")

    with tempfile.TemporaryDirectory() as td:
        result = run_loop(
            SAMPLES / "s3_public.tf", scanner="checkov",
            client=LLMClient(complete_fn=fail_rewrite),
            cfg=ModelConfig(), max_iters=1, output_dir=td,
        )
    assert result.stop_reason is StopReason.ERROR
    assert result.aborted_because.startswith("model call failed")
    assert len(result.iterations) == 1


def test_max_iters_caps_the_run() -> None:
    """A candidate that improves but never converges must stop at the cap, not run on."""
    partly_secure = 'resource "aws_s3_bucket" "example" {\n  bucket = "mybucket"\n}\n'
    result = run("s3_public.tf", DETECT, partly_secure, max_iters=1)
    assert result.stop_reason is StopReason.MAX_ITERS
    assert len(result.iterations) <= 1


def test_token_budget_stops_the_run() -> None:
    """Budget is a real bound, not a suggestion.

    A fake returning a bare `str` reports zero usage and so could never trip the budget;
    returning an LLMResponse with usage is what makes this reachable.
    """
    expensive = LLMResponse(
        text=SECURE_DOCKERFILE,
        usage=TokenUsage(prompt_tokens=5_000, completion_tokens=5_000, total_tokens=10_000, calls=1),
    )
    detect = LLMResponse(
        text=DETECT,
        usage=TokenUsage(prompt_tokens=5_000, completion_tokens=5_000, total_tokens=10_000, calls=1),
    )
    result = run("vulnerable.Dockerfile", detect, expensive, max_iters=5, token_budget=1)
    assert result.stop_reason is StopReason.TOKEN_BUDGET


# --------------------------------------------------------------------------------------
# the gates — what the loop refuses
# --------------------------------------------------------------------------------------


def test_empty_remediation_never_converges() -> None:
    """The classic fake zero. An empty file scans clean under every scanner."""
    result = run("s3_public.tf", DETECT, "")
    assert result.stop_reason is not StopReason.CONVERGED
    assert _best_count(result) == result.baseline.failed_count


def test_unparseable_remediation_is_never_scanned() -> None:
    result = run("s3_public.tf", DETECT, 'resource "aws_s3_bucket" "x" { bucket = ')
    assert all(not r.accepted for r in result.iterations)
    assert all(r.scan is None for r in result.iterations if not r.accepted)
    assert _best_count(result) == result.baseline.failed_count


def test_deleting_the_flawed_resource_is_rejected() -> None:
    """The headline behaviour, on the exact shape observed in a live evaluation run.

    Deleting `aws_db_instance.bad_rds` genuinely *would* lower the finding count — the
    resource is gone, so its findings are gone. The gate rejects it before it is scored,
    and the original file is returned unchanged.
    """
    original = (SAMPLES / "vulnerable_main.tf").read_text()
    lines, out, skipping, depth = original.splitlines(keepends=True), [], False, 0
    for ln in lines:
        if ln.startswith('resource "aws_db_instance" "bad_rds"'):
            skipping, depth = True, ln.count("{") - ln.count("}")
            continue
        if skipping:
            depth += ln.count("{") - ln.count("}")
            skipping = depth > 0
            continue
        out.append(ln)
    deleted = "".join(out)
    assert "bad_rds" not in deleted

    result = run("vulnerable_main.tf", DETECT, deleted, max_iters=1)
    rejected = [r for r in result.iterations if not r.accepted]
    assert rejected, "the deletion should have been rejected"
    assert any("drift" in r.rejected_because for r in rejected)
    assert _best_count(result) == result.baseline.failed_count


# --------------------------------------------------------------------------------------
# invariants
# --------------------------------------------------------------------------------------


def test_returns_best_so_far_not_last_attempt() -> None:
    """A later iteration can be worse; returning the last one would silently regress."""
    good = SECURE_DOCKERFILE
    worse = SECURE_DOCKERFILE.replace("USER appuser\n", "")
    result = run("vulnerable.Dockerfile", DETECT, good, worse, max_iters=3)
    best = _best_count(result)
    assert best is not None
    assert best <= min(
        (r.scan.failed_count for r in result.iterations if r.scan), default=best
    )


def test_dockerfile_output_is_not_written_as_terraform() -> None:
    """Regression test for a real bug: remediated Dockerfiles went to fixed.tf.

    Both scanners select Dockerfile rules by filename, so the same content scored 0 findings
    named `.tf` and 6 named `Dockerfile` — a silent perfect pass.
    """
    result = run("vulnerable.Dockerfile", DETECT, SECURE_DOCKERFILE)
    assert result.output_path is not None
    assert Path(result.output_path).name == "Dockerfile"


def test_terraform_output_keeps_a_tf_suffix() -> None:
    result = run("s3_public.tf", DETECT, 'resource "aws_s3_bucket" "example" {\n  bucket = "b"\n}\n')
    assert result.output_path is not None
    assert Path(result.output_path).suffix == ".tf"


def test_baseline_is_recorded_and_non_zero() -> None:
    """Every LoopResult is only interpretable alongside the baseline it was measured against."""
    result = run("s3_public.tf", DETECT, "")
    assert result.baseline.failed_count == 8
    assert result.scanner == "checkov"


# --------------------------------------------------------------------------------------
# on_step — progress reporting that cannot damage the run it reports on
# --------------------------------------------------------------------------------------


def test_on_step_reports_the_baseline_before_any_model_call() -> None:
    """A caller showing progress needs the first line *before* the slow part, not after it —
    that is the whole point of reporting at all."""
    seen: list[tuple[str, object]] = []
    result = run(
        "s3_public.tf", DETECT, "", on_step=lambda stage, rec: seen.append((stage, rec))
    )
    assert seen[0][0] == "baseline"
    assert seen[0][1].scan.failed_count == result.baseline.failed_count
    assert "detected" in [stage for stage, _ in seen]


def test_on_step_reports_every_iteration_exactly_once() -> None:
    seen: list[tuple[str, object]] = []
    result = run(
        "vulnerable.Dockerfile",
        DETECT,
        SECURE_DOCKERFILE,
        max_iters=3,
        on_step=lambda stage, rec: seen.append((stage, rec)),
    )
    reported = [rec for stage, rec in seen if stage == "iteration"]
    assert [r.index for r in reported] == [r.index for r in result.iterations]


def test_on_step_reports_an_iteration_only_once_its_gates_have_run() -> None:
    """Reporting a candidate mid-decision would let a caller announce a count for one the
    drift gate was about to reject — the exact confusion the gates exist to prevent."""
    states: list[bool] = []

    def note(stage: str, record: object) -> None:
        if stage == "iteration":
            # Settled means exactly one of the two outcomes is populated.
            states.append(bool(record.rejected_because) != bool(record.scan is not None))

    run("s3_public.tf", DETECT, "not valid terraform {{{", max_iters=2, on_step=note)
    assert states and all(states)


def test_a_callback_that_raises_cannot_abort_a_paid_run() -> None:
    """By the third iteration real money has been spent. A typo in someone's status handler
    must not be able to throw the result away."""

    def explode(stage: str, record: object) -> None:
        raise RuntimeError("the caller's problem, not the loop's")

    result = run("s3_public.tf", DETECT, "", max_iters=2, on_step=explode)
    assert result.baseline.failed_count == 8
    assert result.stop_reason is not None


def test_on_step_is_optional() -> None:
    """The default path must not change: every other test in this file passes None."""
    assert run("s3_public.tf", DETECT, "").baseline.failed_count == 8
