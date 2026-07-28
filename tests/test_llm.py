"""Tests for the model layer.

Every test drives `LLMClient` through an injected `complete_fn`, so the suite needs no API key,
makes no network call and costs nothing. That seam is the reason the whole evaluation harness is
runnable by anyone who clones the repo.

Four of these are regression tests for defects in the submitted implementation, recorded in
`ERRATA.md` E4 and E5:
  - no system message, despite the report describing one
  - no temperature parameter, despite the report claiming `temperature = 0`
  - failures returned as strings, which then flowed into the next prompt as if they were analysis
  - fence stripping that covered only ```hcl and ```terraform, so a ```dockerfile reply leaked
    its fence into the file handed to a scanner
"""

from __future__ import annotations

import json

import pytest

from iac_agent.llm import (
    PROMPT_VERSION,
    LLMClient,
    LLMResponse,
    ModelConfig,
    TokenUsage,
    distill_failures,
)
from iac_agent.types import Finding, IaCType, LLMError, ScanResult

FINDINGS_JSON = json.dumps(
    {
        "findings": [
            {
                "issue": "S3 bucket allows public read",
                "severity": "HIGH",
                "resource": "aws_s3_bucket.example",
                "recommendation": "Set the ACL to private.",
            }
        ]
    }
)

TF = 'resource "aws_s3_bucket" "example" {\n  bucket = "b"\n}\n'


def capture():
    """A fake complete_fn that records the messages it was handed."""
    seen: list = []

    def _fn(messages, **kwargs):
        seen.append({"messages": messages, "kwargs": kwargs})
        return FINDINGS_JSON

    return _fn, seen


def returning(*texts: str):
    state = {"i": 0}

    def _fn(messages, **_):
        i = min(state["i"], len(texts) - 1)
        state["i"] += 1
        return texts[i]

    return _fn


# --------------------------------------------------------------------------------------
# prompt construction — the ERRATA E4 regressions
# --------------------------------------------------------------------------------------


def test_a_system_message_is_sent() -> None:
    fn, seen = capture()
    LLMClient(complete_fn=fn).detect_vulnerabilities(TF, IaCType.TERRAFORM)
    roles = [m["role"] for m in seen[0]["messages"]]
    assert "system" in roles, "the submitted code sent a single user message"


def test_temperature_is_zero_and_seed_is_set() -> None:
    fn, seen = capture()
    LLMClient(complete_fn=fn).detect_vulnerabilities(TF, IaCType.TERRAFORM)
    kwargs = seen[0]["kwargs"]
    # An injected fn only receives the kwargs it declares, so absence here is acceptable;
    # what must never happen is a non-zero temperature reaching the model.
    assert kwargs.get("temperature", 0.0) == 0.0
    assert ModelConfig().temperature == 0.0
    assert ModelConfig().seed is not None


def test_model_is_a_pinned_snapshot_not_a_floating_alias() -> None:
    """A floating alias silently changes every published number on the next model release."""
    model = ModelConfig().model
    assert model != "gpt-4o-mini", "must pin a dated snapshot, not the alias"
    assert any(ch.isdigit() for ch in model.split("-")[-1])


def test_prompt_version_is_exposed_for_the_cache_key() -> None:
    """Cache entries must invalidate when the prompt changes, or results go stale silently."""
    assert PROMPT_VERSION
    assert ModelConfig().prompt_version == PROMPT_VERSION


def test_the_prompt_tells_the_model_not_to_delete_resources() -> None:
    """Prompt-side mitigation for the drift failure mode the drift gate measures."""
    fn, seen = capture()
    LLMClient(complete_fn=fn).generate_fix(TF, [], IaCType.TERRAFORM)
    text = " ".join(str(m.get("content", "")) for m in seen[0]["messages"]).lower()
    assert "delete" in text or "remove" in text
    assert "preserve" in text or "keep" in text or "must not" in text


def test_dialect_differs_between_terraform_and_dockerfile() -> None:
    """The submitted code hardcoded '(Terraform)' even when analysing a Dockerfile."""
    fn_tf, seen_tf = capture()
    LLMClient(complete_fn=fn_tf).detect_vulnerabilities(TF, IaCType.TERRAFORM)
    fn_d, seen_d = capture()
    LLMClient(complete_fn=fn_d).detect_vulnerabilities("FROM python:3.12\n", IaCType.DOCKERFILE)

    tf_text = " ".join(str(m.get("content", "")) for m in seen_tf[0]["messages"]).lower()
    d_text = " ".join(str(m.get("content", "")) for m in seen_d[0]["messages"]).lower()
    assert "terraform" in tf_text
    assert "docker" in d_text
    assert tf_text != d_text


# --------------------------------------------------------------------------------------
# response handling
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        FINDINGS_JSON,
        f"```json\n{FINDINGS_JSON}\n```",
        f"Here is what I found:\n\n{FINDINGS_JSON}\n\nHope that helps.",
        '[{"issue": "S3 bucket allows public read", "severity": "high", '
        '"resource": "aws_s3_bucket.example", "recommendation": "Set ACL to private."}]',
    ],
)
def test_detection_survives_the_shapes_models_actually_return(response: str) -> None:
    findings = LLMClient(complete_fn=returning(response)).detect_vulnerabilities(
        TF, IaCType.TERRAFORM
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "high", "severity must be normalised to lowercase"
    assert findings[0]["issue"]


def test_unparseable_detection_raises_rather_than_returning_nothing() -> None:
    """Returning [] here would read as 'the model found no problems'."""
    with pytest.raises(LLMError):
        LLMClient(complete_fn=returning("I could not analyse that file.")).detect_vulnerabilities(
            TF, IaCType.TERRAFORM
        )


def test_a_failing_complete_fn_raises_instead_of_returning_a_string() -> None:
    """ERRATA E4: the submitted code returned f"Error calling LLM: {e}" as if it were content."""

    def boom(messages, **_):
        raise RuntimeError("connection reset")

    client = LLMClient(complete_fn=boom)
    with pytest.raises(LLMError):
        client.detect_vulnerabilities(TF, IaCType.TERRAFORM)
    with pytest.raises(LLMError):
        client.generate_fix(TF, [], IaCType.TERRAFORM)


@pytest.mark.parametrize("tag", ["hcl", "terraform", "tf", "json", ""])
def test_fences_are_stripped_from_generated_terraform(tag: str) -> None:
    out = LLMClient(complete_fn=returning(f"```{tag}\n{TF}```")).generate_fix(
        TF, [], IaCType.TERRAFORM
    )
    assert "```" not in out
    assert "aws_s3_bucket" in out


def test_dockerfile_fences_are_stripped() -> None:
    """```dockerfile was not in the submitted code's replace list, so it leaked into the file."""
    body = "FROM python:3.12-slim\nUSER app\n"
    out = LLMClient(complete_fn=returning(f"```dockerfile\n{body}```")).generate_fix(
        body, [], IaCType.DOCKERFILE
    )
    assert "```" not in out
    assert out.strip().startswith("FROM")


# --------------------------------------------------------------------------------------
# token accounting and injection
# --------------------------------------------------------------------------------------


def test_usage_accumulates_across_calls() -> None:
    """The loop's TOKEN_BUDGET stop condition reads this; if it never moves, the cap never fires."""
    resp = LLMResponse(
        text=FINDINGS_JSON,
        usage=TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15, calls=1),
    )
    client = LLMClient(complete_fn=lambda messages, **_: resp)
    client.detect_vulnerabilities(TF, IaCType.TERRAFORM)
    first = client.usage.total_tokens
    client.detect_vulnerabilities(TF, IaCType.TERRAFORM)
    assert client.usage.total_tokens > first

    client.reset_usage()
    assert client.usage.total_tokens == 0


def test_injection_is_detectable() -> None:
    assert LLMClient(complete_fn=returning(FINDINGS_JSON)).is_injected
    assert not LLMClient().is_injected


def test_no_api_key_is_needed_to_construct_a_client() -> None:
    """Constructing must not touch the network or the environment — tests depend on this."""
    assert LLMClient(complete_fn=returning("x")) is not None


# --------------------------------------------------------------------------------------
# distill_failures — the loop's cost control
# --------------------------------------------------------------------------------------


def _scan(n: int) -> ScanResult:
    return ScanResult(
        scanner="checkov",
        target=__import__("pathlib").Path("x.tf"),
        iac_type=IaCType.TERRAFORM,
        failed=[
            Finding(
                rule_id=f"CKV_AWS_{i}",
                severity="high",
                resource=f"aws_s3_bucket.b{i}",
                message=f"finding number {i}",
                scanner="checkov",
            )
            for i in range(n)
        ],
    )


def test_distill_is_capped() -> None:
    """Feeding raw scanner JSON back is the difference between a $0.01 run and a $0.50 one."""
    assert len(distill_failures(_scan(50))) <= 10


def test_distill_keeps_the_identifying_fields() -> None:
    out = distill_failures(_scan(3))
    assert out
    joined = json.dumps(out)
    assert "CKV_AWS_0" in joined
    assert "aws_s3_bucket.b0" in joined


def test_distill_of_a_clean_scan_is_empty() -> None:
    assert distill_failures(_scan(0)) == []
