"""Boundaries for the optional public portfolio demo."""

from __future__ import annotations

import os
import hashlib
import json
import time
from pathlib import Path

from iac_agent.scanners import SCANNERS
from iac_agent.llm import LLMResponse, ModelConfig, TokenUsage
from iac_agent.types import LLMError

MAX_UPLOAD_BYTES = 64 * 1024
FREE_MODEL = "gemini-3.5-flash-lite"
GEMINI_OPENAI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"


def demo_mode() -> bool:
    return os.getenv("IAC_DEMO_MODE") == "1"


def available_scanners(public: bool) -> list[str]:
    return ["checkov"] if public else sorted(SCANNERS)


def free_model_fixture(root: Path, name: str, code: str) -> bool:
    """The owner's free-tier key may only process unmodified repository fixtures."""
    fixture = root / "samples" / name
    if not fixture.is_file() or fixture.name != name:
        return False
    try:
        return fixture.read_text(encoding="utf-8") == code
    except OSError:
        return False


def gemini_complete(messages: list[dict[str, str]], *, cfg: ModelConfig,
                    response_format: dict | None = None) -> LLMResponse:
    """OpenAI-compatible Gemini transport for the optional public fixture demo."""
    from openai import OpenAI

    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise LLMError("GEMINI_API_KEY is not configured for this demo.")
    client = OpenAI(api_key=key, base_url=GEMINI_OPENAI_BASE_URL, max_retries=0, timeout=120)
    kwargs = {
        "model": cfg.model,
        "messages": messages,
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
        "reasoning_effort": "low",
    }
    if response_format is not None:
        kwargs["response_format"] = response_format
    for attempt in range(2):
        try:
            resp = client.chat.completions.create(**kwargs)
            break
        except Exception as exc:
            # Retry one transient provider failure. Keep the one-rewrite limit: a failed
            # HTTP response produced no candidate, and every successful response still
            # enters the same parse, drift, and rescan gates.
            status = getattr(exc, "status_code", None)
            if attempt == 0 and isinstance(status, int) and 500 <= status < 600:
                time.sleep(1)
                continue
            # Provider errors may echo request headers. Never show one beside a public key.
            raise LLMError(
                f"Gemini request failed ({type(exc).__name__}); try the recorded example."
            ) from exc
    if not getattr(resp, "choices", None):
        raise LLMError("Gemini returned no candidate.")
    choice = resp.choices[0]
    if getattr(choice, "finish_reason", None) == "length":
        raise LLMError("Gemini reached its output limit; no partial fix was accepted.")
    content = getattr(choice.message, "content", None)
    if not content:
        raise LLMError("Gemini returned no code.")
    usage = getattr(resp, "usage", None)
    return LLMResponse(
        text=content,
        usage=TokenUsage(
            prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
            completion_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
            total_tokens=int(getattr(usage, "total_tokens", 0) or 0),
            calls=1,
        ),
    )


def validate_upload(name: str, content: bytes) -> tuple[str, str]:
    """Return a safe filename and UTF-8 source before any scanner sees it."""
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload exceeds the 64 KiB demo limit.")

    filename = Path(name).name
    lower = filename.lower()
    if not (lower.endswith(".tf") or lower == "dockerfile" or lower.endswith(".dockerfile")):
        raise ValueError("Upload a Terraform or Dockerfile source file.")

    try:
        source = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Upload must be UTF-8 text.") from exc
    return filename, source


def load_recorded_example(root: Path) -> dict:
    """Load one accepted historical repair and verify its committed artifacts."""
    root = root.resolve()

    def read_artifact(relative: str) -> bytes:
        path = (root / relative).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Recorded example path escapes the repository.")
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ValueError(f"Recorded example artifact unavailable: {relative}") from exc

    try:
        report = json.loads(read_artifact("eval/results/results.json"))
        row = next(
            item for item in report["runs"]
            if item["fixture"] == "samples/s3_public.tf"
            and item["variant"] == "stripped"
            and item["run_index"] == 0
        )
        metadata = report["metadata"]
        before = row["before"]["checkov"]
        after = row["after"]["checkov"]
        model = metadata["model"]
        checkov_version = metadata["checkov_version"]
        timestamp = metadata["timestamp"]
        drift_summary = row["drift"]["summary"]
        source_sha = row["file_sha"]
        original_bytes = read_artifact(row["source"])
        output_bytes = read_artifact(row["output_path"])
        output_sha = row["attempts"][-1]["output_sha"]
    except (AttributeError, KeyError, IndexError, StopIteration, TypeError,
            json.JSONDecodeError) as exc:
        raise ValueError("Recorded example evidence is incomplete.") from exc

    if hashlib.sha256(original_bytes).hexdigest() != source_sha:
        raise ValueError("Recorded example source digest does not match its report.")
    if hashlib.sha256(output_bytes).hexdigest() != output_sha:
        raise ValueError("Recorded example artifact digest does not match its report.")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Recorded example scanner evidence is incomplete.")
    if (
        row["source"] != "eval/corpus/stripped/s3_public.tf"
        or before.get("target") != row["source"]
        or after.get("target") != row["output_path"]
    ):
        raise ValueError("Recorded example scanner target does not match its source or output.")
    if any(
        not isinstance(count, int) or isinstance(count, bool) or count < 0
        for count in (before.get("failed_count"), after.get("failed_count"))
    ):
        raise ValueError("Recorded example finding counts are incomplete.")
    try:
        valid = (
            row["remediation_valid"] is True
            and row["after_is_before"] is False
            and not row["drift_touches_flaw"]
            and row["drift"]["drifted"] is False
            and before["parse_errors"] == 0
            and after["parse_errors"] == 0
            and after["failed_count"] < before["failed_count"]
        )
    except (KeyError, TypeError) as exc:
        raise ValueError("Recorded example evidence is incomplete.") from exc
    if not valid:
        raise ValueError("Recorded example did not pass its reported checks.")

    try:
        original = original_bytes.decode("utf-8")
        output = output_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Recorded example source is not UTF-8.") from exc

    return {
        "fixture": row["fixture"],
        "artifact": row["output_path"],
        "original": original,
        "output": output,
        "model": model,
        "checkov_version": checkov_version,
        "timestamp": timestamp,
        "before": before["failed_count"],
        "after": after["failed_count"],
        "drift": drift_summary,
    }
