"""Boundaries for the optional public portfolio demo."""

from __future__ import annotations

import os
import hashlib
import json
from pathlib import Path

from iac_agent.scanners import SCANNERS

MAX_UPLOAD_BYTES = 64 * 1024


def demo_mode() -> bool:
    return os.getenv("IAC_DEMO_MODE") == "1"


def available_scanners(public: bool) -> list[str]:
    return ["checkov"] if public else sorted(SCANNERS)


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
