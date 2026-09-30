"""Boundaries for the optional public portfolio demo."""

from __future__ import annotations

import os
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
