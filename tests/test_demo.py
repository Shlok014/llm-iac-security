"""Public demo boundaries: anonymous scans must stay free and bounded."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_demo_mode_disables_fix_even_if_a_key_is_present(monkeypatch):
    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-key")
    spec = importlib.util.spec_from_file_location("_demo_app_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(app)

    enabled, reason = app._fix_availability()
    assert enabled is False
    assert "demo" in reason.lower()


def test_demo_mode_rejects_direct_fix_call_before_constructing_a_model(monkeypatch):
    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    spec = importlib.util.spec_from_file_location("_demo_direct_fix_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(app)

    def unexpected_model():
        raise AssertionError("a public demo must not construct a model client")

    monkeypatch.setattr(app, "LLMClient", unexpected_model)
    with pytest.raises(ValueError, match="disabled"):
        app._do_fix("example.tf", 'resource "aws_s3_bucket" "a" {}', "checkov", 1)


def test_upload_rejects_oversize_before_decoding():
    from demo import validate_upload

    with pytest.raises(ValueError, match="64 KiB"):
        validate_upload("example.tf", b"\xff" * 65_537)


def test_upload_accepts_exact_size_and_strips_directory():
    from demo import validate_upload

    assert validate_upload("../example.tf", b"a" * 65_536) == (
        "example.tf",
        "a" * 65_536,
    )


@pytest.mark.parametrize("name", ["notes.txt", "configuration.yaml", "../.env"])
def test_upload_rejects_unsupported_filename(name):
    from demo import validate_upload

    with pytest.raises(ValueError, match="Terraform or Dockerfile"):
        validate_upload(name, b"content")


def test_upload_rejects_non_utf8_text():
    from demo import validate_upload

    with pytest.raises(ValueError, match="UTF-8"):
        validate_upload("example.tf", b"\xff")


def test_demo_advertises_only_installed_checkov(monkeypatch):
    from demo import available_scanners

    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    assert available_scanners(public=True) == ["checkov"]
