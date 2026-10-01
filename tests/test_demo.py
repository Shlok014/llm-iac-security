"""Public demo boundaries: anonymous scans must stay free and bounded."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_demo_mode_disables_openai_fix_even_if_a_key_is_present(monkeypatch):
    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-key")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    spec = importlib.util.spec_from_file_location("_demo_app_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(app)

    enabled, reason = app._fix_availability()
    assert enabled is False
    assert "gemini" in reason.lower()


def test_demo_mode_rejects_direct_fix_call_before_constructing_a_model(monkeypatch):
    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    spec = importlib.util.spec_from_file_location("_demo_direct_fix_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(app)

    def unexpected_model():
        raise AssertionError("a public demo must not construct a model client")

    monkeypatch.setattr(app, "LLMClient", unexpected_model)
    with pytest.raises(ValueError, match="disabled"):
        app._do_fix("example.tf", 'resource "aws_s3_bucket" "a" {}', "checkov", 1)


def test_free_model_is_only_available_for_exact_bundled_fixture(monkeypatch):
    from demo import free_model_fixture

    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    fixture = ROOT / "samples" / "ec2_open.tf"
    source = fixture.read_text()
    assert free_model_fixture(ROOT, fixture.name, source)
    assert not free_model_fixture(ROOT, fixture.name, source + "\n# changed")
    assert not free_model_fixture(ROOT, "custom.tf", source)


def test_free_model_guard_rejects_upload_even_with_key(monkeypatch):
    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "not-a-real-key")
    spec = importlib.util.spec_from_file_location("_demo_free_guard_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(app)
    with pytest.raises(ValueError, match="bundled fixture"):
        app._do_fix("custom.tf", 'resource "aws_s3_bucket" "a" {}', "checkov", 1)


def test_gemini_transport_uses_only_its_key_and_compatibility_endpoint(monkeypatch):
    from types import SimpleNamespace
    import openai

    from demo import FREE_MODEL, GEMINI_OPENAI_BASE_URL, gemini_complete
    from iac_agent.llm import ModelConfig

    monkeypatch.setenv("GEMINI_API_KEY", "fixture-test-key")
    calls = []

    class FakeOpenAI:
        def __init__(self, **kwargs):
            calls.append(kwargs)
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(
                choices=[SimpleNamespace(
                    finish_reason="stop",
                    message=SimpleNamespace(content='{"findings": []}'),
                )],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=3, total_tokens=13),
            )

    monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)
    reply = gemini_complete(
        [{"role": "user", "content": "fixture"}],
        cfg=ModelConfig(model=FREE_MODEL),
        response_format={"type": "json_schema"},
    )
    assert reply.text == '{"findings": []}'
    assert reply.usage.total_tokens == 13
    assert calls[0]["base_url"] == GEMINI_OPENAI_BASE_URL
    assert calls[0]["api_key"] == "fixture-test-key"
    assert calls[0]["timeout"] == 120
    assert calls[1]["model"] == FREE_MODEL
    assert calls[1]["reasoning_effort"] == "low"
    assert calls[1]["response_format"] == {"type": "json_schema"}
    assert "seed" not in calls[1]


def test_gemini_transport_retries_one_transient_server_failure(monkeypatch):
    from types import SimpleNamespace
    import openai

    from demo import FREE_MODEL, gemini_complete
    from iac_agent.llm import ModelConfig

    monkeypatch.setenv("GEMINI_API_KEY", "fixture-test-key")
    attempts = []

    class ServerFailure(Exception):
        status_code = 500

    class FakeOpenAI:
        def __init__(self, **_kwargs):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **_kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                raise ServerFailure("temporary provider fault")
            return SimpleNamespace(
                choices=[SimpleNamespace(
                    finish_reason="stop", message=SimpleNamespace(content="fixed code")
                )],
                usage=SimpleNamespace(prompt_tokens=2, completion_tokens=3, total_tokens=5),
            )

    monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)
    reply = gemini_complete(
        [{"role": "user", "content": "fixture"}], cfg=ModelConfig(model=FREE_MODEL)
    )
    assert reply.text == "fixed code"
    assert len(attempts) == 2


def test_gemini_transport_does_not_retry_client_error(monkeypatch):
    from types import SimpleNamespace
    import openai

    from demo import FREE_MODEL, gemini_complete
    from iac_agent.llm import ModelConfig
    from iac_agent.types import LLMError

    monkeypatch.setenv("GEMINI_API_KEY", "fixture-test-key")
    attempts = []

    class ClientFailure(Exception):
        status_code = 401

    class FakeOpenAI:
        def __init__(self, **_kwargs):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **_kwargs):
            attempts.append(1)
            raise ClientFailure("do not display provider response")

    monkeypatch.setattr(openai, "OpenAI", FakeOpenAI)
    with pytest.raises(LLMError, match="Gemini request failed") as caught:
        gemini_complete([{"role": "user", "content": "fixture"}], cfg=ModelConfig(model=FREE_MODEL))
    assert len(attempts) == 1
    assert "do not display provider response" not in str(caught.value)


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


def test_recorded_example_uses_committed_scanner_and_drift_evidence():
    from demo import load_recorded_example

    example = load_recorded_example(ROOT)
    assert example["fixture"] == "samples/s3_public.tf"
    assert example["model"] == "gpt-4o-mini-2024-07-18"
    assert example["checkov_version"] == "3.2.489"
    assert example["before"] == 8
    assert example["after"] == 7
    assert example["drift"] == "no resource drift"
    assert 'acl    = "public-read"' in example["original"]
    assert 'acl    = "private"' in example["output"]
    assert example["artifact"] == "eval/results/artifacts/stripped/run0/s3_public/fixed.tf"


def test_recorded_example_refuses_tampered_artifact(tmp_path):
    from demo import load_recorded_example

    result = json.loads((ROOT / "eval/results/results.json").read_text())
    result["runs"] = [
        row for row in result["runs"]
        if row["fixture"] == "samples/s3_public.tf"
        and row["variant"] == "stripped"
        and row["run_index"] == 0
    ]
    report = tmp_path / "eval/results/results.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps(result))
    row = result["runs"][0]
    for relative in (row["source"], row["output_path"]):
        dest = tmp_path / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, dest)
    (tmp_path / row["output_path"]).write_text("tampered")

    with pytest.raises(ValueError, match="artifact digest"):
        load_recorded_example(tmp_path)


def test_recorded_example_refuses_output_not_bound_to_after_scan(tmp_path):
    from demo import load_recorded_example

    result = json.loads((ROOT / "eval/results/results.json").read_text())
    result["runs"] = [
        row for row in result["runs"]
        if row["fixture"] == "samples/s3_public.tf"
        and row["variant"] == "stripped"
        and row["run_index"] == 0
    ]
    row = result["runs"][0]
    row["after"]["checkov"]["target"] = "unrelated.tf"
    report = tmp_path / "eval/results/results.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps(result))
    for relative in (row["source"], row["output_path"]):
        dest = tmp_path / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, dest)

    with pytest.raises(ValueError, match="target"):
        load_recorded_example(tmp_path)


def test_recorded_example_missing_digest_is_unavailable(tmp_path):
    from demo import load_recorded_example

    result = json.loads((ROOT / "eval/results/results.json").read_text())
    result["runs"] = [
        row for row in result["runs"]
        if row["fixture"] == "samples/s3_public.tf"
        and row["variant"] == "stripped"
        and row["run_index"] == 0
    ]
    row = result["runs"][0]
    del row["file_sha"]
    report = tmp_path / "eval/results/results.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps(result))
    for relative in (row["source"], row["output_path"]):
        dest = tmp_path / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, dest)

    with pytest.raises(ValueError, match="incomplete"):
        load_recorded_example(tmp_path)


def test_public_scans_do_not_reuse_shared_cached_results(monkeypatch):
    from iac_agent.types import IaCType, ScanResult

    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    spec = importlib.util.spec_from_file_location("_demo_scan_cache_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(app)

    calls = 0

    class Scanner:
        def scan(self, target, iac_type):
            nonlocal calls
            calls += 1
            return ScanResult(
                scanner="checkov", target=target, iac_type=IaCType.TERRAFORM,
                passed_count=calls,
            )

    monkeypatch.setattr(app, "get_scanner", lambda _name: Scanner())
    first = app._do_scan("cache-probe.tf", 'resource "aws_s3_bucket" "a" {}', "checkov")
    second = app._do_scan("cache-probe.tf", 'resource "aws_s3_bucket" "a" {}', "checkov")

    assert first["passed"] == 1
    assert second["passed"] == 2


def test_public_scanner_failure_propagates_as_unverified(monkeypatch):
    monkeypatch.setenv("IAC_DEMO_MODE", "1")
    spec = importlib.util.spec_from_file_location("_demo_scanner_failure_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(app)

    class BrokenScanner:
        def scan(self, target, iac_type):
            raise RuntimeError("scanner unavailable")

    monkeypatch.setattr(app, "get_scanner", lambda _name: BrokenScanner())
    with pytest.raises(RuntimeError, match="scanner unavailable"):
        app._do_scan("broken.tf", 'resource "aws_s3_bucket" "a" {}', "checkov")


def test_parse_errors_never_render_a_clean_verified_scan(monkeypatch):
    spec = importlib.util.spec_from_file_location("_demo_parse_error_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(app)

    successes = []
    warnings = []
    verdicts = []
    monkeypatch.setattr(app.st, "success", lambda message: successes.append(message))
    monkeypatch.setattr(app.st, "warning", lambda message: warnings.append(message))
    monkeypatch.setattr(app.st, "caption", lambda message: None)
    monkeypatch.setattr(app.st, "download_button", lambda *args, **kwargs: None)
    monkeypatch.setattr(app.ui, "eyebrow", lambda *args, **kwargs: None)
    monkeypatch.setattr(app.ui, "verdict", lambda *args, **kwargs: verdicts.append(kwargs))

    payload = {
        "findings": [], "scanned_as": "broken.tf", "name": "broken.tf",
        "scanner": "checkov", "passed": 0, "parse_errors": 1, "iac_type": "terraform",
    }
    app._render_scan(payload)

    assert verdicts[0]["tone"] == "unverified"
    assert not successes
    assert warnings
