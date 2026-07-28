"""Test-suite safety net: make an accidental live API call impossible.

Deleting `OPENAI_API_KEY` from the environment is **not** sufficient. `LLMClient` falls back to
`python-dotenv`, which reads `.env` from the working directory, so a test that believes it is
running key-free will happily authenticate and spend the developer's money. That is not
hypothetical — it happened while writing `tests/test_cli.py`, where a test intended to check the
no-credentials path instead ran two full refinement iterations and burned real tokens.

So the guard is applied at the transport boundary rather than the environment: any attempt to
construct a real OpenAI client during a test raises. Tests that need model behaviour inject a
`complete_fn`, which never reaches this path.

To write a test that *does* need the network — there is currently no such test, and adding one
should be a deliberate decision — request the `allow_network` fixture explicitly.
"""

from __future__ import annotations

import pytest


class LiveAPICallInTests(RuntimeError):
    """Raised when a test tries to reach the real API."""


@pytest.fixture(autouse=True)
def _block_live_api(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if "allow_network" in request.fixturenames:
        return

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    # Neutralise the dotenv fallback: without this, `.env` silently re-supplies the key.
    try:
        import dotenv

        monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: False, raising=False)
    except ImportError:  # pragma: no cover - dotenv is a declared dependency
        pass

    try:
        import openai
    except ImportError:  # pragma: no cover
        return

    def _refuse(*_args, **_kwargs):
        raise LiveAPICallInTests(
            "A test tried to construct a real OpenAI client. Tests must inject a "
            "`complete_fn` instead — see tests/test_llm.py. If a live call is genuinely "
            "required, request the `allow_network` fixture."
        )

    monkeypatch.setattr(openai, "OpenAI", _refuse, raising=False)


@pytest.fixture
def allow_network() -> None:
    """Opt out of the guard. Requesting this fixture is a deliberate, reviewable choice."""
    return None
