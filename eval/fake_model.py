"""A deterministic offline stand-in for the model, for exercising the harness without spend.

This is not a simulation of model quality and must never be used to produce published
numbers — it exists so the full pipeline (detect → fix → validity gate → rescan → refine →
metrics → RESULTS.md) can be run end to end with no API key, no network and no cost. That
matters for two reasons: a contributor can verify the harness works before paying for
anything, and a real eval run is expensive enough that discovering a plumbing bug halfway
through is worth actively preventing.

Usage:

    python -m eval.run_eval run --complete-fn eval.fake_model:naive_fixer

`naive_fixer` applies a handful of genuinely correct, deterministic rewrites — the sort of
thing a competent model would get right — so the loop sees a real finding reduction rather
than a no-op. It leaves plenty unfixed, which is what makes it useful: it exercises the
NO_PROGRESS and MAX_ITERS paths as well as CONVERGED.
"""

from __future__ import annotations

import json
import re
from typing import Any, Sequence

# Deterministic rewrites, applied in order. Each is a real hardening step, not a trick to
# drive the count down — a rule that deleted resources would be caught by the drift gate,
# which is exactly the behaviour the gate exists to catch.
_TERRAFORM_RULES: tuple[tuple[str, str], ...] = (
    (r'acl\s*=\s*"public-read(-write)?"', 'acl    = "private"'),
    (r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', 'cidr_blocks = ["10.0.0.0/8"]'),
    (r"publicly_accessible\s*=\s*true", "publicly_accessible = false"),
    (r"encrypted\s*=\s*false", "encrypted   = true"),
    (r"map_public_ip_on_launch\s*=\s*true", "map_public_ip_on_launch = false"),
    (r"skip_final_snapshot\s*=\s*true", "skip_final_snapshot = false"),
)

_DOCKERFILE_RULES: tuple[tuple[str, str], ...] = (
    (r"^\s*ENV\s+(DB_PASSWORD|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=.*$", ""),
    (r"^\s*EXPOSE\s+.*(22|2375).*$", "EXPOSE 5000"),
    (r"chmod\s+777", "chmod 750"),
)


def _last_user_message(messages: Sequence[Any]) -> str:
    for m in reversed(list(messages)):
        role = m.get("role") if isinstance(m, dict) else getattr(m, "role", None)
        if role == "user":
            content = m.get("content") if isinstance(m, dict) else getattr(m, "content", "")
            return content if isinstance(content, str) else str(content)
    return ""


def _looks_like_detection(text: str) -> bool:
    """Detection asks the model to *audit*; remediation asks it to *rewrite*.

    Deliberately keyed on the user message's verb rather than on the word "json": the JSON
    contract lives in the system message and in `response_format`, so a naive
    `"json" in text` check misclassifies every detection call as a remediation and returns
    HCL where the caller expects an object.
    """
    head = text.lstrip()[:200].lower()
    return head.startswith("audit ") or "report every security misconfiguration" in head


def _extract_code(text: str) -> str:
    """Pull the IaC body out of a prompt.

    `llm.py` wraps the file in `<file name="...">…</file>`. Fenced blocks and a few heading
    forms are accepted as fallbacks so this keeps working if the wording shifts.
    """
    tagged = re.search(r"<file\b[^>]*>\n?(.*?)</file>", text, re.DOTALL)
    if tagged:
        return tagged.group(1).strip()
    fenced = re.findall(r"```[a-zA-Z]*\n(.*?)```", text, re.DOTALL)
    if fenced:
        return max(fenced, key=len).strip()
    for marker in ("Original code:", "Current code:", "Code:", "File:"):
        if marker in text:
            return text.split(marker, 1)[1].strip()
    return text.strip()


def _harden(code: str) -> str:
    is_docker = bool(re.search(r"^\s*FROM\s+", code, re.MULTILINE))
    rules = _DOCKERFILE_RULES if is_docker else _TERRAFORM_RULES
    out = code
    for pattern, replacement in rules:
        out = re.sub(pattern, replacement, out, flags=re.MULTILINE)
    if is_docker and "USER " not in out:
        out = out.rstrip() + "\nUSER nonroot\n"
    return out


def naive_fixer(messages: Sequence[Any], **_: Any) -> str:
    """Return canned findings for a detection call, hardened code for a remediation call."""
    text = _last_user_message(messages)
    if _looks_like_detection(text):
        return json.dumps(
            {
                "findings": [
                    {
                        "issue": "Resource is exposed to the public internet",
                        "severity": "high",
                        "resource": "",
                        "recommendation": "Restrict access to a private CIDR range.",
                    },
                    {
                        "issue": "Credentials are hardcoded in the configuration",
                        "severity": "critical",
                        "resource": "",
                        "recommendation": "Move secrets to a secret manager.",
                    },
                ]
            }
        )
    return _harden(_extract_code(text))


def no_op(messages: Sequence[Any], **_: Any) -> str:
    """Returns the input unchanged — drives the loop straight to NO_PROGRESS."""
    text = _last_user_message(messages)
    if _looks_like_detection(text):
        return json.dumps({"findings": []})
    return _extract_code(text)
