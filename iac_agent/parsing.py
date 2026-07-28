"""One JSON extractor, shared.

The original code had two divergent implementations: a bare `json.loads` in `main.py`
that almost always failed (models fence their JSON), and a better multi-stage parser in
`app.py`. `main.py`'s failure was silent — it returned `{"raw_output": ...}`, which then
got interpolated into the remediation prompt as a stringified Python dict.

Structured outputs make this a fallback rather than the primary path, but models still
drift, so the fallback stays and is tested.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any

_FENCE_RE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)


def strip_code_fences(text: str, tags: tuple[str, ...] = ()) -> str:
    """Remove markdown fences from generated code.

    `main.py` did this with three `str.replace` calls covering only ```hcl, ```terraform
    and bare ```, so a model answering with ```dockerfile leaked the fence into the file
    that was then handed to a scanner.
    """
    out = text.strip()
    fenced = re.match(r"^```[a-zA-Z]*\s*\n(.*?)\n?```$", out, re.DOTALL)
    if fenced:
        return fenced.group(1).strip()
    for tag in (*tags, "json", ""):
        out = out.replace(f"```{tag}", "")
    return out.replace("```", "").strip()


def extract_json(text: str) -> Any:
    """Best-effort structured extraction from a model response.

    Stages, in order: fenced block, bracket slice, strict parse, trailing-comma repair,
    then `ast.literal_eval`. Raises ValueError rather than returning a sentinel — a
    caller must not be able to mistake failure for an empty finding list.
    """
    if text is None:
        raise ValueError("no text to parse")
    raw = str(text).strip()
    if not raw:
        raise ValueError("empty response")

    fenced = _FENCE_RE.search(raw)
    if fenced:
        raw = fenced.group(1).strip()

    if not raw.startswith(("[", "{")):
        starts = [i for i in (raw.find("["), raw.find("{")) if i != -1]
        ends = [i for i in (raw.rfind("]"), raw.rfind("}")) if i != -1]
        if starts and ends:
            raw = raw[min(starts) : max(ends) + 1].strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    repaired = re.sub(r",(\s*[\]}])", r"\1", raw)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    try:
        return ast.literal_eval(repaired)
    except (ValueError, SyntaxError) as exc:
        raise ValueError(f"could not parse model output as JSON: {exc}") from exc


def normalise_findings(parsed: Any) -> list[dict]:
    """Coerce a parsed response into a list of finding dicts.

    Accepts a bare list, a `{"findings": [...]}` envelope, or a single object.
    """
    if isinstance(parsed, dict):
        for key in ("findings", "issues", "vulnerabilities", "results"):
            if isinstance(parsed.get(key), list):
                parsed = parsed[key]
                break
        else:
            parsed = [parsed]
    if not isinstance(parsed, list):
        raise ValueError(f"expected a list of findings, got {type(parsed).__name__}")

    out: list[dict] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        lowered = {str(k).lower(): v for k, v in item.items()}
        out.append(
            {
                "issue": str(
                    lowered.get("issue") or lowered.get("title") or lowered.get("description") or ""
                ).strip(),
                "severity": str(lowered.get("severity") or "unknown").strip().lower(),
                "resource": str(lowered.get("resource") or "").strip(),
                "recommendation": str(
                    lowered.get("recommendation") or lowered.get("remediation") or ""
                ).strip(),
            }
        )
    return out
