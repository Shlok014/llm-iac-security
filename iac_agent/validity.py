"""Two gates that run *after* the model rewrites a file, before anyone believes the score.

The original pipeline handed the model's output straight to a scanner and reported the
drop in findings as the result. That measures the wrong thing twice over:

1. **Nothing checked the output was parseable.** A file that Terraform cannot parse and a
   file with zero misconfigurations produce the same number on a leaderboard. Worse, a
   response that still carries markdown fences scans as a Dockerfile with no instructions
   — clean, by the numbers.
2. **Nothing checked the output was still the same infrastructure.** The cheapest way for
   a model to fix a publicly-accessible RDS instance is to delete the resource. Findings
   go to zero, the remediation scores perfectly, and the database is gone. That is the
   metric this module exists to produce: not "did the findings drop" but "did the findings
   drop *because the resource stopped existing*".

Zero new dependencies. HCL parsing uses `hcl2` (the `bc-python-hcl2` distribution), which
is already installed as a Checkov dependency. Dockerfiles get a structural check instead —
no HCL grammar applies to them, and pulling in a Dockerfile parser for a first-instruction
check would not be worth the dependency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import hcl2

from .types import IaCAgentError, IaCType, detect_iac_type

# Fences at the start of a line are the observed LLM failure mode ("```hcl\n...").
# Matching bare ``` anywhere would flag a Dockerfile whose RUN line happens to echo
# backticks, so the line-start form is required — except for a tagged fence, which has no
# innocent reading inside an IaC file.
_FENCE_RE = re.compile(r"^[ \t]*```|```[a-zA-Z]+", re.MULTILINE)

# Longest string we will even consider testing as a filesystem path. Model output is
# routinely megabytes; calling Path().is_file() on it is pointless and, on some platforms,
# raises.
_MAX_PATHLIKE = 1024


class ValidityError(IaCAgentError):
    """Input could not be parsed well enough to reason about its resources.

    Raised by `extract_resources` rather than returning an empty list, for the same reason
    `scanners.py` raises instead of returning zero findings: an empty resource list from a
    broken parse would read as "the model deleted everything", which is a different
    conclusion from "we could not tell".
    """


# --------------------------------------------------------------------------------------
# input normalisation
# --------------------------------------------------------------------------------------


def _read_source(source: str | Path) -> str:
    """Accept a Path, a path string, or raw file content, and return the content.

    Ambiguity is real: a `str` could be either. The rule is that a `Path` is always a path,
    and a `str` is only treated as one if it is short, single-line, and actually names an
    existing file. Everything else is content. In practice model output always contains a
    newline, so it never collides.
    """
    if isinstance(source, Path):
        return source.read_text(encoding="utf-8", errors="replace")

    text = str(source)
    if "\n" not in text and 0 < len(text) <= _MAX_PATHLIKE:
        try:
            candidate = Path(text)
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass  # embedded NUL, name too long, permission — treat it as content
    return text


def _resolve_type(source: str | Path, iac_type: IaCType | None) -> IaCType:
    """Use the caller's type if given, else infer it from a path. Never guess from text."""
    if iac_type is not None:
        return iac_type
    if isinstance(source, Path) or (
        isinstance(source, str) and "\n" not in source and Path(source).exists()
    ):
        return detect_iac_type(source)
    raise ValidityError(
        "iac_type is required when the source is raw text — the content of a Terraform "
        "file and a Dockerfile cannot be distinguished reliably enough to guess."
    )


def _load_hcl(text: str) -> dict:
    """Parse HCL text into python-hcl2's document dict.

    `hcl2.load` takes a file object and `hcl2.loads` takes a string; since every input is
    normalised to text before it reaches here, only `loads` is ever needed. It raises
    `lark` exceptions, which are not part of any contract we control, so callers catch
    broadly and re-wrap.
    """
    parsed = hcl2.loads(text)
    return parsed if isinstance(parsed, dict) else {}


# --------------------------------------------------------------------------------------
# gate 1: does it still parse?
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidityResult:
    """Outcome of the parse gate. `reason` is a stable slug; `detail` is for humans."""

    ok: bool
    reason: str
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


def _instructions(text: str) -> Iterator[tuple[str, str]]:
    """Yield (INSTRUCTION, arguments) for each logical Dockerfile line.

    Handles backslash continuations and drops comment/parser-directive lines, because the
    first real instruction is what the check turns on and a leading `# syntax=` line is
    both legal and common.
    """
    buf = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if not line and not buf:
            continue
        if line.endswith("\\"):
            buf += line[:-1].rstrip() + " "
            continue
        buf += line
        if buf.strip():
            head, _, rest = buf.strip().partition(" ")
            yield head.upper(), rest.strip()
        buf = ""
    if buf.strip():
        head, _, rest = buf.strip().partition(" ")
        yield head.upper(), rest.strip()


def _check_terraform(text: str) -> ValidityResult:
    try:
        doc = _load_hcl(text)
    except Exception as exc:  # lark exception hierarchy is not ours to depend on
        return ValidityResult(
            ok=False,
            reason="hcl_parse_error",
            detail=f"{type(exc).__name__}: {exc}".strip()[:600],
        )
    if not doc:
        # Parses, but declares nothing. A zero-block file scans clean, which is exactly the
        # fail-open this package exists to eliminate — so it fails the gate, not passes it.
        return ValidityResult(
            ok=False,
            reason="empty_document",
            detail="HCL parsed but contains no blocks; an empty file scans clean and would "
            "be scored as a perfect remediation.",
        )
    return ValidityResult(ok=True, reason="parsed", detail=f"{len(doc)} top-level block types")


def _check_dockerfile(text: str) -> ValidityResult:
    for instruction, _args in _instructions(text):
        # ARG is the only instruction Docker permits before FROM (it parameterises the base
        # image), so leading ARGs are skipped rather than rejected.
        if instruction == "ARG":
            continue
        if instruction == "FROM":
            return ValidityResult(ok=True, reason="parsed", detail="first instruction is FROM")
        return ValidityResult(
            ok=False,
            reason="missing_from",
            detail=f"first instruction is {instruction!r}, expected FROM",
        )
    return ValidityResult(
        ok=False, reason="no_instructions", detail="no Dockerfile instructions found"
    )


def check_validity(
    path_or_text: str | Path, iac_type: IaCType | None = None
) -> ValidityResult:
    """Is this remediated file something a scanner can honestly be pointed at?

    Accepts a path or the raw content. `iac_type` may be omitted only when the source is a
    path, in which case it is detected from the filename.
    """
    kind = _resolve_type(path_or_text, iac_type)
    text = _read_source(path_or_text)

    if not text.strip():
        return ValidityResult(ok=False, reason="empty", detail="file is empty or whitespace")
    if _FENCE_RE.search(text):
        # Checked before parsing so the failure reads as "the model fenced its answer"
        # rather than as an inscrutable grammar error 400 characters long.
        return ValidityResult(
            ok=False,
            reason="markdown_fence",
            detail="output still contains markdown code-fence markers (```)",
        )

    if kind is IaCType.TERRAFORM:
        return _check_terraform(text)
    return _check_dockerfile(text)


# --------------------------------------------------------------------------------------
# gate 2: is it still the same infrastructure?
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class ResourceAddr:
    """A Terraform resource address, the unit `terraform state` tracks identity by."""

    type: str
    name: str

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"

    def __str__(self) -> str:
        return self.address


def extract_resources(
    text_or_path: str | Path, iac_type: IaCType | None = None
) -> list[ResourceAddr]:
    """List the resource addresses declared in a file, in document order.

    Dockerfiles have no addressable resources — an image is one artifact, not a set of
    independently-named objects — so this returns `[]` for them by design rather than by
    accident. Drift for Dockerfiles is therefore always empty; if that ever needs a
    metric it will need a different unit of identity (instructions, layers), not this one.

    python-hcl2 shapes a document as `{"resource": [{type: {name: {body}}}, ...]}`, one
    single-key dict per resource block.
    """
    kind = iac_type if iac_type is not None else _resolve_type(text_or_path, None)
    if kind is not IaCType.TERRAFORM:
        return []

    text = _read_source(text_or_path)
    try:
        doc = _load_hcl(text)
    except Exception as exc:
        raise ValidityError(f"could not parse HCL: {type(exc).__name__}: {exc}") from exc

    out: list[ResourceAddr] = []
    seen: set[str] = set()
    for block in doc.get("resource", []) or []:
        if not isinstance(block, dict):
            continue
        for rtype, bodies in block.items():
            if rtype.startswith("__") or not isinstance(bodies, dict):
                continue  # hcl2 injects __start_line__/__end_line__ metadata keys
            for rname in bodies:
                if rname.startswith("__"):
                    continue
                addr = ResourceAddr(str(rtype), str(rname))
                if addr.address not in seen:
                    seen.add(addr.address)
                    out.append(addr)
    return out


@dataclass
class DriftReport:
    """What changed about the *set of resources* between the original and the remediation.

    A rename is, definitionally, a deletion plus an addition, so a renamed resource appears
    in all three lists. `summary()` un-double-counts for display; `drift_touches_flaw()`
    unions them, so the overlap is harmless there.
    """

    deleted: list[ResourceAddr] = field(default_factory=list)
    added: list[ResourceAddr] = field(default_factory=list)
    renamed: list[tuple[ResourceAddr, ResourceAddr]] = field(default_factory=list)
    type_count_drops: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def drifted(self) -> bool:
        """Derived, not stored: a stored flag can disagree with the lists it summarises."""
        return bool(self.deleted or self.type_count_drops or self.renamed)

    def summary(self) -> str:
        renamed_from = {before.address for before, _ in self.renamed}
        renamed_to = {after.address for _, after in self.renamed}
        removed = [r for r in self.deleted if r.address not in renamed_from]
        introduced = [r for r in self.added if r.address not in renamed_to]

        parts: list[str] = []
        if removed:
            parts.append(f"deleted {', '.join(r.address for r in removed)}")
        if self.renamed:
            parts.append(
                "renamed "
                + ", ".join(f"{b.address} -> {a.address}" for b, a in self.renamed)
            )
        if introduced:
            parts.append(f"added {', '.join(r.address for r in introduced)}")
        if self.type_count_drops:
            parts.append(
                "count drops: "
                + ", ".join(
                    f"{t} {b}->{a}" for t, (b, a) in sorted(self.type_count_drops.items())
                )
            )
        if not parts:
            return "no resource drift"
        return ("DRIFT: " if self.drifted else "no drift; ") + "; ".join(parts)


def _by_type(resources: list[ResourceAddr]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for r in resources:
        grouped.setdefault(r.type, []).append(r.name)
    return grouped


def compute_drift(
    original: str | Path, remediated: str | Path, iac_type: IaCType
) -> DriftReport:
    """Compare the resource sets of a file before and after remediation."""
    before = extract_resources(original, iac_type)
    after = extract_resources(remediated, iac_type)

    before_addrs = {r.address for r in before}
    after_addrs = {r.address for r in after}
    report = DriftReport(
        deleted=[r for r in before if r.address not in after_addrs],
        added=[r for r in after if r.address not in before_addrs],
    )

    before_by_type = _by_type(before)
    after_by_type = _by_type(after)
    for rtype, before_names in before_by_type.items():
        after_names = after_by_type.get(rtype, [])
        if len(after_names) < len(before_names):
            report.type_count_drops[rtype] = (len(before_names), len(after_names))
            continue
        if len(after_names) != len(before_names):
            continue
        # Same count, but names moved: the resource still exists in shape and the model
        # merely relabelled it. Cheap to miss, expensive in practice — a rename destroys
        # and recreates on the next apply because `terraform state` keys on the address.
        gone = [n for n in before_names if n not in after_names]
        new = [n for n in after_names if n not in before_names]
        report.renamed.extend(
            (ResourceAddr(rtype, b), ResourceAddr(rtype, a)) for b, a in zip(gone, new)
        )

    return report


def _candidate_addresses(flagged: str) -> set[str]:
    """Normalise a scanner's resource string into the addresses it might mean.

    Both Checkov and Trivy emit a bare `type.name` for the fixtures here, but Checkov
    prefixes module-nested resources (`module.db.aws_db_instance.main`), so the trailing
    two segments are treated as a candidate too.
    """
    flagged = flagged.strip().rsplit(":", 1)[-1].strip()
    parts = flagged.split(".")
    out = {flagged}
    if len(parts) > 2:
        out.add(".".join(parts[-2:]))
    return out


def drift_touches_flaw(drift: DriftReport, flagged_resources: set[str]) -> list[str]:
    """Which resources that *carried findings* did the remediation delete or rename?

    This is the "fixed it by deleting it" detector, and the single most interesting number
    the project produces: a non-empty result means the finding count dropped because the
    resource stopped existing, not because it was secured. `flagged_resources` is the set
    of `Finding.resource` values from the pre-remediation scan.
    """
    lost = {r.address for r in drift.deleted}
    lost |= {before.address for before, _ in drift.renamed}
    return sorted(
        flagged
        for flagged in flagged_resources
        if flagged and _candidate_addresses(flagged) & lost
    )
