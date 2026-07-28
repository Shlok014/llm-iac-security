"""Deciding whether two strings written by different authors name the same thing.

Nothing in the detection metric is harder than this and nothing in it is weaker, so it is
isolated here where it can be read and disputed on its own. A label is hand-written, a
scanner emits its own address format, and an LLM writes prose; recall and precision are
both entirely determined by how generously those three are reconciled.

The reconciliation is two independent tests ANDed together — a *resource* test
(`resource_matches`) and a *semantic* test (`semantic_matches`) — and the conjunction is
what makes each half safe to keep loose. Neither alone may promote a finding to a true
positive. `_content_tokens` is the third, weakest layer, used only to guess whether an
unmatched finding is describing something real; a hand adjudication overrides it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Mapping

from iac_agent.types import IaCType

if TYPE_CHECKING:  # a type-only import: matching must stay importable *before* labels_io
    from .labels_io import Label


# --------------------------------------------------------------------------------------
# resource matching
# --------------------------------------------------------------------------------------

_DOCKER_INSTRUCTIONS = frozenset(
    {
        "FROM", "RUN", "CMD", "LABEL", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
        "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK",
        "SHELL", "MAINTAINER",
    }
)

_RESOURCE_KEYWORD_RE = re.compile(r"^(resource|data|module|variable|output|provider)\s+", re.I)
_QUOTED_SEGMENTS_RE = re.compile(r'"([^"]+)"')

# Terraform's own abbreviations. A model writes `variable "api_key"`; the label writes
# `var.api_key`; both name the same object and neither spelling is wrong.
_PREFIX_ALIASES = {"variable": "var", "local": "local", "data": "data"}


def resource_candidates(raw: str) -> set[str]:
    """Every canonical spelling a resource string might mean.

    Returns a *set* rather than one string because the same address is written four ways
    in this project's inputs: `aws_s3_bucket.example` (both scanners),
    `resource "aws_s3_bucket" "example"` (an LLM quoting the file),
    `module.db.aws_db_instance.main` (Checkov, for module-nested resources), and
    `variable "api_key"` for a label spelled `var.api_key`.
    """
    text = " ".join(str(raw or "").split()).strip().strip("`").lower()
    if not text:
        return set()

    prefix = ""
    m = _RESOURCE_KEYWORD_RE.match(text)
    if m:
        keyword = m.group(1).lower()
        text = text[m.end():].strip()
        if keyword in _PREFIX_ALIASES:
            prefix = _PREFIX_ALIASES[keyword]

    quoted = _QUOTED_SEGMENTS_RE.findall(text)
    if quoted:
        text = ".".join(quoted)
    text = text.replace('"', "").replace("'", "").strip()
    text = re.sub(r"\s*\.\s*", ".", text)
    text = re.sub(r"\s+", ".", text)
    if prefix and not text.startswith(prefix + "."):
        text = f"{prefix}.{text}"

    out = {text}
    parts = [p for p in text.split(".") if p]
    if len(parts) > 2:
        # Checkov prefixes module-nested resources; the trailing two segments are the
        # address a label and a model both write.
        out.add(".".join(parts[-2:]))
    if len(parts) == 2:
        out.update(parts)  # allow a bare type or a bare name to match — see below
    return {p for p in out if p}


def terraform_resource_matches(finding_resource: str, label_resource: str) -> bool:
    """Do two Terraform resource strings name the same object?

    Deliberately generous: a finding whose `resource` is just `bad_rds` matches the label
    `aws_db_instance.bad_rds`. The generosity is safe *only because* it is ANDed with the
    alias test in `semantic_matches` — resource matching alone never promotes a finding to
    a true positive. Loosening this without that conjunct would inflate recall and
    precision simultaneously.
    """
    a, b = resource_candidates(finding_resource), resource_candidates(label_resource)
    return bool(a and b and (a & b))


def _docker_instruction(raw: str) -> str | None:
    head = " ".join(str(raw or "").split()).split(" ", 1)[0].upper().strip(":,")
    return head if head in _DOCKER_INSTRUCTIONS else None


def dockerfile_resource_matches(finding_resource: str, label_resource: str) -> bool:
    """A **contradiction test**, not an equality test.

    A Dockerfile has no addressable resources — `iac_agent.validity.extract_resources`
    returns `[]` for them by design — so there is no stable identity to compare. Labels
    use the instruction plus enough argument to identify it (`EXPOSE 22`,
    `RUN chmod 777 /app/data`) or the pseudo-resource `image` for whole-image properties,
    while a model may answer `Dockerfile`, `image`, `line 26`, or nothing useful at all.

    So the rule is: a match is allowed unless the two name *different instructions*. A
    finding about `RUN pip install` cannot satisfy a label about `EXPOSE 22`, but a
    finding with an unrecognisable resource is decided entirely by the alias test. This
    is looser than the Terraform path and it is the weakest joint in the detection metric;
    it is recorded as such rather than dressed up.
    """
    lab = _docker_instruction(label_resource)
    fnd = _docker_instruction(finding_resource)
    if lab is None or fnd is None:
        return True
    return lab == fnd


def resource_matches(finding_resource: str, label: Label) -> bool:
    if label.framework is IaCType.DOCKERFILE:
        return dockerfile_resource_matches(finding_resource, label.resource)
    return terraform_resource_matches(finding_resource, label.resource)


# --------------------------------------------------------------------------------------
# semantic matching
# --------------------------------------------------------------------------------------

_QUOTE_CHARS = str.maketrans({"'": '"', "‘": '"', "’": '"', "“": '"', "”": '"'})


def normalise_text(text: str) -> str:
    """Fold the spelling differences that are not semantic differences.

    An alias of `acl = "public-read"` has to match a model that wrote `acl="public-read"`
    or `acl = 'public-read'`. Quote style and spacing around `=` carry no meaning here,
    so both sides are folded before the substring test.
    """
    s = " ".join(str(text or "").split()).lower().translate(_QUOTE_CHARS)
    return re.sub(r"\s*=\s*", "=", s)


def semantic_matches(finding: Mapping[str, Any], label: Label) -> str | None:
    """Does the finding's prose contain one of the label's alias phrasings?

    Returns the alias that matched, or None.

    **This is the weak point of the whole detection metric and it is stated, not hidden.**
    Substring matching against a hand-written vocabulary misses a correct finding phrased
    in a way the label author did not anticipate, and such a miss costs twice: once as a
    false negative on the label, once as a false positive on the finding. The two controls
    are that aliases were written before any result was looked at, and that every unmatched
    finding goes through adjudication where a phrasing miss is caught — and an amended
    alias list always forces a full rerun, so no number is ever produced by a vocabulary
    that was tuned against it.
    """
    haystack = normalise_text(
        f"{finding.get('issue', '')} {finding.get('recommendation', '')} {finding.get('resource', '')}"
    )
    for alias in label.aliases:
        needle = normalise_text(alias)
        if needle and needle in haystack:
            return alias
    return None


# --------------------------------------------------------------------------------------
# content-word overlap — the plausibility heuristic's raw material
# --------------------------------------------------------------------------------------

# Words that carry no discriminating signal when deciding whether an unmatched LLM finding
# is describing the same thing as an unlabelled scanner finding.
_STOPWORDS = frozenset(
    """a an the is are be being been to of in on for with without and or not no nor that
    this these those it its as at by from should must ensure make sure has have had can
    could may might will would you your there their which when where any all use used
    using set configured configure enabled enable disabled disable""".split()
)


_SUFFIXES = ("ations", "ation", "ising", "izing", "ised", "ized", "ing", "ion", "ed", "es", "s")


def _stem(word: str) -> str:
    """Crudest possible suffix stripping, and that is the right amount here.

    Without it the token overlap test compares `encryption` to `encrypted` and `bucket` to
    `buckets` and finds nothing in common — measured: the LLM finding "Bucket has no
    server-side encryption" shared only `kms` with Checkov's "Ensure that S3 buckets are
    encrypted with KMS by default", so a correct observation about a real unlabelled flaw
    was scored as a hallucination. A real stemmer would be a new dependency for a
    heuristic that a hand-written adjudication file overrides anyway.
    """
    for suffix in _SUFFIXES:
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


_STOPWORD_STEMS = _STOPWORDS | {_stem(w) for w in _STOPWORDS}


def _content_tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9_]+", normalise_text(text))
    stems = {_stem(w) for w in words if len(w) > 2}
    return {s for s in stems if s not in _STOPWORD_STEMS and len(s) > 2}
