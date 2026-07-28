"""The evaluation CLI: `run`, `report`, `baseline`.

Three subcommands, each with a different cost, and the split is deliberate:

* ``baseline`` — scanners only. **No API key, no model, no network.** Establishes what
  Checkov and Trivy find on the originals with nothing else in the loop. This is the
  number the whole pipeline has to justify itself against, and its absence was the single
  biggest hole in the project's original report.
* ``report``   — recomputes every table from `eval/results/results.json` and the committed
  response cache. **No network and no scanner runs at all.** This is the command an
  interviewer runs to reproduce the published numbers for free.
* ``run``      — executes the pipeline. Cache-first and **fail-closed**: a cache miss is a
  hard error unless `--fresh` is passed. That is the same fail-closed principle
  `iac_agent.scanners` applies to scanner output, applied to spending money — the failure
  mode being designed out is a run that looks reproducible while quietly making live calls
  and producing a different answer for the next person.

**The cache is meant to be committed.** Cache key::

    sha256(model | prompt_version | temperature | seed | run_index | call_kind
           | variant | file_sha | prompt_sha)

`file_sha` is the fixture's bytes; `prompt_sha` is the exact rendered message list. The
assignment's key is the first seven components; `variant` and `prompt_sha` are added
because a stale entry served for a prompt it was not generated from is the classic
hand-rolled-LLM-cache bug, and `prompt_version` alone does not catch a changed *fixture*
inside an unchanged prompt template. Values are one JSON file per key holding the full raw
model response plus the metadata needed to interpret it.

Nothing secret can land in the cache: records are built from a fixed field allowlist that
is enforced on write (`ResponseCache.put`), and prompts are stored as a **hash**, never as
text. No environment, no client configuration, no API key — not even a redacted one.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from iac_agent.llm import LLMClient, LLMResponse, ModelConfig, TokenUsage
from iac_agent.scanners import get_scanner
from iac_agent.types import IaCType, LLMError, ScannerError, detect_iac_type
from iac_agent.validity import ValidityError, check_validity, compute_drift, drift_touches_flaw

from . import (
    ARTIFACT_DIR, BASELINE_JSON, CACHE_DIR, DEFAULT_VARIANT, DRIFT_DIR, RESULTS_DIR,
    RESULTS_JSON, RESULTS_MD, SAMPLES_DIR, SCANNER_NAMES, STRIPPED_DIR, VARIANTS,
    fixture_key, fixture_paths,
)
from . import labels_io, render, serialise, strip_comments
from . import metrics as M

RESULTS_SCHEMA_VERSION = 1
CACHE_SCHEMA_VERSION = 1

# Everything a cache record is permitted to contain. Enforced on write so that a future
# edit cannot casually widen it to include, say, "client_kwargs" — which is exactly how an
# API key ends up in a committed directory.
_CACHE_FIELDS = frozenset(
    "schema_version key call_kind model prompt_version temperature seed run_index variant "
    "fixture file_sha prompt_sha created_utc response usage system_fingerprint "
    "completion_source".split()
)

# The components of the cache key, in the order they are hashed. Reordering this line
# renames every entry in the committed cache, so it is written down once rather than
# re-typed at each call site.
_KEY_COMPONENTS = (
    "model", "prompt_version", "temperature", "seed", "run_index",
    "call_kind", "variant", "file_sha", "prompt_sha", "completion_source",
)

CALL_KINDS = ("detect", "fix")
LIVE_SOURCE = "openai"


class CacheMiss(LLMError):
    """The cache had no answer and nothing was authorised to produce one.

    A distinct type because it is a *configuration* failure, not a model failure. A model
    failure is per-run data and belongs in the record; a cache miss means the run cannot be
    performed at all, so it aborts the whole command with a non-zero exit rather than being
    absorbed into a results file that would then look like a completed evaluation.
    """


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path | None) -> dict[str, Any] | None:
    if path is None or not Path(path).is_file():
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: Path, doc: Mapping[str, Any]) -> None:
    """Every JSON artifact this module emits: `sort_keys` so a re-run diffs only real moves."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_results_md(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render.render_results_md(report), encoding="utf-8")


def print_table(rows: Sequence[Sequence[Any]], *, label_width: int, widths: Sequence[int]) -> None:
    """Left-aligned label column, right-aligned numerics, a rule the width of the header."""
    for index, row in enumerate(rows):
        line = f"{row[0]:<{label_width}} " + " ".join(
            f"{cell:>{width}}" for cell, width in zip(row[1:], widths)
        )
        print(line)
        if index == 0:
            print("-" * len(line))


def tool_version(binary: str) -> str:
    """Record the scanner versions in the results file.

    Rulesets change between releases, so an unpinned scanner makes the 70/57 baseline
    meaningless — a results table that does not say which Checkov produced it cannot be
    reproduced, and per this project's own history, tables that cannot be checked are the
    ones that turn out to be wrong.
    """
    candidate = Path(sys.executable).parent / binary
    exe = str(candidate) if candidate.is_file() else (shutil.which(binary) or "")
    if not exe:
        return "not found"
    try:
        proc = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable ({type(exc).__name__})"
    out = (proc.stdout or proc.stderr or "").strip().splitlines()
    if not out:
        return "unknown"
    first = out[0].strip()
    return first.split()[-1] if first.lower().startswith("version") else first


# --------------------------------------------------------------------------------------
# the completion path
# --------------------------------------------------------------------------------------


def cache_key(
    *, model: str, prompt_version: str, temperature: float, seed: int, run_index: int,
    call_kind: str, variant: str, file_sha: str, prompt_sha: str,
    completion_source: str = LIVE_SOURCE,
) -> str:
    """SHA-256 over everything that determines the response. See the module docstring.

    `completion_source` is in the key for a reason worth spelling out. `eval/fake_model.py`
    exists so the pipeline can be exercised offline, and it is invoked with the same
    `ModelConfig` as a real run — so without this component a fake response and a real one
    for the same fixture hash to the **same key**, and the cache cannot tell them apart. A
    later real run would then be served a canned answer and publish it as the model's, which
    is fabricated data wearing a reproducibility badge. Keying on the source puts injected
    and live completions in disjoint key spaces, so a fake entry can never be replayed as a
    real one and vice versa.
    """
    supplied = locals()
    payload = "|".join(f"{name}={supplied[name]}" for name in _KEY_COMPONENTS)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ResponseCache:
    """One JSON file per key, flat, intended to be committed to the repository.

    Committing it is a deliberate trade: repo noise in exchange for a reviewer with no
    OpenAI account being able to reproduce the published numbers exactly. The cache holds
    only model responses to prompts built from public fixtures.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or CACHE_DIR
        self.hits = 0
        self.misses = 0

    def path_for(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        path = self.path_for(key)
        if not path.is_file():
            self.misses += 1
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # A corrupt entry is a miss we must not swallow silently: served as an empty
            # response it would become an "the model found nothing" result.
            raise LLMError(f"cache entry {path.name} is unreadable: {exc}") from exc
        if not isinstance(record, dict) or not record.get("response"):
            raise LLMError(f"cache entry {path.name} has no response body")
        self.hits += 1
        return record

    def put(self, record: dict[str, Any]) -> Path:
        extra = set(record) - _CACHE_FIELDS
        if extra:
            raise ValueError(
                f"refusing to write cache fields {sorted(extra)}: the cache is committed "
                "to the repository and its field set is an allowlist"
            )
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(record["key"])
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path


def _accepted_optional_kwargs(fn: Callable[..., Any]) -> set[str]:
    """Which of `cfg` / `response_format` an injected completion function will accept."""
    optional = {"cfg", "response_format"}
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):
        return set()
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params):
        return optional
    named = (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    return {p.name for p in params if p.kind in named} & optional


_LIVE_CLIENT: LLMClient | None = None


def _live_complete(messages: list[dict[str, str]], cfg: ModelConfig, response_format: Any) -> Any:
    """The only code path in this package that can spend money. Reachable only via --fresh.

    It borrows `LLMClient._openai_complete` rather than calling the OpenAI SDK directly:
    that method already refuses a refusal string, refuses a `finish_reason == "length"`
    truncation, and accounts tokens. Re-implementing it here would create a second place
    for "a truncated file scored as a remediation" to live, which is precisely the class
    of bug this project exists to remove.
    """
    global _LIVE_CLIENT
    if _LIVE_CLIENT is None:
        _LIVE_CLIENT = LLMClient(cfg)
    return _LIVE_CLIENT._openai_complete(messages, cfg, response_format)


@dataclass
class CallContext:
    """Everything the cache key needs that the message list does not carry."""

    variant: str
    fixture: str
    file_sha: str
    run_index: int


@dataclass(kw_only=True, eq=False)
class CachingCompleter:
    """A `complete_fn` that answers from the committed cache and, only on `--fresh`, live.

    Sits between `LLMClient` and the model, so both cached and live responses go through
    exactly the same parsing, fence-stripping and validation code in `iac_agent.llm`. A
    replayed cache entry therefore exercises the real code path rather than a shortcut
    around it — which is what makes `report` a reproduction rather than a re-print.
    """

    cache: ResponseCache
    cfg: ModelConfig
    call_kind: str
    ctx: CallContext
    inner: Any = None
    allow_network: bool = False
    completion_source: str = LIVE_SOURCE
    calls: list[dict[str, Any]] = field(default_factory=list, init=False)
    _inner_kwargs: set[str] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        if self.call_kind not in CALL_KINDS:
            raise ValueError(f"unknown call kind {self.call_kind!r}")
        if self.inner is not None:
            self._inner_kwargs = _accepted_optional_kwargs(self.inner)

    def _note(self, key: str, *, hit: bool, live: bool, fingerprint: Any) -> None:
        """The per-call audit trail `metadata.live_calls` and the cache counters read."""
        self.calls.append(
            {"kind": self.call_kind, "key": key, "hit": hit, "live": live,
             "system_fingerprint": fingerprint}
        )

    def __call__(
        self, messages: list[dict[str, str]], cfg: ModelConfig | None = None,
        response_format: Any = None,
    ) -> LLMResponse:
        cfg = cfg or self.cfg
        prompt_sha = sha256_text(json.dumps(messages, sort_keys=True, ensure_ascii=False))
        # Built once and used twice: these are both what the key hashes and ten of the
        # seventeen fields of the record. Deriving the record from the same dict is what
        # stops an entry describing itself as something other than what it is filed under.
        components = {
            "model": cfg.model, "prompt_version": cfg.prompt_version,
            "temperature": cfg.temperature, "seed": cfg.seed,
            "run_index": self.ctx.run_index, "call_kind": self.call_kind,
            "variant": self.ctx.variant, "file_sha": self.ctx.file_sha,
            "prompt_sha": prompt_sha, "completion_source": self.completion_source,
        }
        key = cache_key(**components)

        hit = self.cache.get(key)
        if hit is not None:
            self._note(key, hit=True, live=False, fingerprint=hit.get("system_fingerprint"))
            usage = TokenUsage(**(hit.get("usage") or {}))
            return LLMResponse(text=str(hit["response"]), usage=usage)

        if self.inner is None and not self.allow_network:
            raise CacheMiss(
                f"cache miss for {self.call_kind} on {self.ctx.fixture} "
                f"({self.ctx.variant}, run {self.ctx.run_index}), key {key[:12]}…\n"
                "Refusing to make a live model call. Pass --fresh to authorise new calls "
                "(this costs money), or --complete-fn to inject a model, or run `report` "
                "to use only what is already cached."
            )

        if self.inner is not None:
            optional = {"cfg": cfg, "response_format": response_format}
            result = self.inner(
                messages, **{k: v for k, v in optional.items() if k in self._inner_kwargs}
            )
            live = False
        else:
            result = _live_complete(messages, cfg, response_format)
            live = True

        if isinstance(result, LLMResponse):
            text, usage = result.text, result.usage
        elif isinstance(result, str):
            text, usage = result, TokenUsage(calls=1)
        else:
            raise LLMError(
                f"completion function returned {type(result).__name__}, expected str or LLMResponse"
            )
        fingerprint = getattr(result, "system_fingerprint", None)

        self.cache.put(
            {
                # `prompt_sha` rides in as the hash, never the prompt text, and
                # `completion_source` is recorded as well as keyed so that
                # `ls eval/cache | xargs grep` answers "was this produced by the real
                # model?" without recomputing a hash.
                **components,
                "schema_version": CACHE_SCHEMA_VERSION, "key": key,
                "fixture": self.ctx.fixture, "created_utc": _now(),
                "response": text, "usage": usage.as_dict(),
                "system_fingerprint": fingerprint,
            }
        )
        self._note(key, hit=False, live=live, fingerprint=fingerprint)
        return LLMResponse(text=text, usage=usage)


# --------------------------------------------------------------------------------------
# corpus selection
# --------------------------------------------------------------------------------------


def resolve_fixtures(selector: str | None, samples_dir: Path | None = None) -> list[Path]:
    """`--fixtures s3_public,ec2_open.tf` or a path; empty means the whole corpus."""
    available = fixture_paths(samples_dir or SAMPLES_DIR)
    if not selector:
        return available
    chosen: list[Path] = []
    for want in [s.strip() for s in selector.split(",") if s.strip()]:
        name = Path(want).name
        match = next((p for p in available if p.name == name or p.stem == Path(name).stem), None)
        if match is None:
            names = ", ".join(p.name for p in available)
            raise SystemExit(f"unknown fixture {want!r}; available: {names}")
        chosen.append(match)
    return chosen


def variant_source(fixture: Path, variant: str) -> Path:
    if variant == "commented":
        return fixture
    if variant == "stripped":
        return STRIPPED_DIR / fixture.name
    raise SystemExit(f"unknown variant {variant!r}; expected one of {VARIANTS}")


def ensure_stripped_corpus(fixtures: Sequence[Path], quiet: bool = False) -> None:
    """Regenerate `eval/corpus/stripped/` unconditionally.

    Unconditionally, because a stale stripped variant is invisible: it parses, it scans,
    and it scores — against a fixture that no longer exists. Regeneration is milliseconds;
    the `--verify` invariant (identical scanner counts) is the expensive part and is run
    by `python -m eval.strip_comments --verify`, not on every eval run.
    """
    strip_comments.generate(list(fixtures))
    if not quiet:
        print(f"regenerated stripped corpus in {STRIPPED_DIR}")


def _variants(raw: str) -> list[str]:
    if raw == "both":
        return list(VARIANTS)
    chosen = [v.strip() for v in raw.split(",") if v.strip()]
    for v in chosen:
        if v not in VARIANTS:
            raise SystemExit(f"unknown variant {v!r}; expected one of {VARIANTS} or 'both'")
    return chosen


def _scanners(raw: str) -> tuple[str, ...]:
    chosen = tuple(s.strip().lower() for s in raw.split(",") if s.strip())
    for s in chosen:
        if s not in SCANNER_NAMES:
            raise SystemExit(f"unknown scanner {s!r}; expected some of {SCANNER_NAMES}")
    return chosen or SCANNER_NAMES


def corpus(args: argparse.Namespace) -> tuple[list[Path], list[str], tuple[str, ...]]:
    """`--fixtures / --variant / --scanner`, resolved identically for `run` and `baseline`.

    Shared so the two cannot disagree about what the corpus *is*: a baseline measured over
    a different fixture set than the run it is the denominator for gives a "% resolved"
    that compares two different populations.
    """
    fixtures = resolve_fixtures(args.fixtures)
    variants = _variants(args.variant)
    scanners = _scanners(args.scanner)
    if "stripped" in variants:
        ensure_stripped_corpus(fixtures)
    return fixtures, variants, scanners


def sweep(
    variants: Sequence[str], fixtures: Sequence[Path], repeats: int = 1
) -> Iterator[tuple[str, int, Path]]:
    """Every (variant, run_index, fixture) the harness works through, in write order.

    One generator rather than the same three nested loops per caller, because the order is
    load-bearing: `results.json` is committed and `runs` is a list, so re-ordering the same
    set of runs would diff as a change. Baseline collection is this sweep at one repeat.
    """
    for variant in variants:
        for run_index in range(repeats):
            for fixture in fixtures:
                yield variant, run_index, fixture


def scan_all(target: Path, kind: IaCType, scanners: Sequence[str]) -> dict[str, Any]:
    """Serialised results for every scanner on one file, keyed by scanner name."""
    return {n: serialise.scan_to_dict(get_scanner(n).scan(target, kind)) for n in scanners}


# --------------------------------------------------------------------------------------
# scanner-only baseline
# --------------------------------------------------------------------------------------


def collect_baseline(
    fixtures: Sequence[Path],
    variants: Sequence[str],
    scanners: Sequence[str],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Scan every (variant, fixture, scanner). No model, no key, no network."""
    out: dict[str, dict[str, dict[str, Any]]] = {v: {} for v in variants}
    for variant, _, fixture in sweep(variants, fixtures):
        source = variant_source(fixture, variant)
        out[variant][fixture_key(fixture)] = scan_all(source, detect_iac_type(source), scanners)
    return out


# --------------------------------------------------------------------------------------
# one pipeline run
# --------------------------------------------------------------------------------------


@dataclass
class RunConfig:
    cfg: ModelConfig
    cache: ResponseCache
    scanners: tuple[str, ...]
    allow_network: bool
    complete_fn: Any = None
    artifact_dir: Path = ARTIFACT_DIR
    drift_dir: Path = DRIFT_DIR
    completion_source: str = LIVE_SOURCE
    usage: TokenUsage = field(default_factory=TokenUsage)
    live_calls: int = 0
    fingerprints: set[str] = field(default_factory=set)

    def completer(self, call_kind: str, ctx: CallContext) -> CachingCompleter:
        """One place the cache/network wiring lives, so detect and fix cannot drift apart.

        `allow_network` above all: a build where the fix call could go live while the detect
        call could not would spend money on half a run and record it as if both halves came
        from the same place.
        """
        return CachingCompleter(
            cache=self.cache, cfg=self.cfg, call_kind=call_kind, ctx=ctx,
            inner=self.complete_fn, allow_network=self.allow_network,
            completion_source=self.completion_source,
        )


def run_one(fixture: Path, variant: str, run_index: int, rc: RunConfig) -> dict[str, Any]:
    """Detect, fix, validate, rescan, and measure drift for one fixture.

    Single-pass by design at this phase: the bounded refinement loop is a separate piece of
    work, and pretending it exists here would make the "loop vs no-loop" ablation compare a
    computation with itself. `attempts` is already a list so the loop can report every
    draft it discarded — validity measured only on *accepted* output is 100% by
    construction and says nothing about the model.
    """
    source = variant_source(fixture, variant)
    text = source.read_text(encoding="utf-8")
    file_sha = sha256_text(text)
    kind = detect_iac_type(source)
    key = fixture_key(fixture)

    record: dict[str, Any] = {
        "fixture": key, "variant": variant, "run_index": run_index,
        "iac_type": kind.value, "file_sha": file_sha,
        # Repo-relative: committed results are read on machines that are not this one, and an
        # absolute path bakes in a home directory and a username for no benefit.
        "source": serialise.rel_path(source),
        "llm_findings": [], "attempts": [], "calls": [], "error": None,
        "remediation_valid": False, "usage": TokenUsage().as_dict(),
        "before": {}, "after": {}, "after_is_before": False,
        "drift": None, "drift_touches_flaw": [],
    }

    before = scan_all(source, kind, rc.scanners)
    record["before"] = before

    ctx = CallContext(variant=variant, fixture=key, file_sha=file_sha, run_index=run_index)
    detect_completer = rc.completer("detect", ctx)
    fix_completer = rc.completer("fix", ctx)

    fixed: str | None = None
    try:
        detector = LLMClient(rc.cfg, complete_fn=detect_completer)
        findings = detector.detect_vulnerabilities(text, kind)
        record["llm_findings"] = findings

        fixer = LLMClient(rc.cfg, complete_fn=fix_completer)
        fixed = fixer.generate_fix(text, findings, kind)

        usage = TokenUsage()
        usage.add(detector.usage)
        usage.add(fixer.usage)
        record["usage"] = usage.as_dict()
        rc.usage.add(usage)
    except CacheMiss:
        # Not a run outcome. Abort the command rather than write a results file that
        # reads as a completed evaluation of a model that was never consulted.
        raise
    except LLMError as exc:
        # An LLM failure is recorded as a failure, never as an empty finding list or an
        # unchanged file that scores as "nothing to fix".
        record["error"] = f"{type(exc).__name__}: {exc}"

    # Accounted on both paths: a failed run still made calls, and a live call that went
    # unrecorded is money spent that the metadata does not admit to.
    record["calls"] = detect_completer.calls + fix_completer.calls
    _account(rc, record)
    if fixed is None:
        return _scored_against_itself(record, before)

    validity = check_validity(fixed, kind)
    out_dir = rc.artifact_dir / variant / f"run{run_index}" / fixture.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    # `IaCType.output_name` is load-bearing: both scanners select their Dockerfile rules by
    # FILENAME, so a remediated Dockerfile written as `fixed.tf` scans as Terraform, finds
    # nothing, and reports a clean pass. One directory per fixture keeps the required
    # filename while avoiding collisions.
    out_path = out_dir / kind.output_name
    out_path.write_text(fixed, encoding="utf-8")

    record["attempts"] = [
        {
            "index": 0, "valid": bool(validity), "reason": validity.reason,
            "detail": validity.detail, "output_sha": sha256_text(fixed),
        }
    ]
    record["remediation_valid"] = bool(validity)
    record["output_path"] = serialise.rel_path(out_path)

    if not validity:
        return _scored_against_itself(record, before)

    record["after"] = scan_all(out_path, kind, rc.scanners)

    flagged = {
        f["resource"] for scan in before.values() for f in scan["failed"] if f.get("resource")
    }
    try:
        drift = compute_drift(source, fixed, kind)
    except ValidityError as exc:
        # `drift` stays None, as initialised: an unparseable output is "drift unknown",
        # never "drift none", which would score a deletion as a clean fix.
        record["drift_error"] = str(exc)
        return record

    record["drift"] = serialise.drift_to_dict(drift)
    record["drift_touches_flaw"] = drift_touches_flaw(drift, flagged)
    return record


def _scored_against_itself(record: dict[str, Any], before: dict[str, Any]) -> dict[str, Any]:
    """A failed or unusable output resolved nothing: its `after` is its own `before`.

    The one shared answer for both ways a run can produce no file — the model errored, or
    it returned something that does not parse. Scoring either any other way, by dropping it
    from the corpus or by scanning a file that does not parse, flatters the delta with
    exactly the runs where the model failed hardest.
    """
    record["after"] = before
    record["after_is_before"] = True
    return record


def _account(rc: RunConfig, record: dict[str, Any]) -> None:
    for call in record["calls"]:
        if call.get("live"):
            rc.live_calls += 1
        if call.get("system_fingerprint"):
            rc.fingerprints.add(str(call["system_fingerprint"]))


def write_drift_reports(records: Sequence[dict[str, Any]], out_dir: Path = DRIFT_DIR) -> None:
    """One text file per output, so a reader can judge each drift event individually.

    A count of drift events is not actionable — deleting an `aws_s3_bucket_policy` that
    granted `Principal: "*"` is the correct fix and deleting the bucket is a disaster, and
    both are "one drift event". Naming the casualties is the only way to tell them apart.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        drift = record.get("drift")
        if not drift:
            continue
        lost = record.get("drift_touches_flaw") or []
        name = f"{Path(record['fixture']).stem}.{record['variant']}.run{record['run_index']}.txt"
        lines = [
            f"fixture : {record['fixture']}",
            f"variant : {record['variant']}  run: {record['run_index']}",
            f"summary : {drift['summary']}",
            f"drifted : {drift['drifted']}",
            f"deleted : {', '.join(drift['deleted']) or '-'}",
            f"renamed : {', '.join(f'{b} -> {a}' for b, a in drift['renamed']) or '-'}",
            f"added   : {', '.join(drift['added']) or '-'}",
            f"count drops: {drift['type_count_drops'] or '-'}",
            "",
            "flaw-carrying resources deleted or renamed (the 'fixed it by deleting it' set):",
            *(f"  - {r}" for r in lost),
        ]
        if not lost:
            lines.append("  (none)")
        (out_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------------------


def _load_complete_fn(spec: str | None) -> Any:
    """`--complete-fn package.module:attribute` — inject a model, or a fake.

    This is how the whole harness is exercised with no API key and no spend: a fake that
    returns canned strings goes through the identical parsing, validity, drift and scanner
    path as a real model.
    """
    if not spec:
        return None
    import importlib

    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise SystemExit("--complete-fn must be 'module:attribute'")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise SystemExit(f"could not import {module_name!r}: {exc}") from exc
    fn = getattr(module, attr, None)
    if fn is None or not callable(fn):
        raise SystemExit(f"{spec} is not callable")
    return fn


def document(
    cfg: ModelConfig, kind: str, *, fixtures: Sequence[Path], variants: Sequence[str],
    scanners: Sequence[str], **extra: Any,
) -> dict[str, Any]:
    """The `schema_version` + `metadata` envelope `results.json` and `baseline.json` share.

    Built in one place because the two files are read back by the *same* `metrics` code: a
    provenance field present in one and missing from the other is a report that silently
    describes only half of what it measured.
    """
    meta: dict[str, Any] = {
        "timestamp": _now(), "kind": kind,
        "model": cfg.model, "prompt_version": cfg.prompt_version,
        "temperature": cfg.temperature, "seed": cfg.seed, "max_tokens": cfg.max_tokens,
        "checkov_version": tool_version("checkov"), "trivy_version": tool_version("trivy"),
        "python_version": platform.python_version(), "platform": platform.platform(),
        "harness_schema_version": RESULTS_SCHEMA_VERSION,
        "variants": list(variants), "scanners": list(scanners),
        "fixtures": [fixture_key(f) for f in fixtures],
    }
    meta.update(extra)
    return {"schema_version": RESULTS_SCHEMA_VERSION, "metadata": meta}


def cmd_baseline(args: argparse.Namespace) -> int:
    """Scanner-only. Needs no API key; this is the floor everything else is measured against."""
    fixtures, variants, scanners = corpus(args)
    try:
        baseline = collect_baseline(fixtures, variants, scanners)
    except ScannerError as exc:
        print(f"scanner failure: {exc}", file=sys.stderr)
        return 2

    labelsets = labels_io.load_all_labels(fixtures)
    doc = document(
        ModelConfig(), "scanner-only baseline (no model was called)",
        fixtures=fixtures, variants=variants, scanners=scanners,
    )
    doc["baseline"] = baseline
    write_json(args.out, doc)

    exit_code = 0
    for variant in variants:
        scans = {
            f: {s: serialise.scan_from_dict(d) for s, d in per.items()}
            for f, per in baseline[variant].items()
        }
        summary = M.scanner_baseline(scans, labelsets)
        labels = summary["labels"]
        print(f"\n=== scanner-only baseline: variant={variant} ===")
        rows: list[list[Any]] = [["fixture", *scanners, "labels", "detectable"]]
        rows += [
            [f, *(scans[f][s].failed_count for s in scanners),
             len(labelsets[f]), len(labelsets[f].detectable)]
            for f in sorted(scans)
        ]
        rows.append(
            ["TOTAL", *(summary["per_scanner"][s]["findings"] for s in scanners),
             labels["total"], labels["detectable_by_scanner"]]
        )
        print_table(rows, label_width=max(len(f) for f in scans),
                    widths=[9] * len(scanners) + [7, 11])

        print("\nrecall against planted labels (same denominator the LLM is scored on):")
        for name in (*scanners, "union"):
            s = summary["per_scanner"].get(name)
            if not s:
                continue
            mapped = (
                f"   findings mapped to a label: {s['mapped_to_labels']}/{s['findings']}"
                if "mapped_to_labels" in s
                else ""
            )
            print(
                f"  {name:<8} labels detected {s['labels_detected']:>3}/{labels['total']:<3} "
                f"= {(s['recall_all_labels'] or 0) * 100:5.1f}%   "
                f"(detectable subset: {(s['recall_detectable_only'] or 0) * 100:5.1f}%){mapped}"
            )

        violations = labels_io.verify_label_ids(labelsets, scans)
        if violations:
            exit_code = 1
            print(f"\nLABEL ID VERIFICATION FAILED ({len(violations)}):", file=sys.stderr)
            for v in violations:
                print(f"  - {v}", file=sys.stderr)
        else:
            print("\nlabel id verification: passed (every non-empty id list has a live hit)")

    print(f"\nwrote {args.out}")
    return exit_code


def cmd_run(args: argparse.Namespace) -> int:
    fixtures, variants, scanners = corpus(args)
    cfg = ModelConfig(
        model=args.model or ModelConfig().model, temperature=args.temperature, seed=args.seed
    )
    complete_fn = _load_complete_fn(args.complete_fn)
    cache = ResponseCache(args.cache_dir)
    rc = RunConfig(
        cfg=cfg, cache=cache, scanners=scanners, complete_fn=complete_fn,
        allow_network=bool(args.fresh) and complete_fn is None,
        artifact_dir=args.artifact_dir, drift_dir=args.drift_dir,
        # Part of the cache key: an injected completion function and the live model must
        # never share a cache entry. See `cache_key`.
        completion_source=f"injected:{args.complete_fn}" if args.complete_fn else LIVE_SOURCE,
    )
    if rc.allow_network:
        print("--fresh: cache misses WILL make live model calls and cost money.", file=sys.stderr)

    records: list[dict[str, Any]] = []
    started = time.time()
    try:
        for variant, run_index, fixture in sweep(variants, fixtures, args.seeds):
            record = run_one(fixture, variant, run_index, rc)
            records.append(record)
            status = (
                "ERROR" if record["error"]
                else ("valid" if record["remediation_valid"] else "INVALID")
            )
            print(
                f"[{variant} run{run_index}] {record['fixture']:<32} "
                f"{len(record['llm_findings']):>3} findings  {status}"
            )
    except CacheMiss as exc:
        print(f"\ncache miss, and nothing was authorised to fill it:\n{exc}", file=sys.stderr)
        return 2
    except (LLMError, ScannerError) as exc:
        print(f"\n{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    baseline = collect_baseline(fixtures, variants, scanners)
    doc = document(
        cfg, "full pipeline run",
        fixtures=fixtures, variants=variants, scanners=scanners,
        repeats=args.seeds,
        cache_hits=cache.hits, cache_misses=cache.misses, live_calls=rc.live_calls,
        completion_source=args.complete_fn or ("openai" if rc.allow_network else "cache only"),
        system_fingerprints=sorted(rc.fingerprints),
        token_usage=rc.usage.as_dict(),
        wall_seconds=round(time.time() - started, 1),
        repeats_note=(
            "--seeds N repeats the run N times at a FIXED model seed; it is the "
            "cache-key run_index that varies, not ModelConfig.seed. The question "
            "being asked is how much the numbers move when nothing changes."
        ),
    )
    doc["baseline"] = baseline
    doc["runs"] = records
    write_json(args.out, doc)
    write_drift_reports(records, rc.drift_dir)
    print(
        f"\nwrote {args.out}  "
        f"(cache: {cache.hits} hits, {cache.misses} misses, {rc.live_calls} live calls)"
    )

    report = M.compute_report(doc, _read_json(args.baseline_json))
    write_results_md(args.results_md, report)
    print(f"wrote {args.results_md}")

    # A run in which the model failed is not a successful run, even though its per-record
    # failures were captured honestly. Exiting 0 here is how a broken pipeline gets into
    # CI green — the exact shape of the defect this project was rebuilt to remove.
    failed = [r for r in records if r["error"]]
    if failed:
        print(f"\n{len(failed)} of {len(records)} runs failed at the model step:", file=sys.stderr)
        for r in failed:
            print(
                f"  - {r['fixture']} [{r['variant']} run{r['run_index']}]: {r['error']}",
                file=sys.stderr,
            )
        return 3
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Regenerate every table from stored raw data. No network, no scanners, no model."""
    results = _read_json(args.results)
    baseline = _read_json(args.baseline_json)
    if results is None and baseline is None:
        print(
            f"nothing to report: neither {args.results} nor {args.baseline_json} exists.\n"
            "Run `baseline` (free, no API key) or `run` first.",
            file=sys.stderr,
        )
        return 1

    report = M.compute_report(results, baseline)
    write_results_md(args.out, report)

    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")

    for warning in report.get("warnings") or []:
        print(f"note: {warning}")
    for violation in report.get("label_id_violations") or []:
        print(f"LABEL ID VIOLATION: {violation}", file=sys.stderr)
    print(f"wrote {args.out}")
    return 1 if report.get("label_id_violations") else 0


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m eval.run_eval",
        description=(
            "Evaluation harness. `baseline` needs no API key, `report` needs no network, "
            "and only `--fresh` can spend money."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        """The corpus selectors `run` and `baseline` share, wired once."""
        p.add_argument("--scanner", default=",".join(SCANNER_NAMES),
                       help="comma-separated scanners (default: checkov,trivy)")
        p.add_argument("--fixtures", default="",
                       help="comma-separated fixture names or stems; default is the whole corpus")
        p.add_argument("--variant", default=DEFAULT_VARIANT,
                       help="commented | stripped | both. Headline detection numbers are reported "
                            "on 'stripped'; 'commented' exists to measure label leakage "
                            "(default: stripped)")

    p_run = sub.add_parser("run", help="execute the pipeline, honouring the cache")
    common(p_run)
    p_run.add_argument("--seeds", type=int, default=1,
                       help="number of repeat runs. Repeats are reported as mean [min, max] — "
                            "descriptive statistics only; n is far too small for confidence "
                            "intervals")
    p_run.add_argument("--fresh", action="store_true",
                       help="authorise LIVE model calls on a cache miss. Costs money. Without it "
                            "a miss is a hard error (fail closed)")
    p_run.add_argument("--model", default=None, help="model snapshot id (never a floating alias)")
    p_run.add_argument("--temperature", type=float, default=ModelConfig().temperature)
    p_run.add_argument("--seed", type=int, default=ModelConfig().seed)
    p_run.add_argument("--complete-fn", default=None, metavar="module:attr",
                       help="inject a completion function instead of calling OpenAI. With this "
                            "set, no network call is possible")
    p_run.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    p_run.add_argument("--artifact-dir", type=Path, default=ARTIFACT_DIR)
    p_run.add_argument("--drift-dir", type=Path, default=DRIFT_DIR)
    p_run.add_argument("--out", type=Path, default=RESULTS_JSON)
    p_run.add_argument("--baseline-json", type=Path, default=BASELINE_JSON)
    p_run.add_argument("--results-md", type=Path, default=RESULTS_MD)
    p_run.set_defaults(func=cmd_run)

    p_base = sub.add_parser(
        "baseline",
        help="scanner-only floor: what checkov and trivy find with no LLM (no API key needed)",
    )
    common(p_base)
    p_base.add_argument("--out", type=Path, default=BASELINE_JSON)
    p_base.set_defaults(func=cmd_baseline)

    p_report = sub.add_parser(
        "report", help="regenerate RESULTS.md from stored results and the committed cache"
    )
    p_report.add_argument("--results", type=Path, default=RESULTS_JSON)
    p_report.add_argument("--baseline-json", type=Path, default=BASELINE_JSON)
    p_report.add_argument("--out", type=Path, default=RESULTS_MD)
    p_report.add_argument(
        "--json", type=Path, default=None, help="also dump the computed report as JSON"
    )
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
