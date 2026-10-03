"""Command line entry point: `iac-agent scan`, `iac-agent fix`, `iac-agent version`.

**Exit codes carry the fail-closed contract out of the process.** Inside the package "the
scanner could not run" is a `ScannerError` and can never be mistaken for "no issues found",
and that guarantee is worth nothing if the CLI collapses every non-success into exit 1: a CI
job reading non-zero as "findings exist" would report a crashed scanner as a security
finding, and one checking only for 0 would be accidentally right until someone appends
`|| true`. So:

    0  we looked, and it is clean
    1  we looked, and there are findings
    2  we could not look (ScannerError / UnsupportedFileError / ValidityError)
    3  the model layer failed (LLMError) — only reachable from `fix`

Exit 2 is reserved for *the tooling failed*, never for *findings exist*.

**`scan` must stay key-free.** It imports `scanners.py` and nothing from `llm.py` or
`loop.py`; those are imported lazily inside `fix`. That is what makes the scan path runnable
in CI, in a fork, and by a reader with no API key — and it is the honest starting point, since
the scanner output is the ground truth the LLM half is measured against.

`loop.py` is reached through an adapter (`_call_run_loop`, `_LoopView`) that introspects its
signature and reads its result defensively: the two modules were written in parallel against
a prose contract, and a CLI hard-coding one spelling of `workdir` would break on a synonym
rather than on a real disagreement.
"""

from __future__ import annotations

import argparse
import inspect
import json
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

from . import __version__
from .scanners import get_scanner
from .types import (
    Finding,
    IaCAgentError,
    IaCType,
    LLMError,
    ScanResult,
    ScannerError,
    UnsupportedFileError,
    detect_iac_type,
)

EXIT_OK, EXIT_FINDINGS, EXIT_TOOLING, EXIT_LLM = 0, 1, 2, 3
PROG = "iac-agent"

# Rank for display ordering and for `--fail-on`. Checkov's community edition returns no
# severity at all (the field is populated by the commercial platform), so "unknown" is the
# common case for Terraform policy checks and must sort last without being dropped.
_SEVERITY_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_UNKNOWN_RANK = 4

# Directories that never contain reviewable IaC but often contain thousands of files —
# `.terraform` in particular vendors whole provider repos, including their test fixtures.
_SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", ".terraform", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", "site-packages", "dist", "build",
})

_FINDING_FIELDS = ("rule_id", "severity", "resource", "message", "scanner", "file", "line",
                   "guideline")


# --- target discovery --------------------------------------------------------------------

def iter_targets(path: Path) -> list[Path]:
    """Resolve a CLI path argument to the files we will actually scan.

    A file is routed through `detect_iac_type`, so naming an unsupported file is an error
    (exit 2) rather than a silent no-op. A *directory* is walked and unsupported files are
    skipped, because "scan this repo" plainly does not mean "fail on the README"."""
    if path.is_file():
        detect_iac_type(path)  # raises UnsupportedFileError -> exit 2
        return [path]
    if path.is_dir():
        found = list(_walk(path))
        if not found:
            # Fail closed. An empty result here means "we scanned nothing", and reporting
            # that as exit 0 would be the same lie as reporting an empty scanner output as
            # a clean pass — the exact bug this package exists to remove.
            raise UnsupportedFileError(
                f"no Terraform (*.tf) or Dockerfile targets under {path}. "
                "Refusing to exit 0: scanning nothing is not a clean result."
            )
        return sorted(found)
    raise UnsupportedFileError(f"no such file or directory: {path}")


def _collect(raw_paths: Sequence[str]) -> list[Path]:
    """Resolve several path arguments to one de-duplicated target list.

    Multiple paths exist for one caller: a CI job passing the changed files of a pull request.
    Each is resolved independently, so an unreadable or empty one is still an error rather
    than being quietly dropped from the batch."""
    seen: set[Path] = set()
    targets: list[Path] = []
    for raw in raw_paths:
        for target in iter_targets(Path(raw)):
            if target.resolve() not in seen:
                seen.add(target.resolve())
                targets.append(target)
    return targets


def _walk(root: Path) -> Iterator[Path]:
    """Every supported IaC file under `root`; unsupported ones are skipped, not an error."""
    for child in sorted(root.iterdir()):
        if child.is_dir():
            if child.name not in _SKIP_DIRS and not child.name.startswith("."):
                yield from _walk(child)
        elif child.is_file():
            try:
                detect_iac_type(child)
            except UnsupportedFileError:
                continue
            yield child


# --- rendering ---------------------------------------------------------------------------

def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get((severity or "").lower(), _UNKNOWN_RANK)


def _sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_severity_rank(f.severity), f.rule_id, f.resource))


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {name: getattr(f, name) for name in _FINDING_FIELDS}


def _severity_histogram(findings: Iterable[Finding]) -> dict[str, int]:
    hist = Counter((f.severity or "unknown").lower() for f in findings)
    return dict(sorted(hist.items(), key=lambda kv: (_severity_rank(kv[0]), kv[0])))


def _clip(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: max(1, width - 1)] + "…"


def _render_table(result: ScanResult, out) -> None:
    """One scanner's findings for one file, as aligned columns. Widths come from the data,
    but the message column absorbs whatever is left of the terminal: rule ids and resource
    addresses are what a reader greps for, so they are never the ones truncated."""
    rows = [
        (f.severity or "unknown", f.rule_id, str(f.line) if f.line else "-", f.resource or "-",
         f.message or "")
        for f in _sorted_findings(result.failed)
    ]
    if not rows:
        return
    headers = ("SEVERITY", "RULE", "LINE", "RESOURCE")
    widths = [min(40, max(len(h), *(len(r[i]) for r in rows))) for i, h in enumerate(headers)]
    terminal = max(80, min(shutil.get_terminal_size((100, 24)).columns, 200))
    message_width = max(20, terminal - sum(widths) - 2 * len(widths) - 4)

    print(f"  {'  '.join(h.ljust(w) for h, w in zip(headers, widths))}  CHECK", file=out)
    for row in rows:
        cells = [_clip(v, w).ljust(w) for v, w in zip(row[:-1], widths)]
        print(f"  {'  '.join(cells)}  {_clip(row[-1], message_width)}", file=out)


def _emit_json(doc: dict[str, Any]) -> None:
    """The machine-readable document, and nothing else, on stdout — diagnostics go to stderr
    under `--json` so the document stays pipeable."""
    json.dump(doc, sys.stdout, indent=2, sort_keys=False, default=str)
    sys.stdout.write("\n")


# --- scan ----------------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    """Scanner-only path. No model, no API key, no import of `llm.py`."""
    out = sys.stderr if args.json else sys.stdout
    targets = _collect(args.path)
    scanner_names = ["checkov", "trivy"] if args.scanner == "both" else [args.scanner]

    documents: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    all_findings: list[Finding] = []

    for target in targets:
        kind = detect_iac_type(target)
        scans: list[dict[str, Any]] = []
        print(f"\n{target}  [{kind.value}]", file=out)
        for name in scanner_names:
            try:
                result = get_scanner(name).scan(target, iac_type=kind)
            except ScannerError as exc:
                # Recorded, not raised, so one broken scanner does not hide the findings the
                # other one produced. The run still exits 2 — see the exit-code decision
                # below: a partial look is not a clean look.
                errors.append({"file": str(target), "scanner": name, "error": str(exc)})
                print(f"  {name}: SCANNER ERROR: {_clip(str(exc), 300)}", file=out)
                continue
            all_findings.extend(result.failed)
            scans.append({
                "scanner": result.scanner, "failed": result.failed_count,
                "passed": result.passed_count, "parse_errors": result.parse_errors,
                "findings": [_finding_dict(f) for f in _sorted_findings(result.failed)],
            })
            if not args.json:
                _render_table(result, out)
            print(
                f"  {name}: {result.failed_count} failed, {result.passed_count} passed"
                + ("" if result.parsed_cleanly else f", {result.parse_errors} parse errors"),
                file=out,
            )
        documents.append({"file": str(target), "iac_type": kind.value, "scans": scans})

    failed_total = len(all_findings)
    # Distinct (rule_id, resource) pairs: with `--scanner both` the same misconfiguration is
    # frequently reported by both tools, and adding the two totals overstates the problem.
    distinct = len({f.key() for f in all_findings})
    by_severity = _severity_histogram(all_findings)
    gate_hits = _gate_hits(all_findings, args.fail_on)
    code = EXIT_TOOLING if errors else (EXIT_FINDINGS if gate_hits else EXIT_OK)

    if args.json:
        _emit_json({
            "command": "scan", "version": __version__, "requested": list(args.path),
            "targets": documents, "errors": errors,
            "summary": {
                "files_scanned": len(targets), "scanners": scanner_names,
                "failed_total": failed_total, "distinct_findings": distinct,
                "by_severity": by_severity, "scanner_errors": len(errors),
                "fail_on": args.fail_on, "gate_hits": len(gate_hits),
            },
            "exit_code": code,
        })
        return code

    print(f"\n{len(targets)} file(s), {failed_total} finding(s) "
          f"({distinct} distinct) from {', '.join(scanner_names)}", file=out)
    if by_severity:
        print("  by severity: " + ", ".join(f"{k}={v}" for k, v in by_severity.items()), file=out)
    if errors:
        print(f"\n{len(errors)} scanner error(s): exiting {EXIT_TOOLING} "
              "(a scanner that could not run is not a clean result)", file=out)
    elif code == EXIT_OK and failed_total:
        print(f"  no finding met the --fail-on {args.fail_on} threshold; exiting 0", file=out)
    return code


def _gate_hits(findings: Iterable[Finding], fail_on: str) -> list[Finding]:
    """Findings severe enough to justify exit 1 under `--fail-on`.

    `any` (the default) preserves the documented contract. A threshold is opt-in for CI gating
    and deliberately excludes `unknown`: Checkov CE emits no severities, so treating unknown
    as critical would make `--fail-on critical` identical to `--fail-on any` for Terraform.
    """
    if fail_on == "none":
        return []
    findings = list(findings)
    if fail_on == "any":
        return findings
    threshold = _SEVERITY_RANK[fail_on]
    return [f for f in findings if _severity_rank(f.severity) <= threshold]


# --- fix: the loop adapter -----------------------------------------------------------------

# Logical argument -> the parameter names `run_loop` might spell it with. Resolved against
# the real signature at call time; see the module docstring for why.
_LOOP_ALIASES: dict[str, tuple[str, ...]] = {
    "scanner": ("scanner",), "client": ("client", "llm", "llm_client"),
    "cfg": ("cfg", "config", "model_config"), "iac_type": ("iac_type",),
    "max_iters": ("max_iters", "max_iterations"), "token_budget": ("token_budget",),
    "output_dir": ("output_dir", "workdir", "out_dir", "outdir"),
    "on_iteration": ("on_iteration", "progress", "progress_cb", "callback"),
}


def _call_run_loop(run_loop: Callable[..., Any], path: Path, values: dict[str, Any]) -> Any:
    """Invoke `run_loop` with only the keyword arguments it actually declares.

    Passing an argument the callee does not accept is a `TypeError` that reads like a bug in
    the loop; omitting one it needs is silently wrong. Introspection makes the mismatch visible
    here, and a callee taking `**kwargs` gets the canonical spellings."""
    try:
        params = inspect.signature(run_loop).parameters
    except (TypeError, ValueError):  # not introspectable; send the canonical names
        params = {}

    takes_var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
    kwargs: dict[str, Any] = {}
    for logical, names in _LOOP_ALIASES.items():
        if logical not in values or values[logical] is None:
            continue
        target = next((n for n in names if n in params), None)
        if target is None and takes_var_kw:
            target = names[0]
        if target is not None:
            kwargs[target] = values[logical]
    return run_loop(path, **kwargs)


def _first_attr(obj: Any, names: Sequence[str], default: Any = None) -> Any:
    return next((v for v in (getattr(obj, n, None) for n in names) if v is not None), default)


def _typed(obj: Any, name: str, kind: type | tuple[type, ...], default: Any = None) -> Any:
    """`getattr` that yields `default` unless the value has the expected type. The loop
    contract permits a sentinel for a number it could not produce, so a wrong-typed value
    means "not reported" and must fall through to the derivation, never be coerced."""
    value = getattr(obj, name, None)
    return value if isinstance(value, kind) else default


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))


class _LoopView:
    """Read a `LoopResult` without depending on which of two spellings it uses.

    Every field has a primary source and a derivation from the object graph, so a result
    exposing `baseline_failed` and one exposing `baseline.failed_count` render identically.
    Nothing here invents a number: a field we cannot find stays `None` and is reported as
    unknown rather than as zero."""

    def __init__(self, result: Any) -> None:
        self.raw = result
        self.best = _first_attr(result, ("best", "best_iteration"))
        self.baseline_scan: ScanResult | None = _typed(result, "baseline", ScanResult)
        self.stop_reason: str = _enum_value(_first_attr(result, ("stop_reason",), "unknown"))
        self.total_tokens: int = int(_typed(result, "total_tokens", int, 0))
        self.iterations: list[Any] = list(_typed(result, "iterations", (list, tuple), ()))
        self.aborted_because = str(getattr(result, "aborted_because", "") or "")
        self.drift_gate_note = str(getattr(result, "drift_gate_note", "") or "")
        self.output_path = Path(p) if (p := getattr(result, "output_path", None)) else None
        # Did any candidate survive both gates and get rescanned? Defaults to True when the
        # loop does not expose it, so an unknown result is never reported as "the model
        # produced nothing".
        self.accepted_any: bool = _typed(result, "accepted_any", bool, True)

        self.baseline_failed: int | None = _typed(result, "baseline_failed", int)
        if self.baseline_failed is None:
            self.baseline_failed = getattr(self.baseline_scan, "failed_count", None)
        self.final_failed: int | None = _typed(result, "final_failed", int)
        if self.final_failed is None:
            self.final_failed = _iteration_failed(self.best)
        self.best_code: str | None = _typed(result, "best_code", str)
        if self.best_code is None:
            self.best_code = _typed(self.best, "code", str)

    def best_label(self) -> str:
        if self.best is None:
            return "unknown"
        if not getattr(self.best, "index", None):  # index 0 is the loop's synthetic baseline
            # A clean baseline and an all-rejected run both return the original file, but for
            # opposite reasons, and conflating them would misreport an aborted run as a file
            # that needed nothing. The baseline count is what tells them apart.
            if self.baseline_failed == 0:
                return "the input unchanged (already clean — the model was never called)"
            return "baseline (no candidate passed the gates)"
        return f"iter {self.best.index}"

    def keyset(self, name: str) -> list[list[str]]:
        """`resolved` / `introduced` as sorted JSON-safe pairs."""
        pairs = _typed(self.raw, name, (set, frozenset, list, tuple), ())
        return sorted([str(a), str(b)] for a, b in pairs)

    def drift(self) -> Any:
        return _first_attr(self.raw, ("drift", "drift_report")) or getattr(self.best, "drift", None)


def _iteration_failed(record: Any) -> int | None:
    """Failed-check count of one iteration, or None when it was never scanned. A rejected
    candidate has no scan, and the difference between "0 findings" and "never looked" is the
    whole thesis of the package — so this returns None rather than 0."""
    if record is None:
        return None
    scan = _typed(record, "scan", ScanResult)
    if scan is not None:
        return scan.failed_count
    count = getattr(record, "failed_count", None)
    # A sentinel for "no scan" is permitted by the loop contract; only trust a real count.
    return count if isinstance(count, int) and count >= 0 else None


def _iteration_label(index: int, record: Any) -> str:
    count = _iteration_failed(record)
    if getattr(record, "accepted", True) and count is not None:
        return f"iter {index}: {count}"
    reason = str(getattr(record, "rejected_because", "") or "rejected").strip()
    return f"iter {index}: rejected ({_clip(reason, 60)})"


def _iteration_document(index: int, record: Any) -> dict[str, Any]:
    return {
        "index": int(getattr(record, "index", index) or index),
        "accepted": bool(getattr(record, "accepted", False)),
        "failed": _iteration_failed(record),
        "rejected_because": str(getattr(record, "rejected_because", "") or ""),
        "validity": _enum_value(getattr(getattr(record, "validity", None), "reason", "") or ""),
        "prompt_tokens": int(getattr(record, "prompt_tokens", 0) or 0),
        "completion_tokens": int(getattr(record, "completion_tokens", 0) or 0),
    }


# --- fix: command ---------------------------------------------------------------------------

def cmd_fix(args: argparse.Namespace) -> int:
    """Full detect -> fix -> validate -> rescan loop. Requires a model."""
    out = sys.stderr if args.json else sys.stdout
    path = Path(args.path)
    if path.is_dir():
        raise UnsupportedFileError(
            f"{path} is a directory. `fix` takes one file — the loop's before/after "
            "arithmetic is per-file. Use `scan` for directories."
        )
    iac_type = detect_iac_type(path)  # fail before any spend

    # Imported here, not at module import: `scan` must never pull in the model layer, and a
    # missing/partial loop module must not break `iac-agent scan` or `--help`.
    try:
        from .llm import LLMClient, ModelConfig
        from .loop import run_loop
    except ImportError as exc:
        raise IaCAgentError(
            f"the fix loop is unavailable in this install ({exc}). "
            "`iac-agent scan` does not require it."
        ) from exc

    cfg = ModelConfig(model=args.model) if args.model else ModelConfig()
    client = LLMClient(cfg=cfg)

    # A dry run still needs somewhere to write candidates — the scanner reads files, and the
    # filename it reads is load-bearing (IaCType.output_name). The difference is that the
    # directory is temporary and is discarded, so nothing the user can see is touched.
    tmpdir = tempfile.TemporaryDirectory(prefix="iac-agent-") if not args.out else None
    output_dir = Path(args.out) if args.out else Path(tmpdir.name)  # type: ignore[union-attr]
    if args.out:
        output_dir.mkdir(parents=True, exist_ok=True)

    def _tick(*a: Any, **kw: Any) -> None:
        """Live progress if the loop offers a callback; harmless if it never calls back. The
        signature is deliberately open: the callback protocol is not part of the contract this
        module was written against, so a mismatch must not become a crash mid-run."""
        record = a[0] if a else kw.get("record")
        print(f"  {_iteration_label(getattr(record, 'index', '?'), record)}", file=out, flush=True)

    print(f"{path}  [{iac_type.value}]  scanner={args.scanner}  model={cfg.model}", file=out)

    try:
        try:
            result = _call_run_loop(run_loop, path, {
                "scanner": get_scanner(args.scanner), "client": client, "cfg": cfg,
                "iac_type": iac_type, "max_iters": args.max_iters,
                "token_budget": args.token_budget, "output_dir": output_dir,
                "on_iteration": _tick,
            })
        except TypeError as exc:
            # Signature mismatch between this CLI and loop.py. Surfaced as a tooling failure
            # rather than a traceback, and never as a clean result.
            raise IaCAgentError(f"could not call run_loop(): {exc}") from exc

        view = _LoopView(result)
        # Without --out the candidates live in the temp directory only, so there is nothing to
        # keep — writing is skipped for the same reason --dry-run skips it.
        written = _write_output(view, iac_type, output_dir, dry_run=args.dry_run or not args.out)
        drift_doc = _drift_document(view, path, iac_type)
    finally:
        if tmpdir is not None:
            tmpdir.cleanup()

    final, baseline = view.final_failed, view.baseline_failed
    resolved, introduced = view.keyset("resolved"), view.keyset("introduced")
    # `run_loop` records a model failure in `aborted_because` rather than raising, because a
    # verified iteration-1 improvement survives an iteration-2 API error. So exit 3 is
    # reserved for the case where the model layer failed *and nothing was ever accepted* —
    # otherwise the run has a real, scanner-verified result and should be reported as one.
    if view.aborted_because and not view.accepted_any:
        code = EXIT_LLM
    else:
        code = EXIT_OK if final == 0 else EXIT_FINDINGS

    if args.json:
        _emit_json({
            "command": "fix", "version": __version__, "target": str(path),
            "iac_type": iac_type.value, "scanner": args.scanner, "model": cfg.model,
            "config": {
                "temperature": cfg.temperature, "seed": cfg.seed,
                "prompt_version": cfg.prompt_version, "max_iters": args.max_iters,
                "token_budget": args.token_budget,
            },
            "baseline_failed": baseline, "final_failed": final, "best": view.best_label(),
            "accepted_any": view.accepted_any, "resolved": resolved, "introduced": introduced,
            "stop_reason": view.stop_reason, "aborted_because": view.aborted_because,
            "total_tokens": view.total_tokens,
            "iterations": [_iteration_document(i, r) for i, r in enumerate(view.iterations, 1)],
            "drift": drift_doc, "drift_gate_note": view.drift_gate_note,
            "output_file": str(written) if written else None, "exit_code": code,
        })
        return code

    steps = [f"baseline: {baseline if baseline is not None else '?'} failed"]
    steps += [_iteration_label(i, rec) for i, rec in enumerate(view.iterations, start=1)]
    print(f"\n{' -> '.join(steps)}  {view.stop_reason.upper()}", file=out)
    print(f"  returned {view.best_label()}: {final} failed "
          f"({len(resolved)} resolved, {len(introduced)} introduced), "
          f"{view.total_tokens} tokens over {len(view.iterations)} iteration(s)", file=out)
    if introduced:
        print("  NEW findings introduced by the fix: "
              + ", ".join(f"{rule}/{res}" for rule, res in introduced[:5]), file=out)
    if view.aborted_because:
        print(f"  run ended early: {view.aborted_because}", file=out)
    if view.drift_gate_note:
        print(f"  {view.drift_gate_note}", file=out)
    _print_drift(drift_doc, out)
    if written:
        print(f"\n  wrote {written}", file=out)
        if not view.accepted_any:
            # The best-so-far rule means an all-rejected run returns the original bytes.
            # Saying so prevents the file being mistaken for a remediation.
            print("  NOTE: that is the ORIGINAL file. No candidate passed the gates, and the "
                  "loop returns the best result it verified — never the last one it produced.",
                  file=out)
    elif args.dry_run:
        print("\n  --dry-run: nothing written", file=out)
    elif not args.out:
        print("\n  no --out given: the remediated file was not kept", file=out)
    return code


def _write_output(view: _LoopView, iac_type: IaCType, output_dir: Path,
                  dry_run: bool) -> Path | None:
    """Report where the best candidate landed, writing it only if the loop did not.

    `IaCType.output_name`, never a hardcoded string: both scanners select their Dockerfile
    rules by filename, so writing a remediated Dockerfile to `fixed.tf` would make the next
    scan apply Terraform rules to it and report a clean pass.
    """
    if dry_run:
        return None
    written = view.output_path
    if written is not None and written.is_file():
        return written
    if not view.best_code:
        return None
    target = output_dir / iac_type.output_name
    target.write_text(view.best_code, encoding="utf-8")
    return target


def _no_drift(reason: str) -> dict[str, Any]:
    return {"available": False, "reason": reason, "drifted": None, "summary": "",
            "touched_flawed": []}


def _drift_document(view: _LoopView, source: Path, iac_type: IaCType) -> dict[str, Any]:
    """Report Terraform resource or Dockerfile structural drift.

    Drift separates "secured the bucket" from "deleted the bucket", so the CLI would rather
    derive it from the code it is about to write than omit it because the loop spelled the
    attribute differently."""
    from .validity import DriftReport, compute_drift, drift_touches_flaw

    report = view.drift()
    if not isinstance(report, DriftReport) and view.best_code:
        try:
            report = compute_drift(source, view.best_code, iac_type)
        except IaCAgentError:
            report = None  # unparseable candidate: the validity gate already recorded why
    if not isinstance(report, DriftReport):
        return _no_drift("no parseable candidate to compare")

    baseline = view.baseline_scan
    flagged = {f.resource for f in baseline.failed} if baseline else set()
    summary = report.summary()
    if iac_type is IaCType.DOCKERFILE and not report.drifted:
        summary = "no protected Dockerfile structure removed"
    return {
        "available": True, "drifted": report.drifted, "summary": summary,
        "deleted": [r.address for r in report.deleted],
        "added": [r.address for r in report.added],
        "renamed": [[b.address, a.address] for b, a in report.renamed],
        "type_count_drops": {k: list(v) for k, v in report.type_count_drops.items()},
        "terraform_changes": list(report.terraform_changes),
        "docker_drops": list(report.docker_drops),
        "touched_flawed": drift_touches_flaw(report, flagged) if flagged else [],
    }


def _print_drift(doc: dict[str, Any], out) -> None:
    if not doc.get("available"):
        print(f"\n  drift: not measured — {doc.get('reason', 'unknown')}", file=out)
        return
    print("\n  drift: " + (doc["summary"] or "no resource drift"), file=out)
    if doc["touched_flawed"]:
        # The single most important warning this tool emits: the finding count fell because
        # the resource stopped existing, not because it was secured.
        bar = "!" * 74
        lines = [
            bar,
            "!! DRIFT TOUCHED A FLAW-CARRYING RESOURCE — the finding count fell because",
            "!! these resources were deleted or renamed, not because they were secured:",
            *(f"!!    {name}" for name in doc["touched_flawed"]),
            "!! Do not treat this run as a remediation. Review the diff before applying.",
            bar,
        ]
        print("\n" + "\n".join(f"  {line}" for line in lines), file=out)


# --- version, plumbing ----------------------------------------------------------------------

def cmd_version(args: argparse.Namespace) -> int:
    doc = {"name": PROG, "version": __version__, "python": sys.version.split()[0],
           "platform": sys.platform}
    if args.json:
        _emit_json(doc)
    else:
        print(f"{PROG} {__version__} (python {doc['python']}, {doc['platform']})")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """The three subcommands. `--json`/`--traceback` are shared through a parent parser so
    they cannot drift apart; everything else is per-command. See docs/LLD.md §9."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true",
                        help="emit a JSON document on stdout (diagnostics to stderr)")
    common.add_argument("--traceback", action="store_true",
                        help="show the Python traceback on error")

    parser = argparse.ArgumentParser(
        prog=PROG,
        description=("Detect and remediate Infrastructure-as-Code misconfigurations. "
                     "`scan` is scanner-only and needs no API key; `fix` runs the LLM loop."),
        epilog=("exit codes: 0 = clean, 1 = findings remain, 2 = tooling failed "
                "(scanner error / unsupported file), 3 = model call failed. "
                "2 never means 'findings exist'."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="{scan,fix,version}")

    p_scan = sub.add_parser(
        "scan", parents=[common], help="run static scanners only (no LLM, no API key)",
        description=("Run checkov and/or trivy over a file or directory. Never calls a model. "
                     "Exits 1 when findings remain and 2 when a scanner could not run."),
    )
    p_scan.add_argument("path", nargs="+", metavar="PATH",
                        help="one or more .tf/Dockerfile paths, or directories to walk")
    p_scan.add_argument("--scanner", choices=("checkov", "trivy", "both"), default="checkov",
                        help="which scanner(s) to run (default: checkov)")
    p_scan.add_argument(
        "--fail-on", choices=("any", "critical", "high", "medium", "low", "none"), default="any",
        help=("minimum severity that causes exit 1 (default: any). 'unknown' severities never "
              "meet a threshold — checkov CE reports none. Scanner errors still exit 2."),
    )
    p_scan.set_defaults(handler=cmd_scan)

    p_fix = sub.add_parser(
        "fix", parents=[common],
        help="run the detect/fix/validate/rescan loop (needs OPENAI_API_KEY)",
        description=("Iteratively remediate one file, re-scanning each candidate and rejecting "
                     "any that fails the validity or drift gate. Writes to --out; never edits "
                     "the input."),
    )
    p_fix.add_argument("path", metavar="PATH", help="a single .tf or Dockerfile")
    p_fix.add_argument("--scanner", choices=("checkov", "trivy"), default="checkov",
                       help="scanner used as the loop's oracle (default: checkov)")
    p_fix.add_argument("--max-iters", type=int, default=3,
                       help="maximum loop iterations (default: 3)")
    p_fix.add_argument("--model", default=None, help="model id (default: the pinned snapshot)")
    p_fix.add_argument("--token-budget", type=int, default=60_000,
                       help="stop once this many tokens have been spent (default: 60000)")
    p_fix.add_argument("--out", default=None, help="directory to write the remediated file into")
    p_fix.add_argument("--dry-run", action="store_true",
                       help="run the loop and the gates but keep nothing on disk")
    p_fix.set_defaults(handler=cmd_fix)

    p_version = sub.add_parser(
        "version", parents=[common], help="print the version and exit",
        description="Print the package version and the interpreter it is running on.",
    )
    p_version.set_defaults(handler=cmd_version)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "handler", None) is None:
        parser.print_help(sys.stderr)
        return EXIT_TOOLING

    try:
        return args.handler(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except IaCAgentError as exc:
        # Every failure this package raises lands here and becomes a message plus the right
        # exit code. A traceback is available but is never the primary user-facing error.
        code = EXIT_LLM if isinstance(exc, LLMError) else EXIT_TOOLING
        if getattr(args, "traceback", False):
            import traceback

            traceback.print_exc()
        print(f"{PROG}: {type(exc).__name__}: {exc}", file=sys.stderr)
        if getattr(args, "json", False):
            _emit_json({"command": getattr(args, "command", None), "version": __version__,
                        "error": str(exc), "error_type": type(exc).__name__, "exit_code": code})
        return code


if __name__ == "__main__":  # `python -m iac_agent.cli ...`
    sys.exit(main())
