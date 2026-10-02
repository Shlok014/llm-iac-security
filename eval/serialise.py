"""One on-disk representation of a scan, shared by the writer and the reader.

`run_eval.py` writes `results.json` / `baseline.json`; `metrics.py` reads them back and
recomputes every published table from them. If the two ever disagreed about the field set,
`report` would silently score a subset of what was measured — so both go through the four
functions here and there is no second spelling anywhere in the package.

Two properties of that representation are load-bearing rather than cosmetic, and each is
argued at its function: paths are relativised (`rel_path`, `rel_resource`) because these
files are committed and read by strangers, and findings are sorted (`scan_to_dict`) because
Checkov does not emit them in a stable order.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from iac_agent.types import Finding, IaCType, ScanResult
from iac_agent.validity import DriftReport

from . import REPO_ROOT


def rel_path(p: str | Path) -> str:
    """Render a path relative to the repository root.

    Committed results are read by people who are not us, on machines that are not ours. An
    absolute path bakes in a home directory and a username: it is unportable, it is noise in
    every diff, and on a public repo it discloses local filesystem layout for no benefit.
    Everything serialised into `eval/results/` therefore goes through here.
    """
    try:
        return Path(p).resolve().relative_to(REPO_ROOT).as_posix()
    except (ValueError, OSError):
        # Outside the repo (a tempdir candidate, say) — fall back to the bare filename rather
        # than leaking the absolute path of wherever it happened to live.
        return Path(p).name


def rel_resource(resource: str) -> str:
    """Relativise the path prefix Checkov bakes into Dockerfile resource identifiers.

    Checkov names a Dockerfile finding's resource `<path it was given>.<INSTRUCTION>`, so
    scanning an absolute path yields `/Users/someone/repo/samples/x.Dockerfile.ADD`. Terraform
    addresses (`aws_s3_bucket.example`) carry no path and pass through untouched.

    Note this is deliberately weaker than `loop._finding_key`, which reduces the same resource
    all the way to `ADD` because it needs identity to survive the file moving to a work
    directory. Here the file is worth keeping — a committed result should say *which* file a
    finding came from — so only the leading absolute path is rewritten.
    """
    res = (resource or "").strip()
    if not res or "/" not in res:
        return res
    root = REPO_ROOT.as_posix()
    if res.startswith(root + "/"):
        return res[len(root) + 1 :]
    return res


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "resource": rel_resource(f.resource),
        "message": f.message,
        "scanner": f.scanner,
        "file": rel_path(f.file) if f.file else "",
        "line": f.line,
        "guideline": f.guideline,
    }


def finding_from_dict(d: Mapping[str, Any]) -> Finding:
    return Finding(
        rule_id=str(d.get("rule_id", "?")),
        severity=str(d.get("severity", "unknown")),
        resource=str(d.get("resource", "")),
        message=str(d.get("message", "")),
        scanner=str(d.get("scanner", "")),
        file=str(d.get("file", "")),
        line=d.get("line"),
        guideline=str(d.get("guideline", "")),
    )


def scan_to_dict(s: ScanResult) -> dict[str, Any]:
    """Serialise a scan, with the findings **sorted**.

    Sorted because Checkov does not emit its failed checks in a stable order — measured:
    two consecutive scans of `samples/s3_public.tf` returned the same 8 checks with
    `CKV_AWS_144`, `CKV_AWS_145` and `CKV_AWS_21` in different positions, presumably from
    parallel check execution. `results.json` and `baseline.json` are committed artifacts,
    so an unsorted list makes every re-run produce a spurious diff and leaves a reviewer
    unable to tell a real change from scanner scheduling noise. Every metric here is set
    or count arithmetic, so ordering carries no information to lose.
    """
    return {
        "scanner": s.scanner,
        "target": rel_path(s.target),
        "iac_type": s.iac_type.value,
        "failed": [
            finding_to_dict(f)
            for f in sorted(s.failed, key=lambda f: (f.rule_id, f.resource, f.line or 0))
        ],
        "failed_count": s.failed_count,
        "passed_count": s.passed_count,
        "parse_errors": s.parse_errors,
    }


def drift_to_dict(d: DriftReport) -> dict[str, Any]:
    """Serialise a drift report. `metrics.drift_metrics` reads back exactly these keys.

    Here rather than at the call site in `run_eval.py` for the same reason `scan_to_dict`
    is: the writer and the reader of `results.json` must not hold two spellings of the same
    record. Drift is the block least able to survive a rename — a missing `deleted` list
    reads as "the model deleted nothing", which is precisely the finding the drift gate
    exists to make impossible to lose.
    """
    return {
        "deleted": [r.address for r in d.deleted],
        "added": [r.address for r in d.added],
        "renamed": [[b.address, a.address] for b, a in d.renamed],
        "type_count_drops": {k: list(v) for k, v in d.type_count_drops.items()},
        "docker_drops": list(d.docker_drops),
        "drifted": d.drifted,
        "summary": d.summary(),
    }


def scan_from_dict(d: Mapping[str, Any]) -> ScanResult:
    return ScanResult(
        scanner=str(d.get("scanner", "")),
        target=Path(str(d.get("target", ""))),
        iac_type=IaCType(str(d.get("iac_type", "terraform"))),
        failed=[finding_from_dict(x) for x in d.get("failed", [])],
        passed_count=int(d.get("passed_count") or 0),
        parse_errors=int(d.get("parse_errors") or 0),
    )
