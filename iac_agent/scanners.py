"""Static scanners behind one interface, and a hard rule: fail closed.

Two scanners are supported because two independent tools agreeing is stronger evidence
than one, and because they disagree in useful ways — Checkov is policy-oriented and
verbose on Dockerfiles; Trivy carries the old tfsec Terraform ruleset.

The invocation detail that matters: Checkov must be run through its **console script**.
`python -m checkov` fails on every Python version because the package ships no
`__main__` module. The original implementation used `python3 -m checkov`, so its
validation step never executed even once — and, because empty stdout was treated as
"no issues found", every run reported a clean pass.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Protocol

from .types import Finding, IaCType, ScanResult, ScannerError, detect_iac_type

# Checkov: 0 = every check passed, 1 = at least one check failed. Anything else is a
# crash, a bad flag, or a missing dependency — none of which are "clean".
_CHECKOV_OK_CODES = {0, 1}
_TRIVY_OK_CODES = {0}

# Checkov's most dangerous failure mode, and the reason exit codes alone are not enough.
# Ask it for a framework that does not match the file — `--file x.Dockerfile --framework
# terraform` — and it logs this to stderr, exits 0, and prints a bare summary
# `{"passed": 0, "failed": 0, "parsing_errors": 0, "resource_count": 0}` with no "results"
# key at all. That JSON is indistinguishable from a genuinely resource-less file, so it
# cannot be detected from stdout; a valid `variable "x" {}` produces the identical shape.
# Without this check, pointing the wrong framework at a file reports a clean pass on a file
# with real findings — precisely the fail-open bug this package exists to eliminate.
_NO_RUNNERS = "There are no runners to run"

_TIMEOUT_S = 300


def _resolve(binary: str) -> str:
    """Find an executable, preferring the active interpreter's own bin directory.

    Running inside a venv, `sys.executable`'s sibling `checkov` is the one whose
    dependencies we pinned; PATH may point at a broken system install.
    """
    sibling = Path(sys.executable).parent / binary
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return str(sibling)
    found = shutil.which(binary)
    if found:
        return found
    raise ScannerError(
        f"{binary!r} not found. Install it into the active environment "
        f"(looked in {sibling.parent} and on PATH)."
    )


def _run(
    cmd: list[str],
    ok_codes: set[int],
    forbid_stderr: tuple[str, ...] = (),
) -> str:
    """Run a scanner, refusing to return output we have reason to distrust.

    `forbid_stderr` exists because exit codes are not a complete failure signal. Checkov can
    log a fatal condition, emit a well-formed but empty report, and still exit 0 — see
    `_NO_RUNNERS` below. Any pattern listed here turns such a run into a `ScannerError`.
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT_S, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{cmd[0]} timed out after {_TIMEOUT_S}s") from exc
    except OSError as exc:
        raise ScannerError(f"could not execute {cmd[0]}: {exc}") from exc

    if proc.returncode not in ok_codes:
        detail = (proc.stderr or proc.stdout or "").strip()[:600]
        raise ScannerError(
            f"{Path(cmd[0]).name} exited {proc.returncode} (expected one of "
            f"{sorted(ok_codes)}). This is a scanner failure, not a clean result.\n{detail}"
        )

    stderr = proc.stderr or ""
    for pattern in forbid_stderr:
        if pattern in stderr:
            raise ScannerError(
                f"{Path(cmd[0]).name} exited {proc.returncode} but reported a fatal condition "
                f"on stderr: {pattern!r}. It produced a report without examining the file, so "
                f"its 'zero findings' is an absence of analysis, not a clean result.\n"
                f"{stderr.strip()[:600]}"
            )
    return proc.stdout


def _load_json(raw: str, scanner: str) -> object:
    """Parse scanner stdout, refusing to treat emptiness as success."""
    text = raw.strip()
    if not text:
        raise ScannerError(
            f"{scanner} produced no output. Refusing to report this as 'no issues "
            f"found' — an absent result is not a passing result."
        )
    start = min(
        (i for i in (text.find("{"), text.find("[")) if i != -1),
        default=-1,
    )
    if start == -1:
        raise ScannerError(f"{scanner} output contained no JSON:\n{text[:400]}")
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError as exc:
        raise ScannerError(f"{scanner} output was not valid JSON: {exc}") from exc


class Scanner(Protocol):
    name: str

    def scan(self, path: Path, iac_type: IaCType | None = None) -> ScanResult: ...


class CheckovScanner:
    name = "checkov"

    def scan(self, path: Path, iac_type: IaCType | None = None) -> ScanResult:
        path = Path(path)
        if not path.is_file():
            raise ScannerError(f"not a file: {path}")
        kind = iac_type or detect_iac_type(path)

        raw = _run(
            [
                _resolve("checkov"),
                "-f", str(path),
                "-o", "json",
                "--compact",
                "--quiet",
                "--framework", kind.checkov_framework,
            ],
            _CHECKOV_OK_CODES,
            forbid_stderr=(_NO_RUNNERS,),
        )
        doc = _load_json(raw, "checkov")
        if isinstance(doc, list):
            doc = doc[0] if doc else None
        if not isinstance(doc, dict):
            raise ScannerError("checkov returned an unexpected JSON shape")

        # Checkov uses a bare summary for a file with no runnable resources.
        # A framework mismatch can have the same shape, but _run rejects its error stderr.
        bare_summary = "summary" not in doc and "results" not in doc
        summary = doc if bare_summary else doc.get("summary")
        results = {"failed_checks": []} if bare_summary else doc.get("results")
        if (
            not isinstance(summary, dict)
            or not isinstance(results, dict)
            or not isinstance(results.get("failed_checks"), list)
            or (bare_summary and any(key not in summary for key in
                                     ("failed", "resource_count", "checkov_version")))
            or any(
                not isinstance(summary.get(key), int)
                or isinstance(summary.get(key), bool)
                or summary[key] < 0
                for key in ("passed", "parsing_errors")
            )
        ):
            raise ScannerError("checkov returned an incomplete JSON result shape")
        findings = [
            Finding(
                rule_id=c.get("check_id", "?"),
                severity=(c.get("severity") or "unknown").lower(),
                resource=c.get("resource", "") or "",
                message=c.get("check_name", "") or "",
                scanner=self.name,
                file=str(path),
                line=(c.get("file_line_range") or [None])[0],
                guideline=c.get("guideline") or "",
            )
            for c in results["failed_checks"]
        ]
        return ScanResult(
            scanner=self.name,
            target=path,
            iac_type=kind,
            failed=findings,
            passed_count=summary["passed"],
            parse_errors=summary["parsing_errors"],
        )


class TrivyScanner:
    name = "trivy"

    def scan(self, path: Path, iac_type: IaCType | None = None) -> ScanResult:
        path = Path(path)
        if not path.is_file():
            raise ScannerError(f"not a file: {path}")
        kind = iac_type or detect_iac_type(path)

        raw = _run(
            [_resolve("trivy"), "config", "--quiet", "--format", "json", str(path)],
            _TRIVY_OK_CODES,
        )
        doc = _load_json(raw, "trivy")
        if not isinstance(doc, dict):
            raise ScannerError("trivy returned an unexpected JSON shape")

        findings: list[Finding] = []
        passed = 0
        for result in doc.get("Results", []) or []:
            for m in result.get("Misconfigurations", []) or []:
                status = (m.get("Status") or "FAIL").upper()
                if status == "PASS":
                    passed += 1
                    continue
                cause = m.get("CauseMetadata") or {}
                findings.append(
                    Finding(
                        rule_id=m.get("ID", "?"),
                        severity=(m.get("Severity") or "unknown").lower(),
                        resource=cause.get("Resource", "") or "",
                        message=m.get("Title", "") or "",
                        scanner=self.name,
                        file=str(path),
                        line=(cause.get("StartLine") or None),
                        guideline=m.get("PrimaryURL") or "",
                    )
                )
        return ScanResult(
            scanner=self.name,
            target=path,
            iac_type=kind,
            failed=findings,
            passed_count=passed,
            parse_errors=0,
        )


SCANNERS: dict[str, type] = {"checkov": CheckovScanner, "trivy": TrivyScanner}


def get_scanner(name: str) -> Scanner:
    try:
        return SCANNERS[name.lower()]()
    except KeyError:
        raise ScannerError(
            f"unknown scanner {name!r}; available: {', '.join(sorted(SCANNERS))}"
        ) from None


def scanner_path(name: str) -> str | None:
    """Where this scanner's executable is, or `None` if it is not installed.

    A question the callers ask *before* running anything, so it must not raise. Both scanners
    invoke a binary named after themselves, and `_resolve` is the same lookup a real scan does
    — so a `None` here and a `ScannerError` there cannot disagree. Trivy is a Go binary that
    `pip install` does not provide, which is why "is it there?" is worth asking up front rather
    than discovering at the end of a run.
    """
    try:
        return _resolve(name.lower())
    except ScannerError:
        return None
