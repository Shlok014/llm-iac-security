"""Comment-stripped fixture variants — removing the answer key from the exam paper.

**Why this file exists.** The fixtures in `samples/` were written as teaching examples,
before anyone intended to score a model on them, so they annotate their own planted
flaws inline::

    acl    = "public-read"        # <- public-read is insecure
    cidr_blocks = ["0.0.0.0/0"]   # <- insecure: SSH open to world
    # 9) Embedding plaintext credentials in ENV

A detection score measured on files in that state is contaminated: the model is not being
asked to *find* the flaws, it is being asked to *restate the comments*. Every recall
number this project publishes on the commented fixtures would be unfalsifiable in exactly
the way the original report's "high detection accuracy" was.

So the corpus is run twice, and the gap is the measurement::

    label_leak = recall(commented) - recall(stripped)

A large positive gap means the headline detection number was mostly comment
comprehension. A gap near zero means the model read the code. Neither outcome is assumed,
and the second is not the one being fished for.

**The correctness condition is mechanical, not visual.** Stripping comments must not
change what the file *does*. That is checked by an invariant a human never has to eyeball:

    the scanner finding counts must be identical before and after stripping

If Checkov's failed-check count moves when comments are removed, the stripper edited the
infrastructure rather than the prose and the variant is invalid. `verify()` enforces this
and `python -m eval.strip_comments --verify` is the command that runs it.

**Line numbers are preserved.** A comment-only line becomes an *empty* line rather than
disappearing, and a trailing comment is cut in place. Stripped line N is therefore
original line N, which keeps the `lines:` field in `eval/labels/*.labels.yaml` valid for
both variants and makes `diff samples/x.tf eval/corpus/stripped/x.tf` show removals only.

**What is deliberately NOT stripped**, because stripping it would change semantics:

* Anything inside a quoted HCL string — `"${aws_s3_bucket.public_bucket.arn}/*"` contains
  a `/*` that is not the start of a block comment, and `"# not a comment"` is data.
* Anything inside an HCL heredoc. The body of `user_data = <<-EOF ... EOF` is the
  *value* of an attribute, so the `# This writes a plaintext secret file` line inside it
  is a string, not a comment. It is a residual leak and is reported as one by
  `residual_leaks()` rather than being silently removed.
* Trailing `#` on a Dockerfile line. Docker supports whole-line comments only:
  `RUN echo hello # world` passes `# world` to the shell. Cutting it would change the
  built image.
* A Dockerfile parser directive (`# syntax=`, `# escape=`). Syntactically a comment,
  semantically build configuration.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from iac_agent.scanners import get_scanner
from iac_agent.types import IaCType, ScannerError, detect_iac_type
from iac_agent.validity import check_validity

from . import SAMPLES_DIR, STRIPPED_DIR, SCANNER_NAMES, fixture_paths

# `<<EOF`, `<<-EOF` and `<<~EOF` all open a heredoc; the tag runs to the end of the
# identifier. Matched during the character scan (not with a line-level regex) so that a
# `<<` appearing inside a string literal cannot open a phantom heredoc.
_HEREDOC_RE = re.compile(r"<<([-~]?)\s*([A-Za-z_][A-Za-z0-9_]*)")

# Only these two directives are honoured by the builder, and only before the first
# instruction. Everything else beginning with `#` is prose.
_PARSER_DIRECTIVE_RE = re.compile(r"^#\s*(syntax|escape|check)\s*=", re.IGNORECASE)


# --------------------------------------------------------------------------------------
# Terraform
# --------------------------------------------------------------------------------------


def _strip_hcl_line(line: str, in_block_comment: bool) -> tuple[str, bool, str | None]:
    """Strip comments from one HCL line, tracking string / block-comment / heredoc state.

    Returns `(code, still_in_block_comment, heredoc_tag_opened_on_this_line)`.

    A character scan rather than a regex because every regex formulation of "a `#` that is
    not inside a string" is wrong on at least one of the four fixtures: `s3:GetObject`
    contains no hash but `"${...arn}/*"` contains a `/*`, and `"vpc-0example"  # placeholder`
    contains both a string and a comment on the same line.
    """
    out: list[str] = []
    in_string = False
    escaped = False
    heredoc: str | None = None
    i = 0
    n = len(line)

    while i < n:
        ch = line[i]

        if in_block_comment:
            if line.startswith("*/", i):
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "#" or line.startswith("//", i):
            break  # line comment: drop it and everything after it

        if line.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue

        if line.startswith("<<", i):
            m = _HEREDOC_RE.match(line, i)
            if m:
                # Last one wins if a line somehow opens two heredocs; that needs a queue
                # and does not occur in this corpus.
                heredoc = m.group(2)
                out.append(m.group(0))
                i = m.end()
                continue

        out.append(ch)
        i += 1

    return "".join(out).rstrip(), in_block_comment, heredoc


def strip_terraform(text: str) -> str:
    """Remove `#`, `//` and `/* */` comments from HCL, preserving code and line numbering."""
    lines = text.splitlines()
    out: list[str] = []
    in_block_comment = False
    heredoc_tag: str | None = None

    for raw in lines:
        if heredoc_tag is not None:
            # Inside a heredoc every byte is string data, including a leading '#'.
            out.append(raw)
            if raw.strip() == heredoc_tag:
                heredoc_tag = None
            continue

        code, in_block_comment, opened = _strip_hcl_line(raw, in_block_comment)
        out.append(code)
        heredoc_tag = opened

    return _restore_trailing_newline(text, "\n".join(out))


# --------------------------------------------------------------------------------------
# Dockerfile
# --------------------------------------------------------------------------------------


def strip_dockerfile(text: str) -> str:
    """Remove whole-line `#` comments from a Dockerfile.

    Only whole-line comments, because that is all Docker has. A `#` after an instruction
    is an argument, and treating it as a comment would rewrite the command that runs.
    """
    lines = text.splitlines()
    out: list[str] = []
    seen_instruction = False
    continuation = False

    for raw in lines:
        stripped = raw.lstrip()
        is_comment = stripped.startswith("#")

        if is_comment and not seen_instruction and _PARSER_DIRECTIVE_RE.match(stripped):
            out.append(raw)  # syntactically a comment, semantically build configuration
            continue

        if is_comment:
            if continuation:
                # A blank line in the middle of a `\` continuation is not universally
                # accepted by builders, so a comment inside one is dropped outright. This
                # is the single place where line numbering is not preserved, and it does
                # not arise in this corpus.
                continue
            out.append("")
            continue

        if stripped:
            seen_instruction = True
        continuation = raw.rstrip().endswith("\\")
        out.append(raw)

    return _restore_trailing_newline(text, "\n".join(out))


def _restore_trailing_newline(original: str, rebuilt: str) -> str:
    """`splitlines()` drops the final newline; putting it back keeps the diff to comments."""
    if original.endswith("\n") and not rebuilt.endswith("\n"):
        return rebuilt + "\n"
    return rebuilt


def strip_text(text: str, iac_type: IaCType) -> str:
    if iac_type is IaCType.TERRAFORM:
        return strip_terraform(text)
    return strip_dockerfile(text)


# --------------------------------------------------------------------------------------
# residual leaks
# --------------------------------------------------------------------------------------

# Phrasings that give a planted flaw away in prose. Used only for *reporting* what the
# stripper could not legally remove — never to drive a removal, because a heredoc body is
# part of the configuration whatever it says.
_LEAK_HINTS = (
    "insecure",
    "vulnerable",
    "dangerous",
    "plaintext secret",
    "hardcoded",
    "bad example",
    "do not use",
)


def residual_leaks(stripped: str) -> list[tuple[int, str]]:
    """Lines of the stripped file that still name a flaw.

    These are string literals — overwhelmingly heredoc bodies — so they cannot be removed
    without changing the resource. Reporting them keeps the leakage claim honest: the
    stripped variant is *less* contaminated, not provably clean.
    """
    found: list[tuple[int, str]] = []
    for n, line in enumerate(stripped.splitlines(), start=1):
        low = line.lower()
        if any(h in low for h in _LEAK_HINTS):
            found.append((n, line.strip()))
    return found


# --------------------------------------------------------------------------------------
# generation + verification
# --------------------------------------------------------------------------------------


@dataclass
class StripReport:
    """What happened to one fixture, and whether the result is usable."""

    fixture: Path
    output: Path
    iac_type: IaCType
    lines: int
    comment_lines_removed: int
    trailing_comments_removed: int
    parses: bool = False
    parse_detail: str = ""
    scanner_counts: dict[str, tuple[int, int]] = field(default_factory=dict)
    residual_leaks: list[tuple[int, str]] = field(default_factory=list)

    @property
    def counts_preserved(self) -> bool:
        return all(before == after for before, after in self.scanner_counts.values())

    @property
    def ok(self) -> bool:
        return self.parses and self.counts_preserved


def _comment_stats(original: str, stripped: str) -> tuple[int, int]:
    """(whole-line comments removed, lines that lost a trailing comment)."""
    whole = 0
    trailing = 0
    for before, after in zip(original.splitlines(), stripped.splitlines()):
        if before == after:
            continue
        if not after.strip():
            whole += 1
        else:
            trailing += 1
    return whole, trailing


def generate(
    fixtures: list[Path] | None = None,
    out_dir: Path | None = None,
) -> list[StripReport]:
    """Write the stripped corpus. Filenames are preserved — that is load-bearing.

    Both scanners select their Dockerfile rulesets by *filename*, so a stripped Dockerfile
    written as `vulnerable.txt` would scan as nothing at all and report a clean pass. Same
    class of bug as writing remediated Dockerfiles to `fixed.tf`.
    """
    fixtures = fixtures or fixture_paths()
    out_dir = out_dir or STRIPPED_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    reports: list[StripReport] = []
    for src in fixtures:
        text = src.read_text(encoding="utf-8")
        kind = detect_iac_type(src)
        stripped = strip_text(text, kind)
        dest = out_dir / src.name
        dest.write_text(stripped, encoding="utf-8")

        whole, trailing = _comment_stats(text, stripped)
        reports.append(
            StripReport(
                fixture=src,
                output=dest,
                iac_type=kind,
                lines=len(stripped.splitlines()),
                comment_lines_removed=whole,
                trailing_comments_removed=trailing,
                residual_leaks=residual_leaks(stripped),
            )
        )
    return reports


def verify(
    reports: list[StripReport],
    scanners: tuple[str, ...] = SCANNER_NAMES,
) -> list[StripReport]:
    """Fill in the parse and scanner-count checks. Mutates and returns the reports.

    Two gates, in order of cost:

    1. `check_validity` — the stripped file must still parse. A stripper that ate a closing
       brace produces a file that scans clean, which is the exact fail-open this project
       exists to remove.
    2. Scanner counts must be *identical* to the original's. This is the strong check: it
       does not require anyone to read the diff, and it fails loudly if a `#` inside a
       string was mistaken for a comment.
    """
    for rep in reports:
        validity = check_validity(rep.output, rep.iac_type)
        rep.parses = bool(validity)
        rep.parse_detail = f"{validity.reason}: {validity.detail}"

        for name in scanners:
            scanner = get_scanner(name)
            before = scanner.scan(rep.fixture, rep.iac_type).failed_count
            after = scanner.scan(rep.output, rep.iac_type).failed_count
            rep.scanner_counts[name] = (before, after)
    return reports


def diff(fixture: Path, stripped: Path) -> str:
    return "".join(
        difflib.unified_diff(
            fixture.read_text(encoding="utf-8").splitlines(keepends=True),
            stripped.read_text(encoding="utf-8").splitlines(keepends=True),
            fromfile=str(fixture),
            tofile=str(stripped),
        )
    )


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def _print_table(reports: list[StripReport], verified: bool) -> None:
    head = f"{'fixture':<32} {'lines':>5} {'whole':>6} {'trail':>6}"
    if verified:
        head += f" {'parses':>7} {'checkov':>15} {'trivy':>15} {'ok':>4}"
    print(head)
    print("-" * len(head))
    for r in reports:
        row = (
            f"{r.fixture.name:<32} {r.lines:>5} "
            f"{r.comment_lines_removed:>6} {r.trailing_comments_removed:>6}"
        )
        if verified:
            def fmt(name: str) -> str:
                pair = r.scanner_counts.get(name)
                if pair is None:
                    return "-"
                before, after = pair
                flag = "==" if before == after else "!!"
                return f"{before} -> {after} {flag}"

            row += (
                f" {'yes' if r.parses else 'NO':>7}"
                f" {fmt('checkov'):>15} {fmt('trivy'):>15}"
                f" {'ok' if r.ok else 'FAIL':>4}"
            )
        print(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m eval.strip_comments",
        description=(
            "Generate eval/corpus/stripped/ from samples/. The fixtures annotate their "
            "own planted flaws, so detection measured on them is contaminated; the "
            "stripped variant is the uncontaminated one and the gap between the two is "
            "the label-leak measurement."
        ),
    )
    parser.add_argument("--samples", type=Path, default=SAMPLES_DIR)
    parser.add_argument("--out", type=Path, default=STRIPPED_DIR)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="run both scanners on original and stripped and require identical counts "
        "(the stripper's correctness condition). Needs checkov and trivy; no API key.",
    )
    parser.add_argument(
        "--scanner",
        default=",".join(SCANNER_NAMES),
        help="comma-separated scanners to verify with (default: checkov,trivy)",
    )
    parser.add_argument("--diff", action="store_true", help="print the unified diffs")
    parser.add_argument(
        "--show-leaks",
        action="store_true",
        help="list lines that still name a flaw (string literals the stripper may not touch)",
    )
    args = parser.parse_args(argv)

    reports = generate(fixture_paths(args.samples), args.out)

    if args.verify:
        scanners = tuple(s.strip() for s in args.scanner.split(",") if s.strip())
        try:
            verify(reports, scanners)
        except ScannerError as exc:
            print(f"scanner failure during verification: {exc}", file=sys.stderr)
            return 2

    _print_table(reports, verified=args.verify)

    if args.show_leaks:
        print("\nresidual leaks (string literals; cannot be stripped without changing code):")
        for r in reports:
            for line_no, text in r.residual_leaks:
                print(f"  {r.output.name}:{line_no}: {text}")

    if args.diff:
        for r in reports:
            print(diff(r.fixture, r.output))

    if args.verify:
        bad = [r for r in reports if not r.ok]
        if bad:
            print(
                "\nFAIL: stripping changed behaviour for "
                + ", ".join(r.fixture.name for r in bad)
                + ". The stripper edited the infrastructure, not the prose.",
                file=sys.stderr,
            )
            return 1
        totals = {
            name: (
                sum(r.scanner_counts[name][0] for r in reports),
                sum(r.scanner_counts[name][1] for r in reports),
            )
            for name in reports[0].scanner_counts
        }
        summary = ", ".join(f"{n}: {b} -> {a}" for n, (b, a) in sorted(totals.items()))
        print(f"\nOK: parse and scanner counts preserved ({summary}).")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
