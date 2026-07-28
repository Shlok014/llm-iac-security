"""Evaluation harness: the part of this project that can return a negative result.

The original report claimed "high detection accuracy" with no denominator, no dataset
size, no baseline, and a validation step that had never executed. Every module in this
package exists to make a claim like that impossible to write again:

* `eval.labels`      — hand-authored ground truth, the recall *denominator*, kept in YAML
                       so it is reviewable separately from the code being scored.
* `eval.strip_comments` — the fixtures annotate their own planted flaws inline, so any
                       detection score measured on them is contaminated. The stripped
                       corpus is the uncontaminated variant; the gap between the two IS
                       the label-leak measurement.
* `eval.metrics`     — each number defined by a formula in its docstring, with the
                       denominator stated.
* `eval.run_eval`    — the CLI. `baseline` needs no API key at all, `report` needs no
                       network at all, and only `--fresh` can spend money.

Paths are collected here rather than recomputed in each module so that a relocation of
`eval/cache/` cannot silently split the cache between two directories — which would look
exactly like a cache that never hits.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "samples"

EVAL_DIR = REPO_ROOT / "eval"
LABELS_DIR = EVAL_DIR / "labels"
CACHE_DIR = EVAL_DIR / "cache"
CORPUS_DIR = EVAL_DIR / "corpus"
STRIPPED_DIR = CORPUS_DIR / "stripped"
RESULTS_DIR = EVAL_DIR / "results"

RESULTS_JSON = RESULTS_DIR / "results.json"
BASELINE_JSON = RESULTS_DIR / "baseline.json"
RESULTS_MD = RESULTS_DIR / "RESULTS.md"
DRIFT_DIR = RESULTS_DIR / "drift"
ARTIFACT_DIR = RESULTS_DIR / "artifacts"
ADJUDICATION_YAML = RESULTS_DIR / "adjudication.yaml"

# The two corpus variants. "commented" is `samples/` as committed; "stripped" is the
# generated variant with the inline answer key removed. Headline detection numbers are
# reported on "stripped"; "commented" is run only to produce the leakage figure.
VARIANTS: tuple[str, ...] = ("commented", "stripped")
DEFAULT_VARIANT = "stripped"

SCANNER_NAMES: tuple[str, ...] = ("checkov", "trivy")


def fixture_paths(samples_dir: Path | None = None) -> list[Path]:
    """The corpus, in a stable order.

    Globbed rather than hard-coded so that adding a fixture to `samples/` does not
    require editing this package — but sorted, because an unordered corpus makes two
    result files diff-noisy for no reason.
    """
    root = samples_dir or SAMPLES_DIR
    found = [
        p
        for p in root.iterdir()
        if p.is_file() and (p.suffix == ".tf" or "dockerfile" in p.name.lower())
    ]
    return sorted(found, key=lambda p: p.name)


def fixture_key(path: Path | str) -> str:
    """Repo-relative identity of a fixture, stable across corpus variants.

    A run over `eval/corpus/stripped/s3_public.tf` is still a run over the fixture
    `samples/s3_public.tf` — that is the key the labels are filed under, and the key
    results are joined on. Keeping the *variant* in a separate field rather than in the
    fixture id is what lets commented and stripped results be compared at all.
    """
    return f"samples/{Path(path).name}"


__all__ = [
    "REPO_ROOT",
    "SAMPLES_DIR",
    "EVAL_DIR",
    "LABELS_DIR",
    "CACHE_DIR",
    "CORPUS_DIR",
    "STRIPPED_DIR",
    "RESULTS_DIR",
    "RESULTS_JSON",
    "BASELINE_JSON",
    "RESULTS_MD",
    "DRIFT_DIR",
    "ARTIFACT_DIR",
    "ADJUDICATION_YAML",
    "VARIANTS",
    "DEFAULT_VARIANT",
    "SCANNER_NAMES",
    "fixture_paths",
    "fixture_key",
]
