"""RESULTS.md, rendered from the computed report and from nothing else.

Split out of `eval.metrics` because rendering and measuring fail differently: a bug here
produces an ugly table, a bug there produces a wrong number, and interleaving them put
four hundred lines of markdown between a reader and the arithmetic.

The prose between the tables is long on purpose. Every paragraph either names a
denominator, admits what a figure cannot see, or explains why two spellings of the same
metric are both printed rather than one being quietly chosen — it is the honesty apparatus
of the project, not filler, and it is why `RESULTS.md` is generated rather than written.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from . import SCANNER_NAMES
from .metrics import fmt_stat

_GENERATED_HEADER = """\
<!--
  GENERATED FILE — DO NOT EDIT BY HAND.

  Regenerate with:

      .venv/bin/python -m eval.run_eval report

  Every number below is computed by eval/metrics.py from eval/results/results.json,
  eval/results/baseline.json and eval/labels/*.labels.yaml. Nothing here is typed in.

  That rule is not tidiness. The project this replaces shipped a hand-written results
  table whose policy ids described entirely different policies, because they were
  recalled rather than read. A hand-edited results file is a claim; a generated one is a
  measurement, and the difference is the whole point of this directory.
-->
"""


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """The only table builder in this module — header, separator, body, joined.

    Every table below goes through here so that "empty" has exactly one rendering
    (`_no data_`, never a headed table with no rows, which reads as a measurement of zero)
    and so that a `None` cell is always an empty cell rather than the string `None`.
    """
    if not rows:
        return "_no data_\n"
    head = "| " + " | ".join(str(h) for h in headers) + " |"
    rule = "| " + " | ".join("---" for _ in headers) + " |"
    body = "\n".join("| " + " | ".join("" if c is None else str(c) for c in r) + " |" for r in rows)
    return f"{head}\n{rule}\n{body}\n"


def _pct(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value) * 100:.1f}%"


def render_results_md(report: Mapping[str, Any]) -> str:
    """Render the whole results document. Generated, never hand-edited."""
    md: list[str] = [_GENERATED_HEADER, "# Evaluation results\n"]
    meta = report.get("metadata") or {}

    md.append(
        "All figures are descriptive statistics over repeat runs — `mean [min, max]`. "
        "**n is far too small for confidence intervals**, significance tests, or any "
        "claim that one configuration beats another; the range answers only *how much "
        "does this number move when nothing changes?*\n"
    )

    md.append("## Run configuration\n")
    md.append(_md_table(["parameter", "value"], [
        ["model snapshot", f"`{meta.get('model', 'n/a')}`"],
        ["prompt_version", f"`{meta.get('prompt_version', 'n/a')}`"],
        ["temperature", meta.get("temperature", "n/a")],
        ["seed", meta.get("seed", "n/a")],
        ["repeat runs", meta.get("repeats", "n/a")],
        ["variants", ", ".join(meta.get("variants", []) or []) or "n/a"],
        ["checkov", f"`{meta.get('checkov_version', 'n/a')}`"],
        ["trivy", f"`{meta.get('trivy_version', 'n/a')}`"],
        ["python", f"`{meta.get('python_version', 'n/a')}`"],
        ["timestamp (UTC)", meta.get("timestamp", "n/a")],
        ["cache hits / misses", f"{meta.get('cache_hits', 0)} / {meta.get('cache_misses', 0)}"],
        ["live model calls", meta.get("live_calls", 0)],
        ["system_fingerprints",
         ", ".join(meta.get("system_fingerprints", []) or []) or "none recorded"],
    ]))

    for warning in report.get("warnings") or []:
        md.append(f"> **Note.** {warning}\n")

    # ---- baseline ----
    md.append(
        "\n## 1. Scanner-only baseline (B1 / B2) — what the LLM has to beat\n"
        "Checkov and Trivy run in about a second each, need no API key and cost nothing. "
        "Any claim on behalf of a pipeline that costs money and can hallucinate has to be "
        "a claim about something these two do not already do for free. **The absence of "
        "this table was the largest hole in the original report.**\n"
    )
    for variant, block in sorted((report.get("baseline") or {}).items()):
        md.append(f"\n### Variant: `{variant}`\n")
        per_fixture = block.get("per_fixture") or {}
        totals = block.get("per_scanner") or {}
        label_totals = block.get("labels") or {}
        per_fixture_labels = label_totals.get("per_fixture") or {}
        rows: list[list[Any]] = [
            [f"`{f}`", per_fixture[f].get("checkov"), per_fixture[f].get("trivy"),
             (per_fixture_labels.get(f) or {}).get("total"),
             (per_fixture_labels.get(f) or {}).get("detectable")]
            for f in sorted(per_fixture)
        ]
        rows.append([
            "**total**",
            (totals.get("checkov") or {}).get("findings"),
            (totals.get("trivy") or {}).get("findings"),
            label_totals.get("total"),
            label_totals.get("detectable_by_scanner"),
        ])
        md.append(_md_table(
            ["fixture", "checkov failed", "trivy findings", "planted labels",
             "of which scanner-detectable"],
            rows,
        ))
        md.append(
            "\nThose two totals are counts of **rule violations, not of flaws**, and they "
            "do not sum: one planted flaw trips many rules, and the two rulesets overlap. "
            "The recall denominator is the label column.\n"
        )

        md.append("\n**Scanner recall against the ground truth**\n")
        md.append(_md_table(
            ["scanner", "findings", "mapped to a planted label", "incidental",
             "labels detected", "recall (all labels)", "recall (detectable subset)"],
            [
                [name,
                 s.get("findings") if s.get("findings") is not None else "n/a (see note)",
                 s.get("mapped_to_labels", "—"), s.get("incidental", "—"),
                 s.get("labels_detected"), _pct(s.get("recall_all_labels")),
                 _pct(s.get("recall_detectable_only"))]
                for name, s in ((n, totals.get(n)) for n in (*SCANNER_NAMES, "union"))
                if s
            ],
        ))
        md.append(
            "\n`recall (detectable subset)` should be 1.000 by construction — "
            "`detectable_by_scanner` is *defined* as 'a rule in one of these two tools "
            "fires on it'. A value below 1.0 means a label's ids are wrong, not that a "
            "scanner underperformed.\n"
        )

    violations = report.get("label_id_violations") or []
    if violations:
        md.append(
            "\n### Label id verification FAILED\n"
            "Every `checkov_ids` / `trivy_ids` entry must have been copied from real "
            "scanner output. These did not appear in the baseline:\n\n"
        )
        md.extend(f"- {v}\n" for v in violations)
    else:
        md.append(
            "\n**Label id verification: passed.** Every label with a non-empty id list has "
            "at least one of those ids present in that fixture's baseline scan.\n"
        )

    # ---- delta ----
    if report.get("delta"):
        md.append(
            "\n## 2. Finding delta (headline)\n"
            "`delta = (before - after) / before`, over every rule violation, planted or "
            "incidental. **`introduced` is never netted against `resolved`**: a run that "
            "resolves 40 and introduces 10 would otherwise be indistinguishable from one "
            "that resolves 30 and introduces 0, and the first wrote ten new "
            "misconfigurations into the user's infrastructure. An output that failed the "
            "validity gate is scored as `after = before` — nothing usable was produced, so "
            "nothing was fixed.\n"
        )
        for variant, per_scanner in sorted(report["delta"].items()):
            md.append(f"\n### Variant: `{variant}`\n")
            md.append(_md_table(
                ["scanner", "before", "after", "delta", "resolved", "introduced",
                 "persisted", "invalid outputs"],
                [
                    [scanner, fmt_stat(s["before"], digits=1), fmt_stat(s["after"], digits=1),
                     fmt_stat(s["delta_pct"], pct=True), fmt_stat(s["resolved"], digits=1),
                     fmt_stat(s["introduced"], digits=1), fmt_stat(s["persisted"], digits=1),
                     fmt_stat(s["invalid_remediations"], digits=1)]
                    for scanner, s in sorted(per_scanner.items())
                ],
            ))
            md.append(
                "\n`resolved - introduced` need not equal `before - after`: "
                "`Finding.key()` is `(rule_id, resource)` and is not injective — Trivy "
                "raises `DS031` three times on three `ENV` lines with an empty resource, "
                "so three findings share one key. The key is also unstable under renaming, "
                "which inflates `resolved` and `introduced` together; read them beside the "
                "drift table, not alone.\n"
            )
            for scanner, s in sorted(per_scanner.items()):
                all_rules = [r for r in (s.get("per_rule") or []) if r["before"]]
                moved = [r for r in all_rules if r["before"] != r["after"]]
                if not all_rules:
                    continue
                md.append(f"\n**Per-rule resolution — {scanner}** (first repeat)\n")
                md.append(_md_table(
                    ["rule_id", "before", "after", "resolved"],
                    [[f"`{r['rule_id']}`", r["before"], r["after"], r["resolved"]] for r in moved],
                ))
                md.append(
                    f"\nRules listed: the {len(moved)} whose count changed. "
                    f"{len(all_rules) - len(moved)} further rules fired before and were "
                    "still failing afterwards at the same count; the full per-rule table "
                    "is in `eval/results/results.json`.\n"
                )

    # ---- detection ----
    if report.get("detection"):
        md.append(
            "\n## 3. Detection precision and recall\n"
            "Scored against `eval/labels/*.labels.yaml`. The recall denominator is "
            "**planted labels only** — incidental scanner findings are excluded from both "
            "precision and recall while still counting fully in the delta above.\n"
        )
        detection = sorted(report["detection"].items())
        md.append(_md_table(
            ["variant", "labels", "TP_label", "FN", "recall", "findings", "TP_finding",
             "FP_strict", "precision (strict)", "precision (adjudicated)"],
            [
                [variant, fmt_stat(d["labels"], digits=0), fmt_stat(d["tp_label"], digits=1),
                 fmt_stat(d["fn"], digits=1), fmt_stat(d["recall"], pct=True),
                 fmt_stat(d["findings"], digits=1), fmt_stat(d["tp_finding"], digits=1),
                 fmt_stat(d["fp_strict"], digits=1), fmt_stat(d["precision_strict"], pct=True),
                 fmt_stat(d["precision_adjudicated"], pct=True)]
                for variant, d in detection
            ],
        ))
        md.append(
            "\n`precision_strict = TP_finding / |findings|` is the defensible floor — it "
            "calls every unmatched finding wrong, including genuine flaws the annotator "
            "never planted. `precision_adjudicated = TP_finding / (|findings| - "
            "|plausible|)` excludes unmatched-but-plausible findings from the denominator "
            "instead of penalising them; they are counted separately below. The gap "
            "between the two measures how incomplete the labels are, and the adjudicated "
            "figure is produced by the system's own author judging the system's output.\n"
        )
        md.append(_md_table(
            ["variant", "unmatched but plausible", "unmatched, no support (hallucination)",
             "precision (adjudicated, credited form)"],
            [
                [variant, fmt_stat(d["plausible_unmatched"], digits=1),
                 fmt_stat(d["hallucinated"], digits=1),
                 fmt_stat(d["precision_adjudicated_credited"], pct=True)]
                for variant, d in detection
            ],
        ))
        md.append(
            "\nThe last column is the alternative spelling from `docs/EVALUATION.md` §5.2, "
            "`(TP_finding + |plausible|) / |findings|`, which credits plausible findings in "
            "the numerator rather than removing them from the denominator. Both appear in "
            "the project's own documents, so both are printed rather than one being quietly "
            "chosen.\n"
        )

        for variant, d in detection:
            per_fixture = d.get("per_fixture") or {}
            if not per_fixture:
                continue
            md.append(f"\n**Per fixture — `{variant}` (first repeat)**\n")
            md.append(_md_table(
                ["fixture", "labels", "TP_label", "recall", "findings", "TP_finding",
                 "FP_strict", "missed labels"],
                [
                    [f"`{f}`", r["labels"], r["tp_label"], _pct(r["recall"]), r["findings"],
                     r["tp_finding"], r["fp_strict"],
                     ", ".join(f"`{m}`" for m in r["missed_label_ids"]) or "—"]
                    for f, r in sorted(per_fixture.items())
                ],
            ))

    # ---- leakage ----
    leak = report.get("leakage") or {}
    if leak:
        md.append(
            "\n## 4. Label leakage (B4)\n"
            "The fixtures annotate their own planted flaws inline, so a detection score "
            "measured on them is contaminated — the model can read the answer key. "
            "`eval/corpus/stripped/` is the variant with those comments removed, verified "
            "by the invariant that **the scanner finding counts must be identical before "
            "and after stripping**.\n"
        )
        md.append(_md_table(["quantity", "value"], [
            ["recall, commented", fmt_stat(leak["recall_commented"], pct=True)],
            ["recall, stripped (headline)", fmt_stat(leak["recall_stripped"], pct=True)],
            ["**label_leak**", _pct(leak["label_leak"])],
        ]))
        md.append(f"\n{leak['note']}\n")

    # ---- validity ----
    if report.get("validity"):
        md.append(
            "\n## 5. Validity rate\n"
            "`validity_rate = outputs that parse / generation attempts`, measured over "
            "**attempts** — including any a refinement loop discarded, because validity "
            "measured on accepted outputs is 100% by construction. A syntax gate only: "
            "`hcl2` parses the grammar, it does not resolve references or check provider "
            "schemas, so a file can pass this and still fail `terraform validate`.\n"
        )
        rows = []
        for variant, v in sorted(report["validity"].items()):
            for framework, f in (v.get("by_framework") or {}).items():
                rows.append([variant, framework, f["attempts"], f["valid"], _pct(f["rate"])])
            rows.append([variant, "**all**", v["attempts"], v["valid"], _pct(v["rate"])])
        md.append(_md_table(["variant", "framework", "attempts", "parsed", "validity rate"], rows))

    # ---- drift ----
    if report.get("drift"):
        md.append(
            "\n## 6. Semantic drift — the number that audits the headline\n"
            "The cheapest way to make a finding disappear is to delete the resource it was "
            "about. That scores a **perfect** finding delta, passes the validity gate, and "
            "leaves precision and recall untouched, while destroying the user's "
            "infrastructure. `drift_touches_flaw()` is the only signal in this protocol "
            "that can tell that apart from a real fix.\n"
        )
        drift = sorted(report["drift"].items())
        md.append(_md_table(
            ["variant", "valid outputs", "of which Terraform", "drifted",
             "drift rate (Terraform)", "**drift touched a flaw-carrying resource**",
             "deleted", "renamed", "added"],
            [
                [variant, d["valid_remediations"], d["valid_terraform_remediations"],
                 d["drifted_outputs"], _pct(d["drift_rate_terraform"]),
                 d["flaw_touching_outputs"], d["resources_deleted"], d["resources_renamed"],
                 d["resources_added"]]
                for variant, d in drift
            ],
        ))
        md.append(
            "\nThe drift rate is quoted over **Terraform** outputs: a Dockerfile has no "
            "addressable resources, so it can never drift, and including Dockerfiles in "
            "the denominator would dilute the rate with outputs structurally incapable of "
            "moving it. Renames count as drift — Terraform keys state on the address, so a "
            "rename destroys and recreates on the next apply. Additions never do, because "
            "fixing a public bucket correctly *requires* adding resources.\n"
        )
        for variant, d in drift:
            events = d.get("events") or []
            if not events:
                continue
            md.append(f"\n**Drift events — `{variant}`** (listed individually, not just counted)\n")
            md.append(_md_table(
                ["fixture", "run", "summary", "flaw-carrying resources lost"],
                [
                    [f"`{e['fixture']}`", e["run_index"], e["summary"],
                     ", ".join(f"`{r}`" for r in e["flaw_carrying_lost"]) or "—"]
                    for e in events
                ],
            ))

    md.append(
        "\n---\n"
        "Method, denominators and threats to validity: [`docs/EVALUATION.md`](../../docs/EVALUATION.md). "
        "Ground truth and the planted-versus-incidental rule: "
        "[`eval/labels/README.md`](../labels/README.md).\n"
    )
    return "".join(md)
