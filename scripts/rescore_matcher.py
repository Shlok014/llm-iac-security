"""Reproduce the matcher finding: substring vs token-subset recall/precision.

Reads only the committed cache — no API calls, no cost. Run from the repo root:

    .venv/bin/python scripts/rescore_matcher.py

It exists so the finding can be re-derived rather than taken on trust.
"""

from __future__ import annotations

import glob
import json
import re

import yaml

STOP = {"the", "a", "an", "is", "are", "to", "of", "in", "on", "and", "or",
        "for", "with", "be", "not", "all", "from", "that", "this"}


def norm(text) -> str:
    return re.sub(r"[^a-z0-9 ]", " ", str(text).lower())


def toks(text) -> set[str]:
    return {w for w in norm(text).split() if len(w) > 2 and w not in STOP}


def load():
    labels = {}
    for path in glob.glob("eval/labels/*.labels.yaml"):
        doc = yaml.safe_load(open(path))
        labels[doc["fixture"]] = doc.get("labels") or []

    runs = {}
    for path in glob.glob("eval/cache/*.json"):
        rec = json.load(open(path))
        if rec.get("call_kind") != "detect" or rec.get("variant") != "stripped":
            continue
        if rec.get("run_index") != 0 or not labels.get(rec.get("fixture")):
            continue
        try:
            parsed = json.loads(rec["response"])
        except Exception:
            continue
        runs[rec["fixture"]] = (
            parsed.get("findings") if isinstance(parsed, dict) else parsed
        ) or []
    return labels, runs


def substring(finding, label) -> bool:
    """What the repo does today."""
    hay = norm(f"{finding.get('issue','')} {finding.get('recommendation','')} "
               f"{finding.get('resource','')}")
    return any(norm(a) in hay for a in (label.get("aliases") or []))


def token_subset(finding, label) -> bool:
    """Order-independent: every significant alias token appears somewhere."""
    hay = toks(f"{finding.get('issue','')} {finding.get('recommendation','')} "
               f"{finding.get('resource','')}")
    for alias in label.get("aliases") or []:
        at = toks(alias)
        if at and at <= hay:
            return True
    return False


def main() -> None:
    labels, runs = load()
    print(f"scored over {len(runs)} fixtures from cache — no API calls\n")
    for name, match in (("substring (current)", substring), ("token-subset", token_subset)):
        hit = total = tp = fp = 0
        for fixture, labs in labels.items():
            if fixture not in runs:
                continue
            findings = runs[fixture]
            total += len(labs)
            hit += sum(1 for lab in labs if any(match(f, lab) for f in findings))
            for f in findings:
                if any(match(f, lab) for lab in labs):
                    tp += 1
                else:
                    fp += 1
        recall = 100 * hit / total if total else 0
        precision = 100 * tp / (tp + fp) if (tp + fp) else 0
        print(f"  {name:<22} recall {recall:5.1f}% ({hit}/{total})   "
              f"precision {precision:5.1f}% ({tp}/{tp+fp})")
    print("\n  scanner baselines on the published subset: checkov 46.2%  trivy 40.4%  union 53.8%")


if __name__ == "__main__":
    main()
