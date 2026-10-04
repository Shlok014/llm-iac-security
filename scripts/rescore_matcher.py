"""Re-score the *published* six-fixture, three-repeat detection runs offline.

This is a post-hoc matcher sensitivity check, not a revised model evaluation. It uses
the exact saved findings and resource matcher from the published results, and refuses
missing fixtures or repeats rather than silently changing the denominator.

Run from the repository root: python -m scripts.rescore_matcher
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from eval import RESULTS_JSON
from eval.labels_io import load_labels
from eval.matching import normalise_text, resource_matches, semantic_matches

_STOPWORDS = frozenset(
    "the a an is are to of in on and or for with be not all from that this".split()
)


def _tokens(value: str) -> set[str]:
    return {
        word for word in re.findall(r"[a-z0-9]+", normalise_text(value))
        if len(word) > 2 and word not in _STOPWORDS
    }


def token_subset(finding: Mapping[str, Any], aliases: Sequence[str]) -> bool:
    """Permissive alternative used only to measure scorer sensitivity."""
    haystack = _tokens(
        " ".join(str(finding.get(key, "")) for key in ("issue", "recommendation", "resource"))
    )
    return any((needle := _tokens(alias)) and needle <= haystack for alias in aliases)


def load_published_runs(path: Path = RESULTS_JSON) -> dict[int, list[dict[str, Any]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    metadata = document["metadata"]
    fixtures = set(metadata["fixtures"])
    repeats = metadata["repeats"]
    if len(fixtures) != 6 or repeats != 3:
        raise ValueError("expected the published six-fixture, three-repeat evaluation")
    rows: dict[int, list[dict[str, Any]]] = {index: [] for index in range(repeats)}
    for row in document["runs"]:
        if row["variant"] == "stripped":
            rows[row["run_index"]].append(row)
    for index, subset in rows.items():
        names = [row["fixture"] for row in subset]
        if len(names) != len(fixtures) or set(names) != fixtures:
            raise ValueError(f"repeat {index} has missing or duplicate fixtures")
        if any(not isinstance(row.get("llm_findings"), list) or row.get("error") for row in subset):
            raise ValueError(f"repeat {index} has incomplete model findings")
    return rows


def score_run(rows: Sequence[Mapping[str, Any]], matcher: str) -> dict[str, int]:
    if matcher not in {"substring", "token_subset"}:
        raise ValueError(f"unknown matcher: {matcher}")
    totals = {"labels": 0, "labels_hit": 0, "findings": 0, "findings_hit": 0}
    for row in rows:
        labels = load_labels(row["fixture"]).labels
        findings = row["llm_findings"]
        totals["labels"] += len(labels)
        totals["findings"] += len(findings)
        pairs = {
            (index, label.id)
            for index, finding in enumerate(findings)
            for label in labels
            if resource_matches(str(finding.get("resource", "")), label)
            and (
                semantic_matches(finding, label) is not None
                if matcher == "substring"
                else token_subset(finding, label.aliases)
            )
        }
        totals["labels_hit"] += len({label_id for _, label_id in pairs})
        totals["findings_hit"] += len({index for index, _ in pairs})
    return totals


def main() -> None:
    runs = load_published_runs()
    print("Post-hoc sensitivity on the published stripped corpus; no API calls")
    print("6 fixtures, 52 labels, 3 repeats; resource matching is identical in both rows")
    for matcher in ("substring", "token_subset"):
        scored = [score_run(runs[index], matcher) for index in sorted(runs)]
        recall = sum(row["labels_hit"] / row["labels"] for row in scored) / len(scored)
        precision = sum(row["findings_hit"] / row["findings"] for row in scored) / len(scored)
        hits = ", ".join(str(row["labels_hit"]) for row in scored)
        finding_hits = ", ".join(str(row["findings_hit"]) for row in scored)
        print(
            f"{matcher:12} recall {recall:.1%} (label hits: {hits}); "
            f"strict precision {precision:.1%} (finding hits: {finding_hits})"
        )
    print("Token-subset is unvalidated and was chosen after inspecting misses; it is not a headline score.")


if __name__ == "__main__":
    main()
