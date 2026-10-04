"""Keep the matcher sensitivity check tied to the published denominator."""

from __future__ import annotations

from eval import RESULTS_JSON
from scripts.rescore_matcher import load_published_runs, score_run, token_subset


def test_published_substring_scores_reproduce_the_original_table() -> None:
    runs = load_published_runs(RESULTS_JSON)
    assert sorted(runs) == [0, 1, 2]
    assert [score_run(runs[i], "substring")["labels_hit"] for i in range(3)] == [21, 21, 19]
    assert [score_run(runs[i], "substring")["labels"] for i in range(3)] == [52] * 3
    assert [score_run(runs[i], "token_subset")["labels_hit"] for i in range(3)] == [30, 30, 29]


def test_token_subset_handles_a_correct_paraphrase_without_becoming_the_headline() -> None:
    finding = {"issue": "SSH access is open to the world", "recommendation": "", "resource": ""}
    assert token_subset(finding, ("ssh open to the world",))
    assert not token_subset({"issue": "SSH access is restricted"}, ("ssh open to the world",))
