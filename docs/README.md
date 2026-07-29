# Documentation

Design documentation for `llm-iac-security`, ordered as a reading path. Start with the
[root README](../README.md) for what the project is and what it claims — everything here is the
detail behind those claims.

| # | Document | The question it answers | Read it if you are |
|---|---|---|---|
| 1 | [ARCHITECTURE.md](ARCHITECTURE.md) | How is the pipeline put together, and which rules are load-bearing rather than incidental? | Everyone. It is the map the rest assume you have seen. |
| 2 | [DECISIONS.md](DECISIONS.md) | Why is it built *this* way? What did each choice cost, and what breaks if you reverse it? | Anyone about to change a design choice — several ADRs exist because the original code chose the opposite and failed silently. |
| 3 | [EVALUATION.md](EVALUATION.md) | How would we know whether this actually works? What does each metric mean, and what is its denominator? | A reviewer deciding whether to believe any number the project reports. |
| 4 | [THREAT_MODEL.md](THREAT_MODEL.md) | What does it cost you to run this? Your IaC leaves your machine — what else can go wrong, and what risk is left over? | Anyone thinking about pointing this at real infrastructure. |
| 5 | [DEVELOPMENT.md](DEVELOPMENT.md) | How do I install it, run it, test it, and avoid spending money doing so? | A contributor — or the author, six months from now. |
| 6 | [LLD.md](LLD.md) | What is going on inside one specific module, and which lines are load-bearing? | Someone about to edit `iac_agent/`. Reference material — open the section you need, do not read it end to end. |
| 7 | [UI_DESIGN.md](UI_DESIGN.md) | Why does the Streamlit page look like that, and what is it allowed to say? | Anyone about to change `app.py`, `ui_theme.py` or `.streamlit/config.toml` — the colours carry meaning, and `tests/test_app_contract.py` enforces the half of it that is mechanical. |

Two related documents live outside this directory:

- [`../README.md`](../README.md) — project overview and headline claims.
- [`../ERRATA.md`](../ERRATA.md) — corrections to the originally submitted college report. The
  submitted artifact is never edited; every correction is recorded there instead.

## Shortcuts

- **Just want to run something?** [DEVELOPMENT.md](DEVELOPMENT.md) → *Running things*. The
  scanner path and the baseline evaluation need no API key and cost nothing.
- **Assessing the engineering?** [ARCHITECTURE.md](ARCHITECTURE.md) §2 (design principles), then
  [EVALUATION.md](EVALUATION.md) §1 (why measurement is the contribution).
- **Deciding whether to trust it?** [THREAT_MODEL.md](THREAT_MODEL.md) §4, then
  [`../ERRATA.md`](../ERRATA.md).

## A convention worth knowing before you read

Every document here tags its claims: what is implemented, what is specified but not yet built,
what was measured on real tool output, and what is only a design intention. The tag vocabulary
varies slightly between documents, but the rule does not — **no document reports a measurement
that has not been taken.** Where a result is still outstanding, you will find a marked
placeholder rather than a plausible-looking number.
