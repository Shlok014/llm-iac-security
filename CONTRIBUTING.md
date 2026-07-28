# Contributing

Thanks for looking. This file is short on purpose: it contains only the things that are
specific to *this* repository and that have already gone wrong once. The long-form guide —
setup, layout, cost model, troubleshooting — is [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md),
and the reasoning behind each rule below is in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Start here

```bash
make setup     # venv on python3.11-3.13, editable install with the dev + ui extras
make test      # fast hermetic suite: no network, no subprocess, no API key
make lint      # ruff
```

`make help` lists everything. Every target in the Makefile is free — nothing in it calls a
model or reads `OPENAI_API_KEY`.

---

## Five rules

Each of these exists because of a defect documented in [`ERRATA.md`](ERRATA.md), not because
of a style preference. Breaking one returns the project to a state it was rebuilt out of.

### 1. Python 3.11, 3.12 or 3.13 — never 3.14

Checkov 3.2.489 crashes on import under 3.14, inside its `networkx` dependency:

```
AttributeError: 'wrapper_descriptor' object has no attribute '__annotate__'
```

**Why:** checkov is the default oracle, so on 3.14 the tool cannot look at anything at all.
The bound is enforced in `pyproject.toml` (`requires-python = ">=3.11,<3.14"`) and re-checked
by `make`, because on macOS a bare `python3` is usually 3.14 and the failure looks like a bug
in this repo when it is not. Build the venv from an explicit versioned interpreter —
`make setup` does, and refuses rather than guessing. *(ERRATA [E1](ERRATA.md#e1--the-checkov-validation-step-never-executed),
closing note; [ADR-003](docs/DECISIONS.md).)*

### 2. The test suite must pass with `OPENAI_API_KEY` unset

```bash
env -u OPENAI_API_KEY .venv/bin/pytest -m ""     # what `make test-all` runs
```

**Why:** the original Checkov validation step reported a clean pass on every run for the
entire life of the project without ever executing, and nothing caught it — because there was
no suite anyone could run cheaply, offline and repeatedly. A suite that needs a key is a suite
that does not get run. *(ERRATA [E1](ERRATA.md#e1--the-checkov-validation-step-never-executed).)*

This is possible because `LLMClient` takes an injectable **`complete_fn`**: the client owns
prompt construction, kwarg negotiation and response parsing, while the thing that actually
talks to OpenAI is a parameter you replace.

```python
from iac_agent.llm import LLMClient
from iac_agent.types import IaCType

client = LLMClient(complete_fn=lambda messages: "[]")   # a complete, valid fake
client.detect_vulnerabilities(source, IaCType.TERRAFORM)
```

Optional kwargs (`cfg`, `response_format`) are negotiated from your function's signature at
construction, so a one-line `lambda` is enough; returning a bare `str` is fine. If you want a
live model call in a test, you want a scripted fake instead — `docs/DEVELOPMENT.md` has a
reusable one, and the pattern that matters is *raise* when the script runs out, so a loop that
fails to terminate is a red test rather than a line on an invoice.
*(ADR-008 in [`docs/DECISIONS.md`](docs/DECISIONS.md).)*

### 3. `eval/results/RESULTS.md` is generated — never hand-edit it

```bash
make report     # regenerates it offline from eval/results/results.json + the committed cache
```

**Why:** the submitted report's Checkov results table could not have been produced by a
Checkov run, because no Checkov run was possible. A hand-corrected number inside a generated
results file is indistinguishable from a fabricated one. If a number in `RESULTS.md` is wrong,
the harness is wrong — fix `eval/`, regenerate, and commit the regenerated file.
*(ERRATA [E2](ERRATA.md#e2--table-52s-policy-identifiers-describe-different-policies).)*

### 4. Never write a scanner rule id from memory

Every rule id that appears in code, tests, labels, docs or a commit message — checkov's
`CKV_AWS_17`, trivy's `AVD-AWS-0092` — must be copied from live scanner output, or verified
against the scanner:

```bash
.venv/bin/checkov --list | grep CKV_AWS_17
```

**Why:** the submitted report gave `CKV_AWS_3` as "EC2 security groups do not allow 0.0.0.0/0"
(it is EBS encryption), `CKV_AWS_7` as "IAM wildcard actions" (it is CMK rotation), and
`CKV_AWS_145` as "RDS publicly accessible" (it is S3 KMS encryption; the right id is
`CKV_AWS_17`). All three *sounded* right. `make baseline` fails if any id listed in
`eval/labels/` never fires, which is the mechanical version of this rule.
*(ERRATA [E2](ERRATA.md#e2--table-52s-policy-identifiers-describe-different-policies).)*

### 5. Never catch `ScannerError` and return an empty finding list

No `except ScannerError: return []`, no bare `except Exception` anywhere near a scanner, no
`if not output: # no issues found`.

**Why:** this is the exact bug the rebuild exists to remove. The original code ran
`python3 -m checkov` — which fails on every Python version, because checkov ships no
`__main__` module — got empty stdout, and returned *"Checkov ran successfully but returned no
JSON output (no issues found)."* A scanner that could not run must never be confusable with a
scanner that found nothing. That distinction is the CLI's exit code `2`, it is asserted
directly in CI, and it is why `iac-agent scan --scanner trivy` on a machine without trivy
exits `2` rather than `0`. *(ERRATA [E1](ERRATA.md#e1--the-checkov-validation-step-never-executed);
ADR-001 and ADR-002.)*

---

## Adding a fixture to `samples/`

Two things happen automatically, and both fail loudly if you skip a step:

- **Ground truth is required.** `make baseline` raises `LabelError: no ground truth for ...`
  until `eval/labels/<stem>.labels.yaml` exists. An unlabelled fixture has no denominator, and
  a metric with no denominator is the defect this harness was built to prevent.
- **Fixtures carry no explanatory comments.** An inline `# <- this is insecure` is an answer
  key leaking straight into the detection prompt; measured leakage on this corpus is **13.5
  points**. If a comment is unavoidable, make sure `eval/strip_comments.py` removes it.

Everything under `samples/` is deliberately vulnerable and must never be deployed — see
[`SECURITY.md`](SECURITY.md).

---

## Opening a pull request

Before you push:

```bash
make lint
make test-all     # -m "" — the bare `pytest` skips every check that runs a real scanner
```

CI (`.github/workflows/ci.yml`) runs lint, the fast suite with an empty `OPENAI_API_KEY`, and
then asserts the exit-code contract (`1` findings / `0` clean / `2` could-not-look) against the
real checkov binary. It needs no secrets, and it should stay that way: if a change makes CI
require `OPENAI_API_KEY`, the separation between the deterministic half and the paid half has
broken, and the fix belongs in the code rather than in the workflow.

A pull request that touches `.tf` or Dockerfile files also gets scanned by
`.github/workflows/iac-scan.yml` and gated on HIGH/CRITICAL findings *in the files it changed*.
The optional model-suggestion job is opt-in per PR via the `llm-suggest` label, and silently
does not exist on pull requests from forks.

In the description, say which numbers you re-measured and on what scanner versions. "It looks
better" is not a result; every published figure in this repo carries the command that produces
it.

## Reporting something instead

- **Bug** — [`bug_report.yml`](.github/ISSUE_TEMPLATE/bug_report.yml).
- **False positive** — [`false_positive.yml`](.github/ISSUE_TEMPLATE/false_positive.yml).
  Worth separating: for a scanner, a wrong finding costs a reviewer's trust, and the template
  asks you to distinguish an upstream rule misfiring from this repo mis-normalising it.
- **A real vulnerability in the tool** — see [`SECURITY.md`](SECURITY.md). Note that automated
  secret scanners flagging `samples/` is expected and is not a finding.
