# Architecture Decision Records

Every record below documents a choice that a future maintainer might otherwise reverse without
knowing what it cost to arrive at. Several exist because the original implementation made the
opposite choice and it broke something silently; those are worth reading before touching the
code they describe.

Format: **Context** (the forcing situation), **Decision** (what was chosen), **Consequences**
(what it bought, and what it cost — the negative half is not optional).

Related: [THREAT_MODEL.md](THREAT_MODEL.md) for the security posture these decisions support.

## Index

| ADR | Decision | Status |
| --- | --- | --- |
| [001](#adr-001-fail-closed-on-scanner-failure) | Fail closed on scanner failure | Accepted — implemented |
| [002](#adr-002-invoke-checkov-via-its-console-script) | Invoke Checkov via its console script | Accepted — implemented |
| [003](#adr-003-pin-python-to-311314) | Pin Python to `>=3.11,<3.14` | Accepted — implemented |
| [004](#adr-004-support-two-scanners-rather-than-one) | Support two scanners, not one | Accepted — implemented |
| [005](#adr-005-filename-driven-output-for-remediated-files) | Filename-driven output for remediated files | Accepted — implemented |
| [006](#adr-006-python-hcl2-for-the-validity-gate-not-terraform-validate) | `python-hcl2` for the validity gate | Accepted — implemented |
| [007](#adr-007-hand-rolled-refinement-loop-not-an-agent-framework) | Hand-rolled refinement loop | Accepted — implemented |
| [008](#adr-008-injectable-complete_fn-instead-of-mocking-the-openai-sdk) | Injectable `complete_fn` over SDK mocking | Accepted — implemented |
| [009](#adr-009-commit-the-eval-response-cache) | Commit the eval response cache | Accepted — implemented |
| [010](#adr-010-structured-outputs-against-a-pinned-model-snapshot) | Structured outputs, pinned model snapshot | Accepted — implemented |
| [011](#adr-011-do-not-auto-commit-llm-generated-fixes-from-ci) | No auto-commit of generated fixes from CI | Accepted — policy |
| [012](#adr-012-freeze-the-submitted-report-publish-errata-alongside-it) | Freeze the submitted report, publish errata | Accepted |
| [013](#adr-013-the-loop-returns-best-so-far-not-last-attempt) | Loop returns best-so-far, not last-attempt | Accepted — implemented |
| [014](#adr-014-report-per-scanner-metrics-not-a-merged-total) | Per-scanner metrics, not a merged total | Accepted — implemented |

---

## ADR-001: Fail closed on scanner failure

**Status:** Accepted. Implemented in `iac_agent/scanners.py` and `iac_agent/types.py`.

**Context.** The original implementation treated an empty scanner result as a passing one:

```python
output = result.stdout.strip()
if not output:
    return {"message": "Checkov ran successfully but returned no JSON output (no issues found)."}
```

Combined with an invocation that could never work ([ADR-002](#adr-002-invoke-checkov-via-its-console-script)),
this meant every single run reported a clean pass while no validation had occurred. That is the
worst failure mode available to a security tool: it does not merely fail to help, it manufactures
confidence. A missed finding leaves the user where they already were; a fabricated clean bill of
health actively moves them backwards.

The general shape of the bug is a success-shaped return value on a failure path. Any error
representation a caller can accidentally treat as data will eventually be treated as data.

**Decision.** Scanner failure is an exception, never a value. `ScannerError` is raised for empty
output, non-JSON output, a missing binary, an unexpected exit code, and a timeout. Checkov's
exit codes `0` and `1` are accepted (`1` legitimately means "checks failed"); everything else is
a crash and is treated as one. The same principle governs `parsing.extract_json()`, which raises
`ValueError` rather than returning a sentinel, so a failed parse can never become an empty
finding list. `types.py` carries the rule in a docstring where someone about to write
`except ScannerError: pass` will see it.

**Consequences.**

- The tool can no longer report a clean result it did not earn. This is the whole point and it
  is worth the rest of the list.
- **Every caller must handle exceptions.** This is a real cost, not a rhetorical one. The CLI
  needs a distinct exit code (`2`) for scanner failure separate from "findings exist" (`1`); the
  eval harness must decide per-file whether a scanner error aborts the run or is recorded as a
  failed sample; the refinement loop must decide whether a mid-loop scanner error ends the run or
  falls back to the last good result. Each is a decision that a fail-open design let you skip —
  by getting it wrong.
- Noisier operation. A transient timeout that previously vanished into a "clean" result now
  surfaces as a traceback. That is correct behaviour and it will still be annoying.
- The guarantee is only as strong as the discipline around it: nothing prevents a caller from
  catching `ScannerError` and substituting `[]`. Enforcement is code review and the docstring,
  not the type system.

---

## ADR-002: Invoke Checkov via its console script

**Status:** Accepted. Implemented in `iac_agent/scanners.py` (`_resolve`).

**Context.** The original code ran `["python3", "-m", "checkov", "-f", path, "-o", "json"]`.
The `checkov` package ships **no `__main__` module**, so `python -m checkov` fails on every
Python version — this is not a version-specific or environment-specific problem. The command
produced no stdout, which [ADR-001](#adr-001-fail-closed-on-scanner-failure)'s predecessor logic
then interpreted as success. Two bugs in series, each individually survivable, together produced
a tool that had never once validated anything.

There is a secondary trap: `python3` on PATH is frequently not the interpreter running the tool.
Invoking the system Python from inside a virtualenv reaches an environment where the pinned
dependencies do not exist.

**Decision.** Invoke the `checkov` console script directly. Resolve it by preferring the binary
adjacent to `sys.executable` — inside a venv, that is the one installed with the pinned
dependency set — and fall back to `shutil.which` only if the sibling is absent. If neither
resolves, raise `ScannerError` naming both locations searched.

**Consequences.**

- Checkov actually runs, which recovered the entire measured baseline (70 failed checks across
  the six fixtures).
- Correct behaviour under a venv without requiring the user to activate it first.
- Depends on the console script's name and CLI contract remaining stable across Checkov versions
  — a coupling that pinning ([ADR-003](#adr-003-pin-python-to-311314)) makes acceptable rather
  than eliminating.
- The `shutil.which` fallback will execute whatever PATH resolves to first. Analysed as residual
  risk in [THREAT_MODEL.md T-07](THREAT_MODEL.md#t-07--supply-chain); accepted on the reasoning
  that an attacker-controlled PATH means the machine is already lost.
- Failure is now loud at the point of invocation, with the searched paths in the message, rather
  than silent three steps later.

---

## ADR-003: Pin Python to `>=3.11,<3.14`

**Status:** Accepted. Development environment is Python 3.13.14.

**Context.** `checkov 3.2.489` crashes on Python 3.14 — a `networkx 3.6` dataclass-slots
incompatibility surfacing during import, i.e. before any scanning happens. Python 3.11 through
3.13 work. The failure is upstream and not fixable from this project. This is not academic: the
system `python3` on the development machine is 3.14, so the naive setup path lands directly on
the broken configuration.

**Decision.** Declare `requires-python = ">=3.11,<3.14"`. Pin CI to a version inside the range.
Document that the venv interpreter, not the system one, is the supported way to run the tool.

**Consequences.**

- The scanner runs. Non-negotiable, since the scanner is the tool's only trustworthy oracle
  ([THREAT_MODEL.md T-03](THREAT_MODEL.md#t-03--prompt-injection-via-malicious-iac-comments)).
- A hard upper bound that will go stale. When Checkov supports 3.14 this ceiling must be lifted
  deliberately — an upper bound nobody revisits becomes an install failure for future users.
- Anyone on a 3.14-only system must install an older interpreter. That friction is real and is
  preferred over a tool that imports and then dies mid-scan.
- The lower bound of 3.11 reflects the modern typing syntax used throughout (`X | None`,
  `from __future__ import annotations`) and matches Checkov's own supported floor.

---

## ADR-004: Support two scanners rather than one

**Status:** Accepted. Implemented in `iac_agent/scanners.py`.

**Context.** A single scanner is a single point of both failure and opinion. Checkov and Trivy
disagree in useful ways: Checkov is policy-oriented and notably verbose on Dockerfiles; Trivy
carries the old tfsec Terraform ruleset. Measured across the six fixtures they produce **70**
and **57** findings respectively — different totals from different rule namespaces looking at
identical files.

There is an evaluation motive too. If remediation is scored against the same scanner that
produced the findings, the loop is optimising against its own grader. A second, independent
scanner that was never shown to the model gives a corroborating signal that is much harder to
game.

**Decision.** Define a `Scanner` protocol (`name`, `scan(path, iac_type) -> ScanResult`) and
implement `CheckovScanner` and `TrivyScanner` behind it. Normalise both into a shared `Finding`
dataclass with a `(rule_id, resource)` identity key, so before/after deltas are set arithmetic
regardless of which tool produced them. Select via `get_scanner(name)`.

**Consequences.**

- Independent corroboration. A fix that satisfies one scanner and not the other is visible as a
  discrepancy rather than invisible as a pass.
- Resilience: one tool being unavailable does not make the pipeline useless.
- **A normalisation layer is now a permanent maintenance cost.** Checkov's `failed_checks` with
  `check_id`/`file_line_range`/`guideline` and Trivy's `Results[].Misconfigurations[]` with
  `ID`/`CauseMetadata`/`PrimaryURL` are mapped by hand. Every upstream JSON schema change breaks
  it, and it will break quietly — a renamed field yields empty strings, not an error.
- Severity vocabularies do not align between the tools, so severity is stored lowercased and
  otherwise unharmonised. Cross-scanner severity comparison is not supported and should not be
  attempted without doing that work properly.
- Adding a third scanner is cheap; the protocol is the whole extension point.
- Trivy is an external binary rather than a Python dependency, so it cannot be pinned by the
  Python package manager and must be installed and version-checked separately.

---

## ADR-005: Filename-driven output for remediated files

**Status:** Accepted. Implemented as `IaCType.output_name` in `iac_agent/types.py`.

**Context.** Both Checkov and Trivy select their Dockerfile rulesets **by filename**, not by
content. The original code wrote every remediated file to `outputs/fixed/fixed.tf` regardless of
input type, so a remediated Dockerfile was handed to the scanner as Terraform. The scanner found
no Terraform resources in it and reported a clean pass.

Measured: identical Dockerfile content produces **0** findings when named `.tf` and **6** when
named `Dockerfile`. A hardcoded output filename was silently suppressing every Dockerfile rule in
the tool — and, being a "clean" result, looked like the tool working perfectly.

**Decision.** Derive the output filename from the detected IaC type. `IaCType.output_name`
returns `fixed.tf` for Terraform and `Dockerfile` for Docker. Input routing uses
`detect_iac_type()`, which matches Dockerfiles by filename substring for exactly the same reason
the scanners do. The property carries a docstring explaining why it is load-bearing, because it
looks like a trivial helper and deleting it would silently disable half the tool.

**Consequences.**

- Dockerfile rules apply to Dockerfiles. The full Dockerfile finding counts in the baseline are
  reachable at all.
- Output naming is now a correctness concern rather than a cosmetic one, which is unusual enough
  to need documenting where a maintainer will find it.
- Only two IaC types are supported. YAML-based formats (CloudFormation, Kubernetes manifests,
  Helm) are out of scope — the old Streamlit UI advertised `.yml`/`.yaml` uploads that nothing
  downstream handled correctly.
- `detect_iac_type()` raises `UnsupportedFileError` on anything unrecognised rather than guessing.
  A wrong guess reintroduces exactly this bug.
- Writing two outputs into one directory collides on name. Callers must scope output paths per
  input file.

---

## ADR-006: `python-hcl2` for the validity gate, not `terraform validate`

**Status:** Accepted. Implemented in `iac_agent/validity.py`.

**Context.** A model can return text that is not valid Terraform: truncated blocks, a leaked
markdown fence, invented syntax. Scoring such output as an improvement — or worse, writing it
over something usable — has to be prevented before any scan comparison happens.

The obvious tool is `terraform validate`. It requires `terraform init`, which downloads provider
plugins: the AWS provider alone is in the hundreds of megabytes, and a realistic fixture set
pulls roughly ~600 MB. On a machine with 8 GB of RAM, a tight disk budget, and no cloud account
to validate against, that is a disproportionate price. It also makes CI slow and network-dependent
for a check whose job is "did the model emit parseable HCL".

Meanwhile `bc-python-hcl2 0.4.3` is already installed — it ships as a Checkov dependency — and
parses all six fixtures. Zero additional install, zero additional supply-chain surface
([THREAT_MODEL.md T-07](THREAT_MODEL.md#t-07--supply-chain)).

**Decision.** Gate validity by parsing: `hcl2.loads()` for Terraform, and a bounded
Dockerfile instruction check for known operations and required arguments (including JSON-form
COPY and RUN heredocs). Output that fails the gate is rejected as a candidate and
never scored. `extract_resources()` builds on the same parse, so the resource inventory used for
drift measurement comes from the parser rather than from regex over the text.

**Consequences.**

- Fast, offline, no network, no cloud credentials, no provider download. The whole eval harness
  stays runnable on a laptop.
- The parser is reused for drift detection, so one dependency serves two purposes.
- **Syntax-level validity only.** No provider schema validation. A file declaring
  `resource "aws_s3_bucket" "x" { not_a_real_argument = true }` parses cleanly and passes the
  gate. `terraform validate` would catch that; this does not. This is the central cost and it is
  accepted knowingly.
- No type checking, no variable resolution, no module resolution, no `terraform plan`. The gate
  proves the file parses — nothing more. Stated as a non-goal in
  [THREAT_MODEL.md §6](THREAT_MODEL.md#6-non-goals) so no reader infers otherwise.
- Depends on a Checkov transitive dependency. If Checkov drops or replaces `bc-python-hcl2`, this
  becomes a direct dependency to declare. It should arguably be declared directly regardless.
- The Dockerfile check is deliberately shallow. It catches unknown instructions, missing
  arguments, and destructive changes to base stages, copy sources, or startup presence. It does
  not prove that the image builds or behaves the same way.

---

## ADR-007: Hand-rolled refinement loop, not an agent framework

**Status:** Accepted. Implemented in `iac_agent/loop.py`.

**Context.** The loop is: scan baseline → detect → fix → validity gate → rescan → distil the
remaining failures → re-fix, with bounded iterations. LangChain, LangGraph, and CrewAI all
provide machinery for this. The reference work in this area (Toprani & Madisetti,
*"LLM Agentic Workflow for Automated Vulnerability Detection and Remediation in
Infrastructure-as-Code"*, IEEE Access vol. 13, 2025, DOI
[10.1109/ACCESS.2025.3560911](https://doi.org/10.1109/ACCESS.2025.3560911)) goes further still,
using RAG and multi-agent orchestration on Amazon Bedrock across 10 CloudFormation templates.

At this project's scale the control flow is roughly eighty lines. A framework would wrap those
eighty lines in an abstraction with its own vocabulary, its own version churn, and a transitive
dependency tree considerably larger than the code it manages. It would also blur the one thing
this project most needs to state precisely: which component decides whether the tool has
succeeded. Here that is the scanner, not the model, and that distinction is a security property
([THREAT_MODEL.md T-03](THREAT_MODEL.md#t-03--prompt-injection-via-malicious-iac-comments)) — not
something to hide inside someone else's orchestrator.

**Decision.** Write the loop by hand with explicit, named stop conditions. `StopReason` has
exactly four values: `CONVERGED`, `MAX_ITERS`, `NO_PROGRESS`, `TOKEN_BUDGET`. No RAG, no
multi-agent orchestration, no framework dependency. The project's contribution relative to the
reference work is not orchestration sophistication — it is a real evaluation harness and drift
measurement, which the loop's simplicity makes possible to reason about.

**Consequences.**

- Every iteration, every termination condition, and every token spent is traceable to a line of
  code, and explainable in an interview without reciting framework internals.
- No transitive dependency tree for orchestration, which materially shrinks the supply-chain
  surface.
- The token budget is a hard stop rather than an emergent property, which matters when the
  project is funded out of a student's pocket.
- **No free tracing or observability.** Frameworks give run trees, span timing, replay, and
  hosted dashboards. This has structured logging and whatever is written by hand. Debugging a
  bad run means reading logs.
- No free retries, no rate-limit backoff, no provider fallback, no streaming — each is a small
  amount of work that has to be done or deliberately skipped.
- The decision does not scale. Add tool use, parallel branches, or a second cooperating model and
  a hand-rolled loop becomes the wrong answer. Revisit at that point rather than defending this
  record.
- The word "agentic": the bounded refinement loop — where scanner feedback changes the next
  action and a stop condition is evaluated — is what earns the term. A straight-line
  detect→fix→report pipeline does not, whatever the original report called it.

---

## ADR-008: Injectable `complete_fn` instead of mocking the OpenAI SDK

**Status:** Accepted. Implemented in `iac_agent/llm.py`.

**Context.** Every test and the entire evaluation harness need model responses. The usual
approach is patching the SDK — `unittest.mock.patch("openai.OpenAI")` — which couples the test
suite to the SDK's internal object graph (`client.chat.completions.create(...)` returning objects
with `.choices[0].message.content`). SDK internals move; `openai` has already had one major
rewrite. Mocks that mirror a vendor's object shape break on their release schedule, not yours,
and they fail in ways that look like product bugs.

The harder constraint: this is a student project with no budget. Anything that requires a live
API call to run — tests, CI, metric regeneration — is something that will stop being run.

**Decision.** `LLMClient` accepts a `complete_fn` callable. The default wraps the OpenAI SDK;
tests and the eval harness inject their own — a canned response, a scripted sequence, a fixture
reader, a cache lookup. The seam sits at the boundary of *our* code, and its contract (text in,
text out) is one we control.

**Consequences.**

- Tests run with no API key, no network, and no spend. They therefore actually run, in CI, on
  every push.
- Deterministic failure modes are trivially testable: malformed JSON, a leaked markdown fence, a
  truncated file, an empty response. These are the cases that matter for
  [ADR-001](#adr-001-fail-closed-on-scanner-failure), and they are painful to trigger against a
  live API.
- The eval cache is a `complete_fn`, so replay and record are the same code path
  ([ADR-009](#adr-009-commit-the-eval-response-cache)).
- A local model backend is a `complete_fn` too — which is what makes removing the third-party
  disclosure boundary tractable ([THREAT_MODEL.md §4](THREAT_MODEL.md#4-primary-disclosure-your-iac-leaves-your-machine)).
- **The real SDK contract is never exercised by the test suite.** An `openai` breaking change, an
  auth failure, a rate-limit response shape, or a model that stops honouring structured outputs
  passes every test and fails in production. Mitigation is one thin, opt-in integration test
  gated on the API key being present — it must exist, and it must be understood as the only place
  the real contract is checked.
- Injected responses reflect what the author *expected* the model to return. Fixtures recorded
  from real calls are less prone to that bias than fixtures written by hand, and should be
  preferred wherever the case allows.

---

## ADR-009: Commit the eval response cache

**Status:** Accepted. Implemented — the cache is committed under `eval/cache/`.

**Context.** Evaluation results in an LLM project are usually unreproducible: the reader has no
key, no budget, or gets different output because the model moved underneath them. A results
table nobody can regenerate is an assertion, not a measurement — and this project's entire
premise is that the original submission asserted results it had never measured
([ADR-012](#adr-012-freeze-the-submitted-report-publish-errata-alongside-it)). Publishing another
unverifiable table would repeat the mistake in a more sophisticated form.

**Decision.** Commit the response cache to the repository. `eval/run_eval.py` reads from cache by
default, so anyone who clones the repo can regenerate `eval/results/RESULTS.md` offline, with no
key and no spend, and get byte-identical numbers. Cache keys incorporate the prompt text, the
pinned model snapshot, and the `prompt_version`
([ADR-010](#adr-010-structured-outputs-against-a-pinned-model-snapshot)) so that changing a prompt
misses the cache instead of silently returning a response from a prompt that no longer exists.

**Consequences.**

- Reproducibility for free, for everyone, forever. This is the single strongest credibility
  signal the project can offer about its own numbers.
- CI can run the full evaluation on every push with no secret access, which also keeps the
  secret-gated job small ([THREAT_MODEL.md T-01](THREAT_MODEL.md#t-01--api-key-exposure)).
- Reviewers can read what the model actually said, rather than trusting a summary of it.
- **Repository size grows** with every model response, and grows monotonically because git keeps
  history. Superseded entries must be pruned deliberately or the repo bloats indefinitely.
- **The cache must be scrubbed before commit.** It is a transcript of everything the model was
  shown. Generated from anything but the committed fixture corpus, it becomes a permanent public
  copy of private infrastructure — analysed in full as
  [THREAT_MODEL.md T-08](THREAT_MODEL.md#t-08--eval-response-cache-leakage).
- Cached numbers age. They describe one model snapshot at one point in time, and must be labelled
  with that snapshot and the date rather than presented as a standing property of "the model".
- Cache-key discipline is load-bearing. A key that omits `prompt_version` produces results that
  look reproducible while measuring a prompt that is no longer in the repository — a failure mode
  that is nearly invisible once it happens.

---

## ADR-010: Structured outputs against a pinned model snapshot

**Status:** Accepted. Implemented in `iac_agent/llm.py` (`ModelConfig`).

**Context.** The original code asked for a JSON array in prose and parsed the reply with a bare
`json.loads`, falling back to `{"raw_output": result}` on failure. Models fence their JSON, so the
fallback fired routinely — and the stringified dict was then interpolated straight into the
remediation prompt, meaning the fixer was frequently reasoning about a Python `repr` rather than
a finding list. The failure was completely silent.

Separately, `model="gpt-4o-mini"` is a floating alias. It repoints. Any result recorded against
an alias is unreproducible by construction, because the reader cannot obtain the model that
produced it.

**Decision.** `ModelConfig` pins the dated snapshot `gpt-4o-mini-2024-07-18` with
`temperature=0`, `seed=42`, and an explicit `prompt_version` that participates in the cache key.
Detection uses the API's structured-output mode so the schema is enforced server-side rather than
requested politely. `parsing.extract_json()` is retained as a defensive fallback — models still
drift, and the fallback is tested — but it is no longer the primary path.

**Consequences.**

- Results are attributable to a specific model version, which is a precondition for the
  reproducibility claim in [ADR-009](#adr-009-commit-the-eval-response-cache).
- Schema conformance is enforced by the provider; the parser handles residual drift instead of
  carrying the whole burden.
- `prompt_version` makes prompt changes visible in the cache, in the results, and in the diff.
  Prompts are code and are versioned like code.
- **Snapshots are retired by the provider.** A pinned snapshot eventually 404s, at which point the
  results become historical and re-running requires re-recording against a new snapshot. This is
  the correct trade — a stale, honestly-labelled number beats a moving, unattributable one — but
  the expiry needs to be expected rather than discovered.
- **`temperature=0` and `seed` reduce variance; they do not guarantee determinism.** The provider
  documents best-effort reproducibility only. Any claim of bit-identical model output would be
  false; the cache is what makes the *published* numbers reproducible, not the sampling
  parameters.
- Pinning to one model means no comparative evaluation across models. A useful extension, and out
  of scope for a project with no budget for it.
- Structured outputs constrain the response shape, which can cost expressiveness on findings that
  do not fit the schema neatly.

---

## ADR-011: Do not auto-commit LLM-generated fixes from CI

**Status:** Accepted. Binding project policy; implemented in `.github/workflows/iac-scan.yml`.

**Context.** The natural next step for a tool like this is a bot: scan on push, generate a fix,
open a pull request, auto-merge when the scanner goes green. It demos beautifully. It is also the
point at which a model-generated change to production infrastructure reaches deployment with no
human having read it.

**Decision.** CI runs `iac-agent scan` (no key, no model call) and the offline evaluation. It
does not run the fixer against the repository's own files, does not commit generated output, and
does not open or merge pull requests. Remediation is a developer-initiated action whose output is
an artefact for a human to read. No `--apply` or `--in-place` flag is provided.

**Rationale, stated plainly, because this is the decision most likely to be reversed for
convenience:**

1. The optimisation target is *scanner-clean*, not *correct*. Gating a merge on a checker that
   the generator can also see is a textbook route to changes that satisfy the metric and nothing
   else.
2. A scanner-clean diff can delete resources. `compute_drift()` surfaces that; it does not
   prevent it, and nothing verifies semantic equivalence
   ([ADR-006](#adr-006-python-hcl2-for-the-validity-gate-not-terraform-validate)).
3. The generator's input is attacker-influenceable. Auto-merge turns a comment in a pull request
   into a code-execution path against a cloud account
   ([THREAT_MODEL.md T-03](THREAT_MODEL.md#t-03--prompt-injection-via-malicious-iac-comments)).
4. The blast radius is asymmetric. A missed finding leaves you where you were; a bad auto-merged
   fix creates a new outage or a new hole.

**Consequences.**

- No fully-automatic remediation story, which is a less impressive demo. Accepted.
- A human must be in the loop for every applied change, which is the intended cost, not a
  limitation to engineer away.
- The secret-gated CI job stays small, so the API key is exposed to as little workflow surface as
  possible.
- **This is policy, not enforcement.** Nothing stops a downstream user from wrapping the CLI in
  `git commit && git push`. Convenience pressure runs exactly that way, and the only defences are
  this record, the threat model, and the absence of a ready-made apply flag.

---

## ADR-012: Freeze the submitted report, publish errata alongside it

**Status:** Accepted.

**Context.** The academic report submitted in December 2025 describes results produced by code
paths that never executed. The Checkov validation step could not run
([ADR-002](#adr-002-invoke-checkov-via-its-console-script)), its empty output was reported as a
clean pass ([ADR-001](#adr-001-fail-closed-on-scanner-failure)), and remediated Dockerfiles were
scanned as Terraform ([ADR-005](#adr-005-filename-driven-output-for-remediated-files)). The
"validated" results in that document are therefore not measurements.

Two options: quietly edit the report so the public repository shows a correct version, or freeze
it and publish a correction next to it.

**Decision.** The submitted report stays exactly as submitted. `ERRATA.md` sits beside it,
enumerating each incorrect claim, the root cause, and what the corrected measurement is. The
README links the errata prominently enough that no reader encounters the report without it.

**Consequences.**

- The submitted artefact remains what was actually submitted. Retroactively editing a graded
  academic deliverable to look better is misrepresentation, regardless of how the edit is framed.
- Finding, documenting, and correcting one's own defects is a stronger demonstration of
  engineering judgement than never having had any — and it is the more honest of the two claims
  available.
- Provenance is preserved for the four original authors (Shlok Dahale, Rugved Bidwai, Swaraj
  Singh, Atharva Ahire). Silently rewriting shared work post-submission would misattribute it;
  the errata and all post-submission work are attributed to the solo maintainer.
- **The repository permanently contains a document with known-false claims.** A reader who finds
  the report without the errata is misled. This is mitigated by cross-linking, not solved by it,
  and every future restructuring of the repo must preserve that link.
- Every subsequent claim is now held to a visibly higher standard, which is the intended effect
  and the reason the [status legend](THREAT_MODEL.md#status-legend) exists.

---

## ADR-013: The loop returns best-so-far, not last-attempt

**Status:** Accepted. Implemented in `iac_agent/loop.py`.

**Context.** Iterative refinement does not improve monotonically. Iteration 3 can fix eleven of
thirteen findings; iteration 4, handed distilled feedback about the remaining two, can rewrite a
resource block and reintroduce six. The naive loop returns whatever the last iteration produced,
so hitting `MAX_ITERS` can hand the user a *worse* file than one the loop already had in hand.

**Decision.** Track every candidate that passes the validity gate along with its scan result, and
return the one with the lowest finding count. Precisely, as implemented:

- **Drift is an up-front rejection gate, not a tiebreak.** A candidate that removed a
  flaw-carrying resource is rejected outright (`rejected_because="drift: removed …"`) and is
  never eligible to become `best`. This is stronger than ranking it lower: a candidate that
  "fixes" a finding by deleting the resource is not a worse answer, it is not an answer.
- **Improvement must be strict** — `scan.failed_count < best_count`. Ties keep the incumbent,
  which prefers the earlier of two equally-good candidates and therefore biases toward the
  smaller diff.
- **The baseline is the initial `best`.** If no candidate ever improves on the original file,
  the original is what comes back. The loop cannot make things worse by running.

All four `StopReason` values return best-so-far. `CONVERGED` is not a precondition for a useful
answer; it is one of several ways the loop can end while still returning its best work.

**Consequences.**

- Output quality is monotonic in iteration count. More iterations can cost tokens without helping,
  but cannot make the returned result worse.
- `NO_PROGRESS` becomes a safe early stop rather than a decision about whether the last attempt
  was salvageable.
- Every candidate's scan result must be retained for the duration of the run — a real memory cost
  on large files, bounded by `MAX_ITERS`.
- "Best" is a ranking function, and any ranking function encodes a value judgement. Finding count
  weights a critical finding equally with an informational one; severity weighting is a plausible
  future refinement and would change which candidate wins.
- The returned result must carry its iteration index, or a reader cannot tell that the answer came
  from iteration 3 of 5. Reporting a best-so-far result without saying which attempt produced it
  would be its own small dishonesty.

---

## ADR-014: Report per-scanner metrics, not a merged total

**Status:** Accepted. Implemented in `eval/metrics.py` and `eval/render.py`.

**Context.** With two scanners ([ADR-004](#adr-004-support-two-scanners-rather-than-one)) there is
an obvious temptation to report one headline number. The measured baseline across the six
fixtures is 70 Checkov failed checks and 57 Trivy findings. "127 findings" would be a fabricated
quantity: the two tools use disjoint rule-ID namespaces, encode overlapping-but-different
policies, and count at different granularities. Summing them double-counts the overlap; taking a
union requires a semantic mapping between rulesets that does not exist and that this project has
not built. Either way the denominator for a "percentage remediated" claim would be invented — the
exact failure mode this rebuild exists to correct.

**Decision.** Report every metric per scanner, per file, always labelled with the scanner that
produced it. `eval/labels/*.labels.yaml` holds ground truth for detection scoring; scanner deltas
are reported as `before → after` counts per tool. Where a cross-scanner statement is genuinely
useful — "this fix satisfied both scanners" — it is expressed as agreement on a specific finding,
not as an arithmetic combination of totals.

**Consequences.**

- No invented denominators, and every published number traces to one tool on one file.
- Scanner disagreement is visible as a signal in its own right, rather than being averaged away.
- **No single headline metric**, which makes the results table wider and harder to skim. A reader
  who wants one number will not find one. That is the correct outcome and it costs readability.
- Semantic overlap between the two rulesets is **unmeasured**, and no claim about it is made
  anywhere in this repository.
- Adding a third scanner widens the results table rather than complicating a merge function —
  the cost scales linearly and stays honest.
