# Public IaC Portfolio Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a free, working scan-only portfolio demo of LLM IaC Security with a clearly labelled recorded repair example.

**Architecture:** Keep the current Streamlit UI and `iac_agent` scan path. Isolate public-demo policy and recorded-evidence loading in a small `demo.py` module. Deploy `app.py` through Streamlit Community Cloud with pinned package dependencies and an explicit demo-mode setting.

**Tech Stack:** Python 3.13, Streamlit 1.51.0, Checkov 3.2.489, pytest, GitHub, Streamlit Community Cloud.

**Spec:** `docs/superpowers/specs/2026-10-01-public-portfolio-demo-design.md`

## Global Constraints

- `IAC_DEMO_MODE=1` disables `LLMClient` and `run_loop` even if an API key exists; local CLI and UI behavior stays unchanged when unset.
- Demo uploads are recognized Terraform or Dockerfile filenames, UTF-8, at most 64 KiB, and never enter a long-lived shared cache.
- Hosted scans use the existing Checkov path and fail closed; the recorded repair is labelled historical and sourced from committed evaluation data.
- No API key is configured on the public deployment. Python 3.13 is required by the pinned Checkov dependency.
- Do not publish a demo URL until an actual hosted scan and failure-state check succeed.

## Review Focus

- An `OPENAI_API_KEY` mistakenly present in demo mode must still leave model actions disabled (Task 1 test).
- An uploaded 64 KiB + 1 byte file must be rejected before decode or scanner invocation (Task 1 test).
- A filename with path segments or unsupported extension must not escape the temporary directory or be scanned under the wrong framework (Task 1 test).
- A missing or malformed committed evaluation artifact must render as unavailable, never as a successful repair (Task 2 test).
- A scanner exception in public mode must remain an unverified error, not an empty findings table (Task 3 test and hosted smoke check).

---

### Task 1: Public demo policy and bounded uploads

**Files:** Create `demo.py`; modify `app.py`; test `tests/test_demo.py`.

**Interfaces:** `demo_mode() -> bool`; `validate_upload(name: str, content: bytes) -> tuple[str, str]` returning sanitized filename and decoded code or raising `ValueError`; `available_scanners(public: bool) -> list[str]` returning `['checkov']` in demo mode and existing scanner names otherwise.

- [ ] Write tests for demo-mode key suppression, exact 64 KiB boundary, oversize rejection, invalid UTF-8, path segments, supported/unsupported filenames, and scanner choices.
- [ ] Run `pytest tests/test_demo.py -q`; confirm the new behavior fails because the interfaces or policy do not exist.
- [ ] Implement the three interfaces and wire `app.py` so the fix action cannot run, uploads are validated before decoding/scanning, and hosted copy accurately says uploaded source reaches the server.
- [ ] Run `pytest tests/test_demo.py tests/test_app_contract.py -q`; confirm green, then run the full fast suite under Python 3.13.
- [ ] Commit only Task 1 files with a focused message.

### Task 2: Recorded repair evidence

**Files:** Modify `demo.py`, `app.py`; test `tests/test_demo.py`.

**Interfaces:** `load_recorded_example(root: Path) -> dict` reads `eval/results/results.json`, selects `samples/s3_public.tf` / `stripped` / run 0, validates `remediation_valid`, `after_is_before`, `drift_touches_flaw`, matching output path, and returns original text, accepted output text, model/checkov metadata, before/after counts, drift summary, and artifact path. It raises `ValueError` on missing or inconsistent evidence.

- [ ] Write a test that validates the committed example's provenance and rejects missing or mismatched evidence in a copied fixture tree.
- [ ] Run `pytest tests/test_demo.py -q`; confirm the new evidence test fails.
- [ ] Implement the loader and add a compact recorded-example section to the existing results tab, showing original, output, before/after counts, diff, provenance, and a historical-run label. Render loader failure as unverified.
- [ ] Run `pytest tests/test_demo.py tests/test_app_contract.py -q`, then the full fast suite under Python 3.13.
- [ ] Commit Task 2 files.

### Task 3: Hosted scan path and deployment package

**Files:** Modify `app.py`, `.streamlit/config.toml`, `README.md`; create `requirements.txt`; test `tests/test_demo.py`.

**Interfaces:** `_do_scan(name: str, code: str, scanner: str) -> dict` remains the UI entrypoint; public mode bypasses `st.cache_data`, while local mode retains caching. Scanner errors continue to propagate to the existing unverified UI state.

- [ ] Write a test that public scans bypass shared caching and a scanner failure does not return a findings payload.
- [ ] Run `pytest tests/test_demo.py -q`; confirm red for the uncached public path.
- [ ] Implement the uncached dispatch, set Streamlit's transport upload limit to 1 MB, add root `requirements.txt` installing `.[ui]`, and add concise README setup with Python 3.13, `app.py`, and `IAC_DEMO_MODE=1`.
- [ ] Run the targeted tests, full fast suite, lint, and a local Streamlit browser smoke check using the supported Python 3.13 environment.
- [ ] Commit Task 3 files.

### Task 4: Publish and verify

**Files:** Update `README.md` only after a successful deployment.

**Interfaces:** GitHub branch `codex/iac-public-demo`; Streamlit Community Cloud repo `Shlok014/llm-iac-security`, entrypoint `app.py`, Python 3.13, demo-mode setting.

- [ ] Push the verified branch and create a reviewable PR if the GitHub connection allows it.
- [ ] Deploy from the branch in Streamlit Community Cloud without an OpenAI API key.
- [ ] Open the public URL as a visitor; scan the bundled Terraform and Dockerfile fixtures; confirm the recorded example, disabled model action, oversize upload rejection, and unverified scanner-error behavior.
- [ ] Add the verified URL to the README, commit and push, then recheck the public URL. If account access or host limits block publication, record the exact blocker and leave the URL unpublished.
