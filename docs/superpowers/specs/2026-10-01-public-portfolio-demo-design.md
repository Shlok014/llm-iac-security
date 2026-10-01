# Public portfolio demo for LLM IaC Security

## 1 October scope update: optional free-tier repair

The user asked to make live repair available with a free API key after the scanner-only
demo was deployed. The owner may set `GEMINI_API_KEY` in Streamlit Secrets for Gemini
3.8 Flash on a free-tier Google AI Studio project. Without it, the deployed app remains
a usable scanner and recorded-repair demo. The public repair path accepts only byte-for-
byte unchanged bundled fixtures, uses Checkov, caps the loop at one rewrite attempt,
and allows one request per Streamlit session. Provider quotas are the final abuse bound;
the session limit is a courtesy limit, not an identity or global rate limit. Uploaded
source never reaches Gemini. The UI must distinguish the live Gemini result from the
recorded OpenAI evaluation and disclose free-tier data use. This section supersedes
the earlier absolute no-model rule below only when `GEMINI_API_KEY` is configured.

## Purpose and success criteria

Give a recruiter or security engineer a public URL where they can run the project's real Checkov scan on a bundled Terraform or Dockerfile fixture, inspect findings and source context, and understand the verified remediation work without supplying a credential. The demo must work on a free hosting tier and must not let anonymous visitors spend the owner's model API budget.

Success means a fresh visitor can open the URL, scan a preselected fixture, see a real scanner result, inspect an already measured repair example, and reach the repository and its evaluation method. Scanner failure must remain visibly different from a clean result. A cold start or unavailable scanner must never produce a fabricated clean result.

This is a portfolio demo of the existing CLI and Streamlit view, not a hosted service for confidential production IaC. No uploaded file is persisted intentionally or sent to a model in demo mode.

## Approaches considered

1. **Streamlit Community Cloud, recommended.** Reuse `app.py` and deploy from GitHub. Add a supported Python dependency manifest, set Python 3.13, enforce public-input limits, and make model repair unavailable in demo mode. This has the smallest code and hosting footprint. Its free app can sleep and has resource limits.
2. **Vercel Python functions.** This requires reworking Streamlit into a separate frontend and API. Scanner startup, subprocess runtime, and filesystem assumptions add substantial work for no portfolio benefit.
3. **General Python web service.** It can run the current app, but free instances also sleep and add process configuration. It is a fallback if Community Cloud cannot install pinned Checkov or serve scans reliably.

## Visitor experience

The `analyse` tab opens with a bundled vulnerable fixture selected. `Scan only` invokes the existing `iac_agent` Checkov path and displays the actual findings and source lines. The public page labels bundled fixtures as deliberately vulnerable.

The repair action is disabled in public demo mode even if a deployment secret is accidentally configured. The page says why: live model repair uses a paid API and is available through the documented CLI. The existing `measured results` and `drift gate` tabs remain. Add one prominent worked example using committed evaluation artifacts: original source, accepted output, scanner before/after evidence, and the drift verdict. Label it as a recorded run, with its fixture, scanner, model snapshot, and evaluation provenance; never imply that pressing a control made a fresh model call.

An optional upload is for small, non-confidential IaC only. The UI must state that uploaded source reaches the hosted server for scanning, even though `Scan only` does not send it to a model. Accept only recognized Terraform or Dockerfile filenames, UTF-8 text, and at most 64 KiB after upload. Reject oversized input before decoding or starting a scanner. Limit the Streamlit transport upload size as well. Keep the current temporary-directory cleanup and ensure neither the uploaded content nor the scanner result enters long-lived shared cache in public mode.

## Runtime and security boundaries

`IAC_DEMO_MODE=1` is an explicit deployment setting. In that mode:

- The page never constructs `LLMClient` or calls `run_loop`, regardless of `OPENAI_API_KEY` presence. The CLI and local UI retain their existing behavior when demo mode is unset.
- Checkov is the default and only advertised hosted scanner. Trivy requires a separate binary and must be hidden or marked unavailable unless it is installed and verified on the host.
- Public uploads are bounded in size. Scanner subprocess timeout remains enforced. A scanner crash, timeout, malformed response, or parse error is shown as unavailable or unverified, never clean.
- No user supplied IaC is written outside per-run temporary storage. Public documentation must not say uploaded code "never leaves this machine" when the machine is a hosted server.

The deployment must not contain an OpenAI API key. The demo flag is a second barrier in case a key is later added by mistake; it is not a reason to configure one.

## Deployment package

Add a root `requirements.txt` that installs the package and its UI extra at the pinned versions already declared in `pyproject.toml`. Document the Community Cloud repo, branch, `app.py` entrypoint, Python 3.13 setting, and `IAC_DEMO_MODE=1` setting without recording credentials. Do not claim a live URL until a deployed instance has been opened and a scan completed successfully.

The README should gain a short `Live demo` path near its start, with a link only after launch succeeds, followed by a two sentence account of what visitors can and cannot run. The existing offline evaluation instructions remain the reproducible evidence for model repair.

## Verification

Run the existing fast tests on a supported Python version, then add targeted tests for demo-mode key suppression, upload-size and filename rejection, recorded-example provenance, and fail-closed scanner display. Smoke test the hosted app with a bundled Terraform fixture, a bundled Dockerfile fixture, and an oversized upload. Verify a scanner error stays visibly unverified. Confirm no model API call occurs. Check the deployment logs for dependency or startup failures without exposing secrets.

## Risks and limits

Free hosting may sleep and may throttle large scanner workloads. The demo promises a usable portfolio preview, not production uptime. A successful scan establishes Checkov's verdict on one file; it does not prove Terraform apply safety. The recorded repair is historical evidence, not a fresh LLM run. The current resource drift gate detects deletion or renaming of resources that carry scanner findings; it does not prove complete semantic preservation.
