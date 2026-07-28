# Makefile — the free entry points to this repository.
#
# Two things about this file are deliberate.
#
# 1. **Every target here is free.** No target calls a model, reads `OPENAI_API_KEY`, or
#    touches the network. The two paid entry points (`iac-agent fix` and the eval sweep
#    with `--fresh`) have no target on purpose: spending money should be something you
#    typed, not something you tab-completed. `make help` names them so they are still
#    discoverable.
#
# 2. **Every command runs the venv's interpreter by explicit path**, never a bare
#    `python`/`python3` and never an activated shell. On macOS `python3` is commonly 3.14,
#    where checkov 3.2.489 dies inside networkx with
#    `AttributeError: 'wrapper_descriptor' object has no attribute '__annotate__'`. A
#    Makefile that inherits whatever interpreter happens to be first on PATH reintroduces
#    the single most time-consuming trap in this project. `$(PY)` is the whole fix.
#
# Compatibility note: macOS ships GNU Make 3.81, so this file uses nothing newer —
# no `.ONESHELL`, no `.SHELLFLAGS`, no `$(file ...)`. Each recipe line is one shell
# command, and multi-line recipes carry their own `\` continuations.

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------------------
# Interpreter and tool paths. Override on the command line, e.g. `make test VENV=.venv313`.
# ---------------------------------------------------------------------------------------
VENV      ?= .venv
PY        := $(VENV)/bin/python
PIP       := $(PY) -m pip
AGENT     := $(VENV)/bin/iac-agent
RUFF      := $(VENV)/bin/ruff
STREAMLIT := $(VENV)/bin/streamlit

# The interpreter `make setup` builds the venv *from*. Searched in preference order rather
# than hardcoded, because the one thing that must not happen is falling back to `python3`.
# Override explicitly if your 3.11-3.13 lives somewhere unusual:
#   make setup BOOTSTRAP_PYTHON=/opt/homebrew/bin/python3.12
BOOTSTRAP_PYTHON ?= $(shell for c in python3.13 python3.12 python3.11 \
	/opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 \
	/usr/local/bin/python3.13 /usr/bin/python3.12; do \
	  command -v "$$c" >/dev/null 2>&1 && { echo "$$c"; break; }; \
	done)

# Pass-throughs, so a target never has to be edited to add a flag.
FILE        ?=
FIXTURES    ?=
OUT         ?=
SCAN_ARGS   ?=
PYTEST_ARGS ?=
EVAL_ARGS   ?=

.PHONY: help setup check-venv test test-all lint scan baseline report ui clean

# ---------------------------------------------------------------------------------------
##@ Getting started
# ---------------------------------------------------------------------------------------

help: ## [free] Show this help (default target)
	@echo ""
	@echo "llm-iac-security"
	@echo ""
	@echo "  Every target in this file is FREE: no model call, no OPENAI_API_KEY, no network."
	@echo "  The paid paths have no target on purpose — see the bottom of this help."
	@echo ""
	@echo "Usage: make <target> [VAR=value]"
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n%s\n", substr($$0, 5); next } \
		/^[a-zA-Z0-9_.-]+:.*##/ { printf "  %-11s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "Variables"
	@echo "  FILE=path            file for 'make scan' (required by that target)"
	@echo "  FIXTURES=a.tf,b.tf   restrict 'make baseline' to named fixtures"
	@echo "  OUT=path             redirect a generated JSON artifact"
	@echo "  VENV=dir             use a different virtualenv (default: .venv)"
	@echo "  PYTEST_ARGS=...      extra pytest flags, e.g. PYTEST_ARGS='-k drift -x'"
	@echo "  EVAL_ARGS=...        extra flags for eval/run_eval.py"
	@echo ""
	@echo "Not a target, on purpose — these cost money and must be typed by hand:"
	@echo "  $(AGENT) fix FILE                        one refinement loop over one file"
	@echo "  $(PY) -m eval.run_eval run --fresh       a live sweep of the whole corpus"
	@echo ""

setup: ## [free] Build the virtualenv from Python 3.11-3.13, install the package with dev + ui extras
	@test -n "$(BOOTSTRAP_PYTHON)" || { \
	  echo "make setup: found no python3.11, 3.12 or 3.13."; \
	  echo "  A bare 'python3' is not good enough — on macOS it is usually 3.14, and"; \
	  echo "  checkov 3.2.489 crashes on import there (networkx / dataclass slots)."; \
	  echo "  Install one, then: make setup BOOTSTRAP_PYTHON=/path/to/python3.13"; \
	  exit 2; \
	}
	@echo "==> $(VENV) from $(BOOTSTRAP_PYTHON) ($$($(BOOTSTRAP_PYTHON) -V 2>&1))"
	@test -d "$(VENV)" || $(BOOTSTRAP_PYTHON) -m venv "$(VENV)"
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev,ui]"
	@echo "==> installed into $$($(PY) -V 2>&1) at $(PY)"
	@echo "==> next, all free: make test | make baseline | make report"

# Internal. Every real target depends on this, so the failure mode of a missing or wrong
# venv is one clear sentence rather than a traceback from checkov.
check-venv:
	@test -x "$(PY)" || { \
	  echo "no interpreter at $(PY). Run: make setup"; \
	  exit 2; \
	}
	@$(PY) -c 'import sys; raise SystemExit(0 if (3,11) <= sys.version_info < (3,14) else 1)' || { \
	  echo "$(PY) is $$($(PY) -V 2>&1), which is outside the supported 3.11-3.13 range."; \
	  echo "  checkov 3.2.489 does not import on 3.14. Rebuild: rm -rf $(VENV) && make setup"; \
	  exit 2; \
	}

# ---------------------------------------------------------------------------------------
##@ Checks
# ---------------------------------------------------------------------------------------

test: check-venv ## [free] Fast hermetic suite — no subprocess, no network, no API key
	env -u OPENAI_API_KEY $(PY) -m pytest -q -m "not slow" $(PYTEST_ARGS)

test-all: check-venv ## [free] Everything, including the tests that shell out to real checkov/trivy
	env -u OPENAI_API_KEY $(PY) -m pytest -m "" $(PYTEST_ARGS)

lint: check-venv ## [free] ruff, with the rule set pyproject declares
	@test -x "$(RUFF)" || { echo "no ruff at $(RUFF). Run: make setup"; exit 2; }
	$(RUFF) check .

# `env -u OPENAI_API_KEY` on both test targets is mechanical enforcement of a rule the
# project actually depends on: the suite must pass with no key, because `LLMClient` takes an
# injectable `complete_fn` and every test drives it through a scripted fake. If someone
# introduces a test that needs a live call, it fails here rather than on a colleague's
# machine or on a bill.

# ---------------------------------------------------------------------------------------
##@ Scanning and evaluation (all free)
# ---------------------------------------------------------------------------------------

scan: check-venv ## [free] Scan one file: make scan FILE=samples/s3_public.tf
	@test -n "$(FILE)" || { \
	  echo "usage: make scan FILE=samples/s3_public.tf [SCAN_ARGS='--scanner both']"; \
	  exit 2; \
	}
	@test -x "$(AGENT)" || { echo "no console script at $(AGENT). Run: make setup"; exit 2; }
	@$(AGENT) scan $(FILE) $(SCAN_ARGS) && code=0 || code=$$?; \
	  case "$$code" in \
	    0) echo "-> exit 0: the scanner ran and found nothing";; \
	    1) echo "-> exit 1: findings. This is the contract, not a make failure";; \
	    2) echo "-> exit 2: a scanner could not run. Unknown is not clean — never treat as a pass";; \
	    *) echo "-> exit $$code: outside the documented 0/1/2 contract";; \
	  esac; \
	  exit "$$code"

baseline: check-venv ## [free] Scanner-only floor over the corpus: what checkov and trivy find with no model
	$(PY) -m eval.run_eval baseline \
	  $(if $(FIXTURES),--fixtures $(FIXTURES),) $(if $(OUT),--out $(OUT),) $(EVAL_ARGS)

report: check-venv ## [free] Regenerate eval/results/RESULTS.md offline from the committed cache
	$(PY) -m eval.run_eval report $(EVAL_ARGS)
	@echo "-> eval/results/RESULTS.md is GENERATED. Commit it as produced; never hand-edit it."

# `baseline` runs the scanners and needs no key; `report` runs neither scanner nor model and
# recomputes every published table from eval/results/results.json plus the committed
# response cache. Between them they reproduce the repo's claims on a clean clone with no
# account. Every fixture in samples/ must have a matching eval/labels/<stem>.labels.yaml or
# `baseline` fails closed with a LabelError — an unlabelled fixture has no denominator, and
# a metric with no denominator is the exact defect this harness exists to prevent. Use
# FIXTURES= to scope a run to a labelled subset.

# ---------------------------------------------------------------------------------------
##@ Extras
# ---------------------------------------------------------------------------------------

ui: check-venv ## [free to start] Launch the legacy Streamlit app (its Fix button is a paid path)
	@test -x "$(STREAMLIT)" || { echo "no streamlit at $(STREAMLIT). Run: make setup"; exit 2; }
	$(STREAMLIT) run app.py

clean: ## [free] Delete caches and gitignored run artifacts
	@find . -type d -name __pycache__ -not -path './$(VENV)/*' -prune -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache .ruff_cache outputs build dist *.egg-info
	@echo "clean: left eval/cache/, eval/results/, eval/corpus/ and samples/ alone on purpose —"
	@echo "       the response cache is committed evidence, not a build artifact."
