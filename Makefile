# 0xRay Hunt Harness — common tasks.  Run `make` or `make help` for the list.
SHELL   := /bin/bash
HARNESS := harness
ENGINE  := engine
PYTHON  := $(if $(wildcard .venv/bin/python),$(CURDIR)/.venv/bin/python,python3)

.DEFAULT_GOAL := help
.PHONY: help setup hooks n8n-up n8n-down import bridge selfcheck e2e remediation dynamic matrix model-families assess skills-lint secret-scan

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

setup: ## Create harness/.env from the example (then edit it)
	@if [ -f $(HARNESS)/.env ]; then echo "$(HARNESS)/.env already exists"; else \
	  cp $(HARNESS)/.env.example $(HARNESS)/.env && chmod 600 $(HARNESS)/.env && \
	  echo "created $(HARNESS)/.env — set HUNT_BRIDGE_TOKEN, SMTP_*, model pool"; fi

hooks: ## Install the git pre-push hook (local CI: secret-scan + skills-lint, no Actions billing)
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true
	@echo "git hooks installed (core.hooksPath=.githooks)"

n8n-up: ## Start the hunting n8n container
	cd $(HARNESS) && docker compose -f docker-compose.hunt-n8n.yml --env-file .env up -d

n8n-down: ## Stop n8n (the data volume persists)
	cd $(HARNESS) && docker compose -f docker-compose.hunt-n8n.yml down

import: ## Import the novelty-monitor workflow into n8n
	cd $(HARNESS) && ./import-workflow.sh workflows/novelty-monitor.json

bridge: ## Start the host bridge under pm2
	cd $(HARNESS) && pm2 start ./hunt-bridge-start.sh --name hunt-bridge

selfcheck: ## Run the engine selfcheck gauntlet
	cd $(ENGINE) && $(PYTHON) scripts/selfcheck.py

e2e: ## Run the end-to-end pipeline trace
	cd $(ENGINE) && $(PYTHON) scripts/e2e.py

remediation: ## Run hunting correctness regression tests
	cd $(ENGINE) && $(PYTHON) tests/test_remediation.py

dynamic: ## Run generic runtime, evidence, adapter, and dimensional-coverage regressions
	cd $(ENGINE) && $(PYTHON) tests/test_dynamic_harness.py
	cd $(ENGINE) && $(PYTHON) tests/test_generic_runtime.py

matrix: ## Run live-local target and real-artifact support matrix
	cd $(ENGINE) && $(PYTHON) eval/run_dynamic_matrix.py

model-families: ## Run opt-in live-model family behavior checks (token cost)
	cd $(ENGINE) && $(PYTHON) eval/run_model_families.py

assess: ## Rate the dynamic harness from actual gate artifacts
	cd $(ENGINE) && $(PYTHON) eval/assess_dynamic.py

skills-lint: ## Lint all skills (frontmatter, naming, secret + identifier scan)
	cd $(ENGINE) && $(PYTHON) scripts/lint_skills.py

secret-scan: ## Fail if obvious secrets are present in the tree
	@if grep -rInE 'gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{80,}|sk_live_[0-9A-Za-z]{20,}|xoxb-[0-9A-Za-z-]{20,}|AIza[0-9A-Za-z_-]{35}' \
	    --exclude-dir=.git --exclude-dir=offensive-osint . \
	    | grep -vE 'AIzaSyA1234567890|secret_scan|secret-patterns|helpers-and-automation|lint_skills|jsdiff|recon\.py'; then \
	  echo "secret-scan: POTENTIAL SECRET FOUND (review above)"; exit 1; \
	else echo "secret-scan: clean"; fi
