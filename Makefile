# Local checks for code quality and security (run before pushing / PR)
# Aligns with CI: ruff, radon, xenon, bandit, pip-audit, htmlhint, stylelint, codeql

.PHONY: check install-check-deps ruff radon bandit pip-audit html css codeql install-node-deps security quality all

# CodeQL database and results paths
CODEQL_DB := .codeql-db
CODEQL_RESULTS := codeql-results.sarif

# Install Python tools for local checks
install-check-deps:
	pip install ruff radon xenon bandit pip-audit

# Install Node tools (htmlhint, stylelint) - requires npm
install-node-deps:
	npm install

# Run all checks (quality + security + frontend)
check: ruff radon bandit pip-audit html css
	@echo "✅ All local checks passed"

# Individual check targets
ruff:
	@echo "--- Ruff (lint + format) ---"
	ruff check .
	ruff format --check .

radon:
	@echo "--- Radon CC (complexity) ---"
	radon cc app.py routes/ service/ utils/ state.py constants.py -a -s --total-average
	@echo "--- Radon MI (maintainability) ---"
	radon mi app.py routes/ service/ utils/ state.py constants.py -s -n B
	@echo "--- Xenon (fail on CC > B) ---"
	xenon --max-absolute B --max-modules B --max-average B app.py routes/ service/ utils/

bandit:
	@echo "--- Bandit (security lint) ---"
	bandit -r app.py routes/ service/ utils/ state.py constants.py -ll -c pyproject.toml

pip-audit:
	@echo "--- pip-audit (dependency vulnerabilities) ---"
	PIP_NO_CACHE_DIR=1 pip-audit .

html:
	@echo "--- HTML (HTMLHint) ---"
	npx htmlhint "templates/**/*.html" "static/**/*.html"

css:
	@echo "--- CSS (stylelint) ---"
	npx stylelint 'static/**/*.css' --max-warnings 0

# CodeQL: requires CodeQL CLI in PATH (download from github.com/github/codeql-action/releases)
codeql:
	@echo "--- CodeQL (security analysis) ---"
	@command -v codeql >/dev/null 2>&1 || { echo "CodeQL CLI not found. Install from: https://github.com/github/codeql-action/releases"; exit 1; }
	rm -rf $(CODEQL_DB)
	codeql database create $(CODEQL_DB) --language=python --codescanning-config=.github/codeql/codeql-config.yml
	codeql database analyze $(CODEQL_DB) --format=sarif-latest --output=$(CODEQL_RESULTS) --sarif-category=python --codescanning-config=.github/codeql/codeql-config.yml
	@echo "CodeQL results written to $(CODEQL_RESULTS)"

# Default target (run by `make` or `make all`)
all: check

# Shorthand for quick lint-only
lint: ruff
