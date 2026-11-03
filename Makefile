# Local checks for code quality and security (run before pushing / PR)
# Aligns with CI: ruff, radon, xenon, bandit, pip-audit, npm audit, htmlhint, stylelint, codeql

.PHONY: check install-check-deps ruff radon bandit pip-audit npm-audit html css codeql install-node-deps security quality all

# CodeQL database and results paths
CODEQL_DB := .codeql-db
CODEQL_RESULTS := codeql-results.sarif

# Install Python tools for local checks
install-check-deps:
	pip install ruff radon xenon bandit pip-audit

# Install Node tools (htmlhint, stylelint) - requires npm
install-node-deps:
	npm ci

node_modules/.bin/htmlhint node_modules/.bin/stylelint &: package.json package-lock.json
	npm ci

# Run all checks (quality + security + frontend)
check: ruff radon bandit pip-audit npm-audit html css
	@echo "✅ All local checks passed"

# Individual check targets
ruff:
	@echo "--- Ruff (lint + format) ---"
	ruff check .
	ruff format --check .

radon:
	@echo "--- Radon CC (complexity) ---"
	radon cc run.py settings.py settings_utils.py app/ -a -s --total-average -x "app/templates/*,app/static/*"
	@echo "--- Radon MI (maintainability) ---"
	radon mi run.py settings.py settings_utils.py app/ -s -n B -x "app/templates/*,app/static/*"
	@echo "--- Xenon (fail on CC > B) ---"
	xenon --max-absolute B --max-modules B --max-average B -e "app/templates/.*,app/static/.*" run.py settings.py settings_utils.py app/

bandit:
	@echo "--- Bandit (security lint) ---"
	bandit -r run.py settings.py settings_utils.py app/ -ll -c pyproject.toml -x "app/templates/*,app/static/*"

pip-audit:
	@echo "--- pip-audit (dependency vulnerabilities) ---"
	@echo ""
	@echo "##############################################################################"
	@echo "#  ⚠️  WARNING: CVE-2024-23342 (ecdsa) IS WHITELISTED IN THIS AUDIT  ⚠️     #"
	@echo "#  Whitelisted per pymdoccbor documentation — risk is accepted.             #"
	@echo "##############################################################################"
	@echo ""
	@PY=$$(python3 -c 'import tomllib' >/dev/null 2>&1 && echo python3 || echo python3.12); \
	"$$PY" scripts/poetry_lock_requirements.py | PIP_NO_CACHE_DIR=1 pip-audit --no-deps --disable-pip -r /dev/stdin --ignore-vuln CVE-2024-23342

npm-audit:
	@echo "--- npm audit (package-lock.json) ---"
	npm audit --package-lock-only

html: node_modules/.bin/htmlhint
	@echo "--- HTML (HTMLHint) ---"
	./node_modules/.bin/htmlhint "app/templates/**/*.html" "app/static/**/*.html"

css: node_modules/.bin/stylelint
	@echo "--- CSS (stylelint) ---"
	./node_modules/.bin/stylelint 'app/static/**/*.css' --max-warnings 0

# CodeQL: requires CodeQL CLI in PATH (download from github.com/github/codeql-action/releases)
codeql:
    # download codeql bundle here: https://github.com/github/codeql-action/releases/tag/codeql-bundle-v2.24.1
	@echo "--- CodeQL (security analysis) ---"
	@command -v codeql >/dev/null 2>&1 || { echo "CodeQL CLI not found. Install from: https://github.com/github/codeql-action/releases"; exit 1; }
	rm -rf $(CODEQL_DB)
	codeql database create $(CODEQL_DB) --language=python --codescanning-config .github/codeql/codeql-config.yml
	codeql database analyze $(CODEQL_DB) --format=sarif-latest --output=$(CODEQL_RESULTS) --sarif-category=python
	@python3 scripts/codeql-summary.py $(CODEQL_RESULTS)

# Default target (run by `make` or `make all`)
all: check

# Shorthand for quick lint-only
lint: ruff
