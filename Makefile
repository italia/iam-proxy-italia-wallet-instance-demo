# Local checks for code quality and security (run before pushing / PR)
# Aligns with CI: ruff, radon, xenon, bandit, pip-audit, htmlhint, stylelint

.PHONY: check install-check-deps ruff radon bandit pip-audit html css install-node-deps security quality all

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

# Default target (run by `make` or `make all`)
all: check

# Shorthand for quick lint-only
lint: ruff
