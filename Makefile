# =========================================================
# Generic Python Project Makefile
# =========================================================
# Usage:
#   make <target>
#
# Run `make help` to see available targets.
# =========================================================

# Variables
PYTHON      ?= python3
PIP         ?= $(PYTHON) -m pip
DIST_DIR    := dist

# Default target
.PHONY: all
all: check build ## Run checks and build the package

# ----------------------------
# Dependency Management
# ----------------------------
.PHONY: deps
deps: ## Install dependencies
	$(PIP) install -r requirements.txt

# ----------------------------
# Quality & Testing
# ----------------------------
.PHONY: test lint typecheck format check coverage

# lint: ## Lint code
# 	ruff check src tests
#
# typecheck: ## Type-check
# 	mypy src tests

format: ## Autoformat code
	ruff format src tests

# check: lint typecheck test ## Run lint, typecheck, and test

test: ## Run test suite
	$(PYTHON) -m pytest -v tests

coverage: ## Run tests with coverage report
	$(PYTHON) -m pytest --cov=src --cov-report=term-missing

# ----------------------------
# Build & Packaging
# ----------------------------
.PHONY: build clean clean-preview install

build: clean deps ## Build distribution package
	$(PYTHON) -m build

clean: ## Remove items from CLEANUP section in .gitignore
	@tmpfile=$$(mktemp); \
	sed -n '/# >>> CLEANUP/,/# <<< CLEANUP/p' .gitignore \
		| grep -v '^#' \
		| grep -v '^[[:space:]]*$$' > $$tmpfile; \
	git ls-files --ignored --exclude-from=$$tmpfile --others --directory -z \
		| xargs -0 rm -rf; \
	rm $$tmpfile; \
	$(MAKE) -C docs/_docs_tools clean

clean-preview: ## Show what would be deleted by the `clean` target
	@tmpfile=$$(mktemp); \
	sed -n '/# >>> CLEANUP/,/# <<< CLEANUP/p' .gitignore \
		| grep -v '^#' \
		| grep -v '^[[:space:]]*$$' > $$tmpfile; \
	git ls-files --ignored --exclude-from=$$tmpfile --others --directory; \
	rm $$tmpfile

# install: build ## Install on local machine
# 	$(PIP) install $(DIST_DIR)/*.whl

# ----------------------------
# Documentation
# ----------------------------
.PHONY: docs

docs: ## Build/process documentation
	$(MAKE) -C docs/_docs_tools all

# # ----------------------------
# # Release Helpers
# # ----------------------------
# .PHONY: dist upload
#
# dist: build ## List built distributions
# 	ls -lh $(DIST_DIR)
#
# upload: build ## Upload package to PyPI (requires twine)
# 	twine upload $(DIST_DIR)/*

# ----------------------------
# Help
# ----------------------------
.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'



