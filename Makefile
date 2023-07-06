.PHONY: venv-dev
venv-dev:
	@echo Building Python virtual environment for developer
	set -e ;\
	python3 -m venv venv-dev ;\
	source venv-dev/bin/activate ;\
	pip install --upgrade pip ;\
	pip install -r requirements.txt -r requirements.dev.txt

.PHONY: fresh-requirements
fresh-requirements:
	@echo Freshening requirments files
	set -e ;\
	python3 -m piptools compile  -o requirements.txt     pyproject.toml ;\
	python3 -m piptools compile  --extra dev   -o requirements.dev.txt     pyproject.toml


.PHONY: quick
quick:
	@echo Performing 'quick' build
	set -e ;\
	maturin develop ;\
	pytest

submodule-cedar: third_party/cedar/cedar-integration-tests/
	git submodule update --init --recursive

submodules: submodule-cedar

.PHONY: integration-tests
integration-tests: submodules
	@echo Running integration tests
	@echo Running official Cedar integration test cases
	set -e ;\
	pytest tests/integration/test_cedar_integration_tests.py

.PHONY: release
release:
	@echo Building a release
	set -e ;\
	maturin build ;\
	pytest
