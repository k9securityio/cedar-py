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


