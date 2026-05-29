VCS_REF := $(shell git rev-parse --short HEAD)

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

submodule-cedar-integration-tests: third_party/cedar-integration-tests/
	git submodule update --init --recursive

submodules: submodule-cedar-integration-tests

.PHONY: integration-tests
integration-tests: submodules
	@echo Running integration tests
	@echo Running official Cedar integration test cases
	set -e ;\
	pytest tests/integration/test_cedar_integration_tests.py

.PHONY: corpus-tests
corpus-tests: submodules
	@echo Running auto-generated cedar corpus tests
	@echo This suite is large \(7000+ files\) and may take several minutes.
	set -e ;\
	pytest tests/integration/test_cedar_corpus_tests.py

.PHONY: release
release:
	@echo Building a release
	set -e ;\
	maturin build --release ;\
	WHEEL=$$(ls -1t target/wheels/cedarpy-*.whl | head -1) ;\
	echo "Installing $$WHEEL for test" ;\
	python -m pip install --force-reinstall --no-deps "$$WHEEL" ;\
	pytest

# Performance benchmark targets
BENCHMARK_RESULTS_DIR := tests/benchmark/results

.PHONY: benchmark
benchmark:
	@echo Running performance benchmarks
	set -e ;\
	maturin develop --release ;\
	pytest tests/benchmark --benchmark-only -v

.PHONY: benchmark-save
benchmark-save:
	@echo Running benchmarks and saving results
	@mkdir -p $(BENCHMARK_RESULTS_DIR)/out
	set -e ;\
	maturin develop --release ;\
	pytest tests/benchmark --benchmark-only \
		--benchmark-json=$(BENCHMARK_RESULTS_DIR)/out/results.$(VCS_REF).$$(date +%Y%m%d_%H%M%S).json -v

.PHONY: benchmark-compare
benchmark-compare:
	@echo Running N benchmark runs at HEAD and comparing median Δ against baseline
	@if [ ! -f $(BENCHMARK_RESULTS_DIR)/baseline.json ]; then \
		echo "Error: $(BENCHMARK_RESULTS_DIR)/baseline.json not found. Sym-link $(BENCHMARK_RESULTS_DIR)/baseline.json to a baseline-<state>-median.json first."; \
		exit 1; \
	fi
	set -e ;\
	bash tests/benchmark/run_current.sh ;\
	python3 tests/benchmark/aggregate.py --compare-current $(BENCHMARK_RESULTS_DIR)/current

.PHONY: benchmark-history
benchmark-history:
	@echo Capturing release-mode benchmark history across the commits listed in tests/benchmark/capture_history.sh
	@echo "(this takes ~30-40 min; switches branches and restores on exit)"
	set -e ;\
	bash tests/benchmark/capture_history.sh ;\
	python3 tests/benchmark/aggregate.py

.PHONY: benchmark-baseline
# Synthesize a median-of-N baseline JSON from BASELINE_STATE's committed
# historical runs (default v4_8_0; override with BASELINE_STATE=...). Output
# lands in tests/benchmark/results/baseline-<state>-median.json — a new file
# alongside the existing baseline.json, not a replacement. The maintainer
# decides when (and whether) to point `make benchmark-compare` at it.
BASELINE_STATE ?= v4_8_0
benchmark-baseline:
	@echo Synthesizing $(BENCHMARK_RESULTS_DIR)/baseline-$(BASELINE_STATE)-median.json from $(BASELINE_STATE) historical runs
	python3 tests/benchmark/aggregate.py --build-baseline-from $(BASELINE_STATE)
