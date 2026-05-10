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

.PHONY: release
release:
	@echo Building a release
	set -e ;\
	maturin build ;\
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
	# note: tried failing on stddev and max deviations, but the tail seems to be too noisy.
	# observed repeated max+stddev failures on back to back runs on the same machine
	# so skipped those assertions and relaxed mean regression threshold, which is a little noisy on batches.

	@echo Running benchmarks and comparing with baseline
	@if [ ! -f $(BENCHMARK_RESULTS_DIR)/baseline.json ]; then \
		echo "Error: $(BENCHMARK_RESULTS_DIR)/baseline.json not found. Sym-link $(BENCHMARK_RESULTS_DIR)/baseline.json to the current baseline results"; \
		exit 1; \
	fi
	set -e ;\
	maturin develop --release ;\
	pytest tests/benchmark --benchmark-only \
		--benchmark-compare=$(BENCHMARK_RESULTS_DIR)/baseline.json -v \
		--benchmark-compare-fail=median:5% \
		--benchmark-compare-fail=mean:15%

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
