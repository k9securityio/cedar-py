#!/usr/bin/env bash
# Capture N release-mode pytest-benchmark runs at HEAD for `make benchmark-compare`.
#
# Unlike capture_history.sh, this script does NOT switch branches, NOT require
# a clean working tree, and NOT write into the committed historical record
# (tests/benchmark/results/Darwin-CPython-3.11-64bit/). It writes ephemeral
# per-run JSONs into tests/benchmark/results/current/ (gitignored), which the
# comparator (aggregate.py --compare-current) then aggregates and gates on
# median Δ vs baseline.json.
#
# Run count: BENCHMARK_RUNS (default 5).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if [ ! -d "venv-dev" ]; then
  echo "ERROR: venv-dev not found. Run 'make venv-dev' first." >&2
  exit 1
fi
# shellcheck disable=SC1091
source venv-dev/bin/activate

RUNS="${BENCHMARK_RUNS:-5}"
OUT_DIR="$REPO_ROOT/tests/benchmark/results/current"

echo "===== HEAD: $(git log --oneline -1) ====="
echo "===== RUNS=$RUNS  OUT_DIR=${OUT_DIR#$REPO_ROOT/} ====="

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "---- building (release) at $(date +%H:%M:%S) ----"
maturin develop --release 2>&1 | tail -3

for n in $(seq 1 "$RUNS"); do
  out="$OUT_DIR/run$n.json"
  echo "  [$(date +%H:%M:%S)] run $n -> ${out#$REPO_ROOT/}"
  pytest tests/benchmark --benchmark-only \
    --benchmark-json="$out" \
    -q 2>&1 | tail -3
done

echo "===== DONE at $(date +%H:%M:%S) ====="
