#!/usr/bin/env bash
# Capture release-mode pytest-benchmark data at a list of historical cedarpy
# commits. Used to maintain tests/benchmark/results/history/ — the committed
# historical perf record.
#
# For each state: git checkout, maturin develop --release, then RUNS× pytest
# --benchmark-save. Native pytest-benchmark JSONs land in
# tests/benchmark/results/Darwin-CPython-3.11-64bit/.
#
# Restores the starting branch on exit (success or failure).
#
# Adding a new state: append "<save_prefix>:<git-ref>" to STATES below and
# re-run. The aggregator (aggregate.py) discovers states from filenames.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! git diff-index --quiet HEAD --; then
  echo "ERROR: working tree has uncommitted changes; aborting" >&2
  exit 1
fi

if [ ! -d "venv-dev" ]; then
  echo "ERROR: venv-dev not found. Run 'make venv-dev' first." >&2
  exit 1
fi
# shellcheck disable=SC1091
source venv-dev/bin/activate

START_BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse HEAD)"
echo "Starting on: $START_BRANCH"

STORAGE="$REPO_ROOT/tests/benchmark/results"
RUNS="${BENCHMARK_RUNS:-5}"

# save_prefix : git-ref  (chronological order)
# - tagged states use sanitized tag (dots -> underscores)
# - untagged commits use "<descriptor>_<short-sha>"
STATES=(
  "v4_8_0:v4.8.0"
  "v4_8_1:v4.8.1"
  "pr65_6f601df:6f601df"
  "pr66_500a8d0:500a8d0"
  "main_ca5d83c:ca5d83c"
)

restore_branch() {
  echo
  echo "===== Restoring on $START_BRANCH ====="
  git reset --hard >/dev/null 2>&1 || true
  git checkout "$START_BRANCH" >/dev/null 2>&1 || true
  echo "now on: $(git log --oneline -1 2>/dev/null || true)"
}
trap restore_branch EXIT

for state in "${STATES[@]}"; do
  IFS=':' read -r prefix ref <<< "$state"
  echo
  echo "==================================================================="
  echo "===== STATE: $prefix (ref=$ref) at $(date +%H:%M:%S) ====="
  echo "==================================================================="

  git reset --hard >/dev/null
  git checkout "$ref" >/dev/null 2>&1
  echo "checked out: $(git log --oneline -1)"

  echo "---- building (release) at $(date +%H:%M:%S) ----"
  maturin develop --release 2>&1 | tail -3

  for n in $(seq 1 "$RUNS"); do
    save_name="$prefix-run$n"
    echo "  [$(date +%H:%M:%S)] run $n -> $save_name"
    pytest tests/benchmark --benchmark-only \
      --benchmark-save="$save_name" \
      --benchmark-storage="$STORAGE" \
      -q 2>&1 | tail -3
  done
done

echo
echo "===== DONE at $(date +%H:%M:%S) ====="
