#!/usr/bin/env bash
# Full validation run: lint, tests, keys, pipeline, attacks A-G, benchmarks, figures.
# Usage: scripts/run_validation.sh "<machine label>"      (from the repository root, venv active)
# Writes results/validation_logs/*.log and results/validation_logs/environment.txt.
set -u
LABEL="${1:-unlabelled machine}"
PY="${PYTHON:-python}"
LOGS=results/validation_logs
mkdir -p "$LOGS"
run() {  # run <name> <command...>
  local name="$1"; shift
  echo "== $name: $*"
  local t0=$(date +%s.%N)
  { "$@" ; echo "exit=$?"; } > "$LOGS/$name.log" 2>&1
  printf "real %.1fs\n" "$(echo "$(date +%s.%N) - $t0" | bc)" >> "$LOGS/$name.log"
  tail -3 "$LOGS/$name.log"
}
{
  echo "machine label: $LABEL"
  echo "date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "os: $(uname -srm)"; echo "cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs) x $(nproc 2>/dev/null) logical"
  echo "memory: $(awk '/MemTotal/{printf "%.1f GB", $2/1e6}' /proc/meminfo 2>/dev/null)"
  $PY --version
  $PY -c "import torch, cryptography, sklearn, numpy; print('torch', torch.__version__, '| cuda', torch.cuda.is_available(), '| cryptography', cryptography.__version__, '| scikit-learn', sklearn.__version__, '| numpy', numpy.__version__)"
  $PY -m ruff --version
  echo "git: $(git rev-parse --short HEAD 2>/dev/null || echo n/a)"
} > "$LOGS/environment.txt" 2>&1
cat "$LOGS/environment.txt"
export CHAINGUARD_HOME="${CHAINGUARD_HOME:-$PWD}"
run 1_ruff        $PY -m ruff check .
run 2_pytest      $PY -m pytest -q
run 3_keys        $PY -m cli.main keys init
run 4_pipeline    $PY -m ml_pipeline.run_pipeline
run 5_attacks     $PY -m attacks.run_all
run 6_benchmark   $PY -m scripts.benchmark --machine-label "$LABEL"
run 7_figures     $PY -m scripts.make_figures
run 8_trustlog    $PY -m scripts.trustlog_benchmark
run 9_trust_log_state $PY -m cli.main keys trust-log
echo "done: $LOGS"
