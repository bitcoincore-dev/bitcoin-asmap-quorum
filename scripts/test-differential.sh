#!/usr/bin/env bash
#
# Runs the whole ASMap codec validation suite: the Python-free property and
# negative tests, then the differential against the vendored
# contrib/asmap/asmap.py.
#
# Requires python3 >= 3.9 on PATH (or $ASMAP_PYTHON). No venv, no pip, no
# network, and neither git submodule is touched — both contrib/asmap scripts are
# standard library only. Takes well under a minute on a warm target/.
#
# Environment knobs, all optional:
#   ASMAP_TEST_SEED=1234      master seed; every trial derives from it
#   ASMAP_TEST_TRIALS=N       widen the sweep (nightly uses 1000)
#   ASMAP_TEST_ONLY_TRIAL=t   replay exactly one trial
#   ASMAP_PYTHON=/path/python interpreter to use as the oracle
#
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "${repo_root}"

python_bin="${ASMAP_PYTHON:-python3}"
if ! command -v "${python_bin}" >/dev/null 2>&1; then
  echo "error: ${python_bin} not found on PATH." >&2
  echo "       The differential needs the vendored reference implementation's" >&2
  echo "       interpreter. Set ASMAP_PYTHON, or run 'cargo test --workspace'" >&2
  echo "       for the Python-free property and negative tests alone." >&2
  exit 1
fi

echo "== codec property and negative tests (no python) =="
cargo test -p asmap-codec -- --nocapture

echo
echo "== CLI negative tests (no python) =="
cargo test -p bitcoin-asmap-quorum --test cli_negative -- --nocapture

echo
echo "== differential vs contrib/asmap/asmap.py =="
# --test-threads=1 keeps the per-test 'comparisons=N mismatches=N' lines
# unmangled, so the numbers can be quoted straight out of a CI log.
cargo test -p bitcoin-asmap-quorum --features python-differential \
  --test differential_python -- --nocapture --test-threads=1
