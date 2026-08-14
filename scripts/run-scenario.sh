#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

scenario="${1:-}"
if [[ -z "${scenario}" ]]; then
  echo "usage: $0 <scenario> [args...]" >&2
  echo "runs: ${script_dir}/test-<scenario>.sh then ${script_dir}/<scenario>.sh" >&2
  exit 1
fi
shift

test_script="${script_dir}/test-${scenario}.sh"
real_script="${script_dir}/${scenario}.sh"

for script in "${test_script}" "${real_script}"; do
  if [[ ! -x "${script}" ]]; then
    echo "missing executable script: ${script}" >&2
    exit 1
  fi
done

"${test_script}" "$@"
"${real_script}" "$@"
