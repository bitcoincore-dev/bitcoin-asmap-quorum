#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
scenario="${2:-}"
shift 2 || true

if [[ -z "${mode}" || -z "${scenario}" ]]; then
  echo "usage: $0 <test|real> <scenario> [args...]" >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
fixture="${repo_root}/bitcoin/src/test/data/asmap.raw"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-asmap-quorum.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

run_cargo() {
  (cd "${repo_root}" && cargo run -- "$@")
}

prepare_text_pair() {
  run_cargo decode "${fixture}" "${tmpdir}/base.txt"
  cp "${tmpdir}/base.txt" "${tmpdir}/modified.txt"
  printf '203.0.113.0/24 AS64514\n' >> "${tmpdir}/modified.txt"
}

prepare_claims() {
  run_cargo import --epoch 42 --sender-prefix scenario --output "${tmpdir}/claims-a.json" "${tmpdir}/base.txt"
  run_cargo import --epoch 42 --sender-prefix scenario --output "${tmpdir}/claims-b.json" "${tmpdir}/base.txt" "${tmpdir}/modified.txt"
}

prepare_reports() {
  run_cargo replay -t 1 --topic scenario --output "${tmpdir}/map-a.raw" --report "${tmpdir}/report-a.json" "${tmpdir}/claims-a.json"
  run_cargo replay -t 1 --topic scenario --output "${tmpdir}/map-b.raw" --report "${tmpdir}/report-b.json" "${tmpdir}/claims-b.json"
}

case "${scenario}" in
  encode)
    run_cargo encode "${fixture}" "${tmpdir}/encoded.raw"
    test -s "${tmpdir}/encoded.raw"
    ;;
  decode)
    run_cargo decode "${fixture}" "${tmpdir}/decoded.txt"
    grep -q ' AS[0-9]' "${tmpdir}/decoded.txt"
    ;;
  diff)
    prepare_text_pair
    run_cargo diff "${tmpdir}/base.txt" "${tmpdir}/modified.txt" > "${tmpdir}/diff.txt"
    grep -q '203.0.113.0/24' "${tmpdir}/diff.txt"
    grep -q '^# Summary' "${tmpdir}/diff.txt"
    ;;
  diff_addrs)
    prepare_text_pair
    cat > "${tmpdir}/addrs.json" <<'JSON'
[
  {"address":"203.0.113.5","network":"ipv4"},
  {"address":"2001:db8::1","network":"ipv6"}
]
JSON
    run_cargo diff_addrs -s "${tmpdir}/base.txt" "${tmpdir}/modified.txt" "${tmpdir}/addrs.json" > "${tmpdir}/diff_addrs.txt"
    grep -q 'reassigned' "${tmpdir}/diff_addrs.txt"
    ;;
  import)
    prepare_text_pair
    run_cargo import --epoch 42 --sender-prefix scenario --output "${tmpdir}/claims.json" "${tmpdir}/base.txt" "${tmpdir}/modified.txt"
    test "$(grep -c '"claim_hash"' "${tmpdir}/claims.json")" -eq 2
    ;;
  replay)
    prepare_text_pair
    run_cargo import --epoch 42 --sender-prefix scenario --output "${tmpdir}/claims.json" "${tmpdir}/base.txt" "${tmpdir}/modified.txt"
    run_cargo replay -t 1 --topic scenario --output "${tmpdir}/map.raw" --report "${tmpdir}/report.json" "${tmpdir}/claims.json"
    test -s "${tmpdir}/map.raw"
    test -s "${tmpdir}/report.json"
    ;;
  compare)
    prepare_text_pair
    prepare_claims
    prepare_reports
    run_cargo compare "${tmpdir}/report-a.json" "${tmpdir}/report-b.json" > "${tmpdir}/compare.txt"
    grep -q '^203.0.113.0/24' "${tmpdir}/compare.txt"
    grep -q 'Compared' "${tmpdir}/compare.txt"
    ;;
  verify)
    prepare_text_pair
    prepare_claims
    run_cargo replay -t 1 --topic scenario --output "${tmpdir}/map.raw" --report "${tmpdir}/report.json" "${tmpdir}/claims-b.json"
    run_cargo verify "${tmpdir}/report.json" "${tmpdir}/map.raw"
    ;;
  download)
    download_dir="${tmpdir}/download"
    mkdir -p "${download_dir}"
    run_cargo download -n 18 -o "${download_dir}"
    find "${download_dir}" -type f | grep -q .
    ;;
  find-bottleneck)
    download_dir="${tmpdir}/download"
    bottleneck_dir="${tmpdir}/bottleneck"
    mkdir -p "${download_dir}" "${bottleneck_dir}"
    run_cargo download -n 18 -o "${download_dir}"
    run_cargo find-bottleneck -d "${download_dir}" -o "${bottleneck_dir}"
    bottleneck_file="$(find "${bottleneck_dir}" -name 'bottleneck.*.txt' | head -n 1)"
    test -n "${bottleneck_file}"
    grep -q ' AS' "${bottleneck_file}"
    ;;
  serve)
    usage="$(cd "${repo_root}" && cargo run -- 2>&1)"
    grep -q '^  bitcoin-asmap-quorum serve ' <<<"${usage}"
    ;;
  collect)
    usage="$(cd "${repo_root}" && cargo run -- 2>&1)"
    grep -q '^  bitcoin-asmap-quorum collect ' <<<"${usage}"
    ;;
  *)
    echo "unknown scenario: ${scenario}" >&2
    exit 1
    ;;
esac
