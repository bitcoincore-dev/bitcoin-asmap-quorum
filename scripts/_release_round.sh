#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
usage: _release_round.sh [--data-dir DIR] [--epoch N] [--signer NAME] [--claims FILE] [--threshold N] [--topic NAME] [--local-peer-id ID] [--state-file FILE] [--no-sign] [--no-latest]

Runs replay -> verify -> publish-data as one release round and records the
phase transitions in a state log.
EOF
}

data_dir="${repo_root}/data"
claims=""
epoch=""
signer=""
threshold="3"
topic="bitcoin-asmap-quorum"
local_peer_id="offline-replay"
state_file=""
no_sign=0
no_latest=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data-dir)
      data_dir="$2"
      shift 2
      ;;
    --claims)
      claims="$2"
      shift 2
      ;;
    --epoch)
      epoch="$2"
      shift 2
      ;;
    --signer)
      signer="$2"
      shift 2
      ;;
    --threshold)
      threshold="$2"
      shift 2
      ;;
    --topic)
      topic="$2"
      shift 2
      ;;
    --local-peer-id)
      local_peer_id="$2"
      shift 2
      ;;
    --state-file)
      state_file="$2"
      shift 2
      ;;
    --no-sign)
      no_sign=1
      shift
      ;;
    --no-latest)
      no_latest=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$claims" || -z "$epoch" || -z "$signer" ]]; then
  usage
  exit 1
fi

if [[ ! "$data_dir" = /* ]]; then
  data_dir="${repo_root}/${data_dir}"
fi

if [[ -z "$state_file" ]]; then
  state_file="$(mktemp "${TMPDIR:-/tmp}/bitcoin-asmap-release.XXXXXX.log")"
fi

if [[ ! "$state_file" = /* ]]; then
  state_file="${repo_root}/${state_file}"
fi

state_dir="$(dirname -- "$state_file")"
mkdir -p "$state_dir"
: > "$state_file"

log_state() {
  printf '%s phase=%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" | tee -a "$state_file"
}

run_cargo() {
  (cd "${repo_root}" && cargo run -p bitcoin-asmap-quorum -- "$@")
}

log_state draft "claims=${claims} epoch=${epoch} threshold=${threshold} topic=${topic} local_peer_id=${local_peer_id}"

map_path="$(mktemp "${TMPDIR:-/tmp}/bitcoin-asmap-release.XXXXXX.map")"
report_path="$(mktemp "${TMPDIR:-/tmp}/bitcoin-asmap-release.XXXXXX.json")"
trap 'rm -f "${map_path}" "${report_path}"' EXIT

run_cargo replay --threshold "${threshold}" --epoch "${epoch}" --topic "${topic}" --local-peer-id "${local_peer_id}" --output "${map_path}" --report "${report_path}" "${claims}"
log_state replayed "map=${map_path} report=${report_path}"

run_cargo verify "${report_path}" "${map_path}"
log_state verified "report=${report_path} map=${map_path}"

publish_args=(--data-dir "${data_dir}" --epoch "${epoch}" --signer "${signer}" --map "${map_path}")
if [[ "$no_sign" -eq 1 ]]; then
  publish_args+=(--no-sign)
fi
if [[ "$no_latest" -eq 1 ]]; then
  publish_args+=(--no-latest)
fi

"${repo_root}/scripts/publish-data.sh" "${publish_args[@]}"
log_state attested "data_dir=${data_dir} signer=${signer}"

if [[ "$no_sign" -eq 0 ]]; then
  (cd "${data_dir}" && ./asmap-verify)
  log_state published "data_dir=${data_dir} signer=${signer}"
else
  log_state staged "data_dir=${data_dir} signer=${signer} verification=skipped"
fi

echo "release round complete; state log: ${state_file}"
