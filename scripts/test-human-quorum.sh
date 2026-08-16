#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
target_dir="$(cd "${repo_root}" && cargo metadata --no-deps --format-version 1 | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -n1)"
binary="${target_dir}/debug/bitcoin-asmap-quorum"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/hq.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

mkdir -p "${tmpdir}/data" "${tmpdir}/gpg" "${tmpdir}/bin"
chmod 700 "${tmpdir}/gpg"

cat > "${tmpdir}/bin/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -eq 0 ]]; then
  exec shasum -a 256
else
  exec shasum -a 256 "$@"
fi
EOF
chmod +x "${tmpdir}/bin/sha256sum"

cp -R "${repo_root}/data/builder-keys" "${tmpdir}/data/"
cp "${repo_root}/data/asmap-attest" "${tmpdir}/data/"
cp "${repo_root}/data/asmap-verify" "${tmpdir}/data/"

(cd "${repo_root}" && cargo build --quiet -p bitcoin-asmap-quorum --bin bitcoin-asmap-quorum)

if [[ ! -x "${binary}" ]]; then
  echo "missing built binary: ${binary}" >&2
  exit 1
fi

export GNUPGHOME="${tmpdir}/gpg"
export PATH="${tmpdir}/bin:${PATH}"
export RUST_LOG=debug
unset SSH_AUTH_SOCK
unset GPG_AGENT_INFO

pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

wait_for_file() {
  local path="$1"
  for _ in {1..180}; do
    [[ -s "$path" ]] && return 0
    sleep 1
  done
  echo "timed out waiting for $path" >&2
  return 1
}

wait_for_listen_addr() {
  local log_path="$1"
  local addr
  for _ in {1..60}; do
    if addr="$(sed -n 's/.*listening on \(\/ip[46]\/[^[:space:]]*\/tcp\/[0-9][0-9]*\).*/\1/p' "$log_path" | head -n1)"; then
      if [[ -n "${addr:-}" ]]; then
        printf '%s\n' "$addr"
        return 0
      fi
    fi
    sleep 1
  done
  echo "timed out waiting for listen address in $log_path" >&2
  return 1
}

generate_signer() {
  local signer="$1"
  gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "${signer} <${signer}@example.invalid>" rsa2048 sign 0
  local fingerprint
  fingerprint="$(gpg --with-colons --list-keys "${signer}@example.invalid" | awk -F: '/^fpr:/ { print $10; exit }')"
  gpg --export "${fingerprint}" > "${tmpdir}/data/builder-keys/${signer}.gpg"
}

signers=(op-alpha op-bravo op-charlie op-delta op-echo)
for signer in "${signers[@]}"; do
  generate_signer "$signer"
done

import_inputs=()
for signer in "${signers[@]}"; do
  snapshot="${tmpdir}/${signer}.txt"
  cp "${repo_root}/bitcoin/src/test/data/asmap.raw" "${snapshot}"
  import_inputs+=("${snapshot}")
done

relay_args=()
if [[ -n "${HUMAN_QUORUM_RELAY:-}" ]]; then
  relay_args+=(--relay "${HUMAN_QUORUM_RELAY}")
  echo "using relay bootstrap: ${HUMAN_QUORUM_RELAY}"
fi

p2p_outputs=()
bootstrap_addr=""
for idx in 0 1 2 3; do
  p2p_map="${tmpdir}/p2p-${idx}.map"
  p2p_log="${tmpdir}/p2p-${idx}.log"
  p2p_outputs+=("${p2p_map}")
  p2p_args=()
  if [[ -n "${bootstrap_addr}" ]]; then
    p2p_args+=(--bootstrap "${bootstrap_addr}")
  fi
  serve_args=(
    serve
    --threshold 3
    --epoch 1772726400
    --epoch-secs 3600
    --topic human-quorum-p2p
  )
  if [[ ${#relay_args[@]} -gt 0 ]]; then
    serve_args+=("${relay_args[@]}")
  fi
  if [[ ${#p2p_args[@]} -gt 0 ]]; then
    serve_args+=("${p2p_args[@]}")
  fi
  serve_args+=("${import_inputs[$idx]}" "${p2p_map}")
  "${binary}" "${serve_args[@]}" 2>&1 | tee "${p2p_log}" &
  pids+=("$!")
  if [[ -z "${bootstrap_addr}" ]]; then
    bootstrap_addr="$(wait_for_listen_addr "${p2p_log}")"
    echo "using local bootstrap: ${bootstrap_addr}"
  fi
done

for p2p_map in "${p2p_outputs[@]}"; do
  wait_for_file "${p2p_map}"
done

for idx in 0 1 2 3; do
  wait_for_file "${tmpdir}/p2p-${idx}.json"
done

cleanup
pids=()

claims="${tmpdir}/claims.json"
(cd "${repo_root}" && cargo run -p bitcoin-asmap-quorum -- import --epoch 1772726400 --sender-prefix human-quorum --output "${claims}" "${import_inputs[@]}")

for signer in "${signers[@]}"; do
  "${script_dir}/_release_round.sh" \
    --data-dir "${tmpdir}/data" \
    --epoch 1772726400 \
    --signer "${signer}" \
    --claims "${claims}" \
    --state-file "${tmpdir}/${signer}.state.log"
done

(cd "${tmpdir}/data" && ./asmap-verify)

for signer in "${signers[@]}"; do
  test -f "${tmpdir}/data/attestations/2026/1772726400/${signer}/SHA256SUMS"
  test -f "${tmpdir}/data/attestations/2026/1772726400/${signer}/SHA256SUMS.asc"
done

test -f "${tmpdir}/data/latest_asmap.dat"

artifact_dir="${repo_root}/crates/bitcoin-asmap-quorum/tests"
mkdir -p "${artifact_dir}"
artifact_path="${artifact_dir}/asmap-quorum-$(date -u +%s).raw"
cp "${tmpdir}/data/latest_asmap.dat" "${artifact_path}"
echo "wrote quorum artifact to ${artifact_path}"
