#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
binary="${repo_root}/target/debug/bitcoin-asmap-quorum"

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

cargo build --quiet --bin bitcoin-asmap-quorum

export GNUPGHOME="${tmpdir}/gpg"
export PATH="${tmpdir}/bin:${PATH}"
export RUST_LOG=info
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

p2p_outputs=()
for idx in 0 1 2 3; do
  p2p_map="${tmpdir}/p2p-${idx}.map"
  p2p_outputs+=("${p2p_map}")
  "${binary}" serve \
    --threshold 3 \
    --epoch 1772726400 \
    --epoch-secs 3600 \
    --topic human-quorum-p2p \
    "${import_inputs[$idx]}" \
    "${p2p_map}" \
    > "${tmpdir}/p2p-${idx}.log" 2>&1 &
  pids+=("$!")
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
(cd "${repo_root}" && cargo run -- import --epoch 1772726400 --sender-prefix human-quorum --output "${claims}" "${import_inputs[@]}")

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
