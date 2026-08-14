#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-asmap-release-test.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

mkdir -p "${tmpdir}/data"
mkdir -p "${tmpdir}/bin"
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

claims="${tmpdir}/claims.json"
state_file="${tmpdir}/release-state.log"

(cd "${repo_root}" && PATH="${tmpdir}/bin:${PATH}" cargo run -- import --epoch 1772726400 --sender-prefix scenario --output "${claims}" \
  "${repo_root}/bitcoin/src/test/data/asmap.raw" \
  "${repo_root}/bitcoin/src/test/data/asmap.raw")

PATH="${tmpdir}/bin:${PATH}" \
  "${script_dir}/_release_round.sh" \
    --data-dir "${tmpdir}/data" \
    --epoch 1772726400 \
    --signer sr-gi \
    --claims "${claims}" \
    --state-file "${state_file}" \
    --no-sign \
    --no-latest

grep -q 'phase=draft' "${state_file}"
grep -q 'phase=replayed' "${state_file}"
grep -q 'phase=verified' "${state_file}"
grep -q 'phase=attested' "${state_file}"
grep -q 'phase=staged' "${state_file}"
