#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-asmap-publish-test.XXXXXX")"
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

PATH="${tmpdir}/bin:${PATH}" \
"${script_dir}/_publish_to_data.sh" \
  --data-dir "${tmpdir}/data" \
  --epoch 1772726400 \
  --signer sr-gi \
  --map "${repo_root}/bitcoin/src/test/data/asmap.raw" \
  --no-sign \
  --no-latest

test -f "${tmpdir}/data/2026/1772726400_asmap.dat"
test -f "${tmpdir}/data/2026/1772726400_asmap_unfilled.dat"
test -f "${tmpdir}/data/attestations/2026/1772726400/sr-gi/SHA256SUMS"
