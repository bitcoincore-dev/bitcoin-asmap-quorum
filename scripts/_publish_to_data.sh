#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
usage: _publish_to_data.sh [--data-dir DIR] [--epoch N] [--signer NAME] [--map FILE] [--no-sign] [--no-latest]

Stages a consensus ASMap into the data submodule layout, then writes the
attestation manifest through ./data/asmap-attest.
EOF
}

data_dir="${repo_root}/data"
epoch=""
signer=""
map_path=""
no_sign=0
no_latest=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data-dir)
      data_dir="$2"
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
    --map)
      map_path="$2"
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

if [[ -z "$epoch" || -z "$signer" || -z "$map_path" ]]; then
  usage
  exit 1
fi

if [[ ! "$data_dir" = /* ]]; then
  data_dir="${repo_root}/${data_dir}"
fi

if [[ ! -d "$data_dir" ]]; then
  echo "data directory does not exist: ${data_dir}" >&2
  exit 1
fi

year_from_epoch() {
  local value="$1"
  if date -d "@${value}" +%Y >/dev/null 2>&1; then
    date -d "@${value}" +%Y
  else
    date -r "${value}" +%Y
  fi
}

run_cargo() {
  (cd "${repo_root}" && cargo run -p bitcoin-asmap-quorum -- "$@")
}

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/bitcoin-asmap-publish.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

tool_dir="${tmpdir}/tools"
mkdir -p "${tool_dir}"
if ! command -v sha256sum >/dev/null 2>&1; then
  cat > "${tool_dir}/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -eq 0 ]]; then
  exec shasum -a 256
else
  exec shasum -a 256 "$@"
fi
EOF
  chmod +x "${tool_dir}/sha256sum"
  export PATH="${tool_dir}:${PATH}"
fi

year="$(year_from_epoch "$epoch")"
release_dir="${data_dir}/${year}"
mkdir -p "${release_dir}"

final_result="${tmpdir}/final_result.txt"
filled_tmp="${tmpdir}/${epoch}_asmap.dat"
unfilled_tmp="${tmpdir}/${epoch}_asmap_unfilled.dat"
filled_target="${release_dir}/${epoch}_asmap.dat"
unfilled_target="${release_dir}/${epoch}_asmap_unfilled.dat"

run_cargo decode "$map_path" "$final_result"
run_cargo encode --fill "$final_result" "$filled_tmp"
run_cargo encode "$final_result" "$unfilled_tmp"

cp "$filled_tmp" "$filled_target"
cp "$unfilled_tmp" "$unfilled_target"

if [[ "$no_latest" -eq 0 ]]; then
  cp "$filled_target" "${data_dir}/latest_asmap.dat"
fi

pushd "$data_dir" >/dev/null
env_args=(env SIGNER="$signer" ASMAP_TXT="$final_result" ENCODED_FILLED="$filled_target" ENCODED_UNFILLED="$unfilled_target" EPOCH="$epoch")
if [[ "$no_sign" -eq 1 ]]; then
  env_args+=(NO_SIGN=1)
fi
"${env_args[@]}" ./asmap-attest
popd >/dev/null

echo "published ${epoch} into ${data_dir}/${year} and attestations/${year}/${epoch}/${signer}"
