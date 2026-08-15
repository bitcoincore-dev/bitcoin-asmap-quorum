#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

(cd "${repo_root}" && cargo test -p bitcoin-asmap-quorum --features nostr --lib tests::nostr_sidecar_emits_quorum_announcement_and_attestations -- --exact --nocapture)
