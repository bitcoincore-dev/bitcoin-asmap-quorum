# Copilot instructions for this repository

## Build, test, and lint

- Build: `cargo build`
- Run all tests: `cargo test`
- Run one test in the main binary: `cargo test --bin asmap-quorum test_sha256_golden_vector -- --exact`
- Format check: `cargo fmt --check`
- Clippy: `cargo clippy --all-targets --all-features`

For the bundled ASMap helper script:

- Encode/decode/diff: `python3 contrib/asmap/asmap-tool.py <encode|decode|diff|diff_addrs> ...`

## High-level architecture

- The main Rust executable lives in `src/bin/asmap-quorum.rs`; `src/main.rs` and `src/lib.rs` are currently unused placeholders.
- The Rust binary combines three concerns:
  - `AsmapEntry` and `AsmapPayload` define the JSON payload exchanged over the network.
  - `AppBehaviour` wires libp2p `gossipsub` + `mdns` into a single swarm behaviour.
  - `QuorumAggregator` deduplicates peers by `sender_id`, counts votes per `(ip_prefix, asn)`, and finalizes a consensus map once the threshold is reached.
- The runtime is a single `tokio::select!` loop that:
  - periodically broadcasts a local payload,
  - reacts to mDNS peer discovery,
  - consumes gossipsub messages,
  - writes a consensus ASMap file when quorum is reached.
- `contrib/asmap/` is a separate Bitcoin Core ASMap utility bundle. `asmap-tool.py` is the CLI front end; `asmap.py` contains the actual text/binary conversion and diff logic.

## Key conventions

- Keep the Rust payload structs and the gossipsub JSON format aligned; the network side assumes `serde_json` serialization/deserialization of `AsmapPayload`.
- Preserve the sender de-duplication rule in `QuorumAggregator`; repeated payloads from the same `sender_id` in one epoch are ignored.
- `AppBehaviour` should continue to be derived with `#[derive(NetworkBehaviour)]` so libp2p can drive both gossipsub and mDNS together.
- Generated consensus files are written as `asmap.map` and, in the current binary, also `final_result.txt`; treat these as runtime outputs, not source files.
- In `contrib/asmap/`, preserve Bitcoin Core's text format conventions (`prefix AS123`) and the existing encode/decode/diff CLI behavior.
- The Rust code is organized with section comments; keep related logic grouped the same way when extending the binary.
