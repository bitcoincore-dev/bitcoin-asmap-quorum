# Copilot instructions for this repository

## Build, test, and lint

- Build: `cargo build`
- Run all tests: `cargo test`
- Run one test: `cargo test network_roundtrip_ipv4 -- --exact`
- Format check: `cargo fmt --check`
- Clippy: `cargo clippy --all-targets --all-features`

- Run the utility: `cargo run -- <encode|decode|diff|diff_addrs> ...`
- The named binary is also available: `cargo run --bin asmap-quorum -- <subcommand> ...`

## High-level architecture

- `src/lib.rs` now owns the ASMap implementation: prefix parsing, trie updates/lookups, text export, binary encode/decode, diffing, and `diff_addrs` support.
- `src/main.rs` and `src/bin/asmap-quorum.rs` are thin wrappers that call the same `bitcoin_asmap_quorum::run()` entry point.
- The CLI is subcommand-driven and mirrors the old ASMap helper workflow:
  - `encode` / `decode` convert between text and binary ASMap files.
  - `diff` compares two ASMap files.
  - `diff_addrs` compares two ASMap files against `getnodeaddresses` output.
- `contrib/asmap/` remains vendored upstream Bitcoin Core tooling for reference behavior and test cases.

## Key conventions

- Preserve the upstream ASMap text convention: `prefix AS123`, with `#` comments allowed on the same line.
- The Rust binary should stay round-trip safe: `encode` followed by `decode` should preserve the ASMap semantics even when the output is not minimal.
- IPv4 prefixes are represented through the IPv4-mapped IPv6 range internally; keep that mapping consistent when changing parsing or diff logic.
- `diff_addrs` consumes JSON shaped like `bitcoin-cli getnodeaddresses` output and filters on `network == "ipv4"` or `"ipv6"`.
- Generated binary/text ASMap files are runtime artifacts; do not treat them as source inputs.
