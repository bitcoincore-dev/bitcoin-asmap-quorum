## Scenario runner

Use `run-scenario.sh` to execute both variants for a scenario:

```bash
./scripts/run-scenario.sh real-world
./scripts/run-scenario.sh tests
```

It runs:

1. `./scripts/test-<scenario>.sh`
2. `./scripts/<scenario>.sh`

Extra arguments are forwarded to both scripts.

## Available scenarios

These scenario names match the CLI subcommands:

- `encode`
- `decode`
- `diff`
- `diff_addrs`
- `import`
- `replay`
- `compare`
- `verify`
- `download`
- `find-bottleneck`
- `serve`
- `collect`

The `serve` and `collect` scenarios are lightweight usage checks; the others
run small local or network-backed smoke workflows.

`test-find-bottleneck.sh` also saves the generated report under
`data/bottlenecks/`.

## Codec validation suite

`test-differential.sh` is not a scenario — it runs the ASMap codec's own test
suite, in two layers:

- **Python-free** (`cargo test --workspace`): property tests over randomly
  generated maps (`from_binary(to_binary(m)) == m` and the entry-list
  round-trips) plus one negative test per known codec defect. These run
  everywhere, including on machines with no `python3`.
- **Differential** (`cargo test --features python-differential`): every result
  compared against the vendored `contrib/asmap/asmap.py`, which is the
  authority on correct behaviour. Off by default so a clone without an
  interpreter still passes; when the feature is on, a missing or too-old
  `python3` is a hard failure rather than a silent skip.

Neither layer touches the network or either git submodule. Useful environment
variables: `ASMAP_TEST_SEED` (default 1234), `ASMAP_TEST_TRIALS`,
`ASMAP_TEST_ONLY_TRIAL`, `ASMAP_PYTHON`. Divergences are dumped, with a
`repro.sh`, under `target/asmap-differential-failures/`.

## Publishing to the data submodule

Use `publish-data.sh` to stage a consensus map into `./data` using the same
layout that the `data` repo expects:

```bash
./scripts/publish-data.sh --epoch 1772726400 --signer sr-gi --map quorum.map
```

- writes `data/<year>/<epoch>_asmap.dat`
- writes `data/<year>/<epoch>_asmap_unfilled.dat`
- updates `data/latest_asmap.dat` unless `--no-latest` is set
- runs `data/asmap-attest` to create `attestations/<year>/<epoch>/<signer>/SHA256SUMS`
- use `--no-sign` for staging or CI-only runs
- use `./scripts/test-publish-data.sh` for the non-networked smoke test

## Release round

Use `release-round.sh` when you want the full production-shaped flow:

```bash
./scripts/release-round.sh --epoch 1772726400 --signer sr-gi --claims claims.json
```

It runs `replay`, `verify`, and `publish-data` in order, and writes a simple
state log with `draft`, `replayed`, `verified`, `attested`, and `published`
phases. The `--no-sign` flag keeps the release staged instead of fully
published.

Use `./scripts/test-release-round.sh` for the CI-safe staging check.

Use `./scripts/test-human-quorum.sh` to simulate a 5-operator release with
ephemeral signing keys and multiple attestations. The script also copies the
resulting consensus ASMap to `crates/bitcoin-asmap-quorum/tests/asmap-quorum-<utc>.raw`, which is the
binary quorum artifact produced by `replay`/`publish-data` for that run. Set
`HUMAN_QUORUM_RELAY=/ip4/.../p2p/...` to route the peers through a shared relay
when you want to exercise the decentralized relay/DCUtR path; otherwise the
wrapper bootstraps the later peers off the first local node.

Use `./scripts/test-nostr.sh` to run the Nostr-sidecar smoke test with the
`nostr` feature enabled; it exercises the announcement/attestation emission
path used by the workflows.