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