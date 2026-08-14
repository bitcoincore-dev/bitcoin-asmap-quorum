# Bitcoin Core ASMap notes

This repository vendors Bitcoin Core under `bitcoin/` and uses its ASMap fixture
and runtime code as reference material for the quorum workflow.

## Where the real ASMap lives

- Fixture: `bitcoin/src/test/data/asmap.raw`
- Test reference: `bitcoin/test/functional/feature_asmap.py`
- Unit-test packaging: `bitcoin/src/test/CMakeLists.txt`

The `asmap.raw` file is a checked-in Bitcoin Core test artifact, not generated
by this project.

## Where Bitcoin Core uses ASMap

Bitcoin Core loads and applies ASMap when the `-asmap=<file>` option is set:

- `bitcoin/src/init.cpp` calls `DecodeAsmap(asmap_path)` during startup.
- `bitcoin/src/util/asmap.cpp` validates and decodes the binary ASMap file.
- `bitcoin/src/netgroup.cpp` maps IPs to ASNs with `NetGroupManager::GetMappedAS()`.
- `bitcoin/src/addrman.cpp` uses that mapped ASN when bucketing peers.
- `bitcoin/src/rpc/net.cpp` exposes the mapped ASN in peer RPC output.

## Why it matters

ASMap lets Bitcoin Core group peers by network ownership instead of raw IP
prefixes. That improves peer diversity in `addrman` and makes it harder for a
single ASN to dominate peer selection.

## In this repo

The Rust CLI can:

- decode `bitcoin/src/test/data/asmap.raw`
- import ASMap snapshots into claims
- replay claims into an offline consensus ASMap
- compare the resulting map against Bitcoin Core behavior

## Real-world quorum workflow

Use this when a group of maintainers wants to produce one shared ASMap from
independent peers.

### Epoch selection

An epoch is the round identifier for one consensus snapshot. Choose it before
collection starts and treat it as part of the release contract.

Rules of thumb:

1. Use exactly one epoch per collection round.
2. Publish the epoch value before any operator submits a claim.
3. Require every claim in that round to carry the same epoch.
4. Bump the epoch for the next round; do not reuse old values.
5. Prefer a human-auditable scheme, such as a release number, date bucket, or
   signed coordination message.

In this repo:

- `import` sets the epoch on the generated claims.
- `replay` groups claims by epoch and should be run with the agreed value
  explicitly in real deployments.
- `collect` defaults to epoch `1`, which is fine for smoke tests but should be
  overridden for a real release.

1. Pick an epoch and publish it before collection starts.
2. Have each operator run one peer on separate infrastructure and submit one
   claim for that epoch.
3. Prefer a fixed quorum like `3-of-5` or `5-of-9`; do not let one person
   control multiple identities.
4. Collect claims in one place, then replay them offline with the agreed
   threshold.
5. Publish the map only if the replay report verifies and the participant list
   matches the expected operators.

Suggested roles:

- **Collector**: runs `collect` or `serve` and produces a claim.
- **Coordinator**: gathers claims and runs `replay`.
- **Verifier**: runs `verify` on the final report and map.

Suggested release rule:

- require all claims to match the published epoch
- require a quorum threshold of at least two-thirds of the operators
- publish the generated map and JSON report together
- keep the raw claims file as audit evidence

Example workflow:

```bash
# each operator contributes one snapshot, then the coordinator builds claims
cargo run -- import --epoch 42 --output claims.json snapshot-a.txt snapshot-b.txt snapshot-c.txt

# coordinator replays them into one consensus artifact
cargo run -- replay --threshold 3 --epoch 42 --output quorum.map --report quorum.json \
  claims.json

# verifier checks the published artifact
cargo run -- verify quorum.json quorum.map
```

For real deployments, the `collect` command is the networked path and
`replay`/`verify` are the release gate.
