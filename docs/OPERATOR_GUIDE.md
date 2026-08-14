# Operator guide

This project turns ASMap snapshots and RIPE RIS observations into a quorum
artifact that can be reviewed, replayed, and verified.

## Intent

- **Use `import`** to turn one or more snapshot files into claim JSON.
- **Use `replay`** to combine claims into one consensus ASMap.
- **Use `verify`** to confirm the published map matches the report.
- **Use `collect`** for the live networked RIS path.
- **Use `find-bottleneck`** and `download` for RIS inspection and fixtures.

## What a quorum means

A quorum is a threshold of independent operators agreeing on the same epoch and
claim set. The goal is not perfect trustlessness; it is a repeatable release
process with clear evidence.

## Epoch policy

1. Pick the epoch before collection starts.
2. Publish it to all operators.
3. Keep one epoch per release round.
4. Bump the epoch for the next round.
5. Reject claims that do not match the agreed epoch.

## Recommended release flow

1. Collect snapshots from each operator.
2. Run `import` to create claims.
3. Run `replay` with the agreed threshold and epoch.
4. Run `verify` on the JSON report and map.
5. Publish the report, map, and raw claims together.

## Command selection

| Need | Command |
| --- | --- |
| Convert text to binary | `encode` |
| Convert binary to text | `decode` |
| Compare two ASMaps | `diff` |
| Compare reassigned addresses | `diff_addrs` |
| Build claim JSON | `import` |
| Produce consensus output | `replay` |
| Check published output | `verify` |
| Compare two reports | `compare` |
| Download RIS dumps | `download` |
| Extract bottlenecks | `find-bottleneck` |
| Run a live peer | `serve` |
| Run RIS collection | `collect` |

## Local vs real-world usage

- **Local/test**: use the `scripts/test-<scenario>.sh` wrappers and the
  `run-scenario.sh` helper.
- **Real-world**: run the matching `scripts/<scenario>.sh` wrapper with real
  inputs and the published epoch.

## Publishing to the `data` submodule

Use this repo to produce the consensus artifact, then move the release files
into `./data` for attestation and publication.

For convenience, use `./scripts/publish-data.sh` to do the staging.

For the full operator-facing release path, use `./scripts/release-round.sh`.

Recommended sequence:

1. Run `replay` to generate the consensus map and JSON report.
2. Run `decode` on the consensus map to create `final_result.txt`.
3. Run `encode` twice on `final_result.txt` to produce the filled and unfilled
   `.dat` files expected by `data/asmap-attest`.
4. Run `./scripts/publish-data.sh` with the epoch, signer, and map path.
5. Run `./asmap-verify` from `./data` to confirm the attestation layout.
6. Commit the new files in the submodule, then update the superproject pointer.

If you want the end-to-end release flow from claims to published data, use
`./scripts/release-round.sh --claims <claims.json> --epoch <epoch> --signer <signer>`.
It records the release states (`draft`, `replayed`, `verified`, `attested`,
`published`) in a state log so the round can be audited after the fact.

Example:

```bash
./scripts/release-round.sh --epoch 42 --signer <signer> --claims claims.json
```

For a real release, keep the generated files organized under
`attestations/<year>/<epoch>/<signer>/` and update `latest_asmap.dat` to the
latest published binary.

## Release state machine

Use this release state sequence:

1. `draft` — claims exist, but no consensus artifact has been produced.
2. `replayed` — `replay` has produced a map and report for the agreed epoch.
3. `verified` — `verify` confirms the map matches the report.
4. `attested` — `publish-data` has staged the map into `./data` and created the
   attestation manifest.
5. `published` — the attested data has passed `./data/asmap-verify`.

## Reproducibility checklist

1. Announce the epoch before collection begins.
2. Keep the claims file and the replay report together.
3. Preserve the generated state log from `release-round.sh`.
4. Preserve the `attestations/<year>/<epoch>/<signer>/SHA256SUMS` file and its
   signature.
5. Keep the matching `data/<year>/<epoch>_asmap*.dat` files and the updated
   `latest_asmap.dat`.

## Operator protocol

- Use one signer identity per operator.
- Use independent infrastructure for each peer.
- Do not start a round until the coordinator publishes the epoch.
- Close the round only after the published map and attestation are verified.
- Keep the raw claims, report, and state log as audit evidence.

## Anti-Sybil guidance

- Treat one peer identity as one human operator.
- Prefer a fixed roster and a fixed quorum threshold.
- Reject duplicate or out-of-epoch claims before replay.
- Prefer public, reproducible snapshot inputs over private one-off sources.
