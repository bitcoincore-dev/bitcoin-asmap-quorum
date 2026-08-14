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

Recommended sequence:

1. Run `replay` to generate the consensus map and JSON report.
2. Run `decode` on the consensus map to create `final_result.txt`.
3. Run `encode` twice on `final_result.txt` to produce the filled and unfilled
   `.dat` files expected by `data/asmap-attest`.
4. Enter `./data` and run `./asmap-attest` with the epoch, signer, text result,
   and both encoded binaries.
5. Run `./asmap-verify` from `./data` to confirm the attestation layout.
6. Commit the new files in the submodule, then update the superproject pointer.

Example:

```bash
cargo run -- replay --threshold 3 --epoch 42 --output quorum.map --report quorum.json claims.json
cargo run -- decode quorum.map final_result.txt
cargo run -- encode --fill final_result.txt 42_asmap_filled.dat
cargo run -- encode final_result.txt 42_asmap_unfilled.dat
cd data
env SIGNER=<signer> \
  ASMAP_TXT=../final_result.txt \
  ENCODED_FILLED=../42_asmap_filled.dat \
  ENCODED_UNFILLED=../42_asmap_unfilled.dat \
  EPOCH=42 \
  ./asmap-attest
./asmap-verify
```

For a real release, keep the generated files organized under
`attestations/<year>/<epoch>/<signer>/` and update `latest_asmap.dat` to the
latest published binary.
