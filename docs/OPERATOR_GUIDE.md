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

