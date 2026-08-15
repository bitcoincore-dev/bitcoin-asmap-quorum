# bitcoin-asmap-quorum

Rust CLI for ASMap conversion/diff workflows plus quorum-based ASMap consensus artifacts.

For the real-world operator workflow, see `BITCOIN.md`.
For a concise operator guide, see `docs/OPERATOR_GUIDE.md`.
For scenario wrappers, see `scripts/README.md`.
For publishing into the `data` submodule, use `scripts/publish-data.sh`.
For the full claims-to-publication flow, use `scripts/release-round.sh`.
The human quorum smoke test also writes the resulting binary consensus map to
`crates/bitcoin-asmap-quorum/tests/asmap-quorum-<utc>.raw` for easy inspection.
With the `nostr` feature enabled, replay writes a matching `.nostr.json`
sidecar next to each quorum report.

## Workspace layout

```
Cargo.toml                     # virtual workspace manifest
crates/asmap-codec/            # ASMap trie + Bitcoin Core binary/text codec (std + thiserror + optional serde)
crates/bitcoin-asmap-quorum/   # CLI, libp2p quorum engine, RIS collection, reports
contrib/asmap/                 # vendored Python reference implementation
```

`cargo run -- <subcommand>` at the repository root still resolves to the
`bitcoin-asmap-quorum` binary: `asmap-codec` has no binary targets and the
quorum crate declares `default-run`. The workspace deliberately sets no
`default-members`, so bare `cargo build` / `cargo test` cover both crates.

## Build, test, and lint

```bash
cargo build --workspace
cargo test --workspace -- --nocapture
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
```

Run one named test:

```bash
# --exact matches the full path, module prefix included
cargo test tests::network_roundtrip_ipv4 -- --exact --nocapture
```

For the real RIPE RIS download cases, run them sequentially to avoid
overlapping network-heavy jobs:

```bash
cargo test -p bitcoin-asmap-quorum --test consensus_lifecycle -- --nocapture --test-threads=1
```

### Codec validation against the reference implementation

`cargo test --workspace` includes the codec's property tests
(`from_binary(to_binary(m)) == m` and the entry-list round-trips over randomly
generated maps) and a negative test for each known codec defect. Those need no
Python.

The differential suite compares every result against the vendored
`contrib/asmap/asmap.py`, which is the authority on correct behaviour. It is
behind an off-by-default feature so a clone without an interpreter still passes
`cargo test`; with the feature on, a missing or too-old `python3` is a hard
failure rather than a silent skip.

```bash
./scripts/test-differential.sh          # everything, ~25 s
cargo test -p bitcoin-asmap-quorum --features python-differential \
  --test differential_python -- --nocapture --test-threads=1
```

Both layers are hermetic: no network, no `pip`, and neither git submodule is
touched. `ASMAP_TEST_SEED` (default 1234) seeds every trial, `ASMAP_TEST_TRIALS`
widens the sweep, and `ASMAP_TEST_ONLY_TRIAL` replays exactly one; divergences
are dumped with a `repro.sh` under `target/asmap-differential-failures/`.

What the suite asserts, precisely. `to_binary` and `from_binary` are compared
byte for byte. `to_entries` (and the `decode` CLI over it) cannot be, because
`_to_entries_minimal` in `asmap.py` iterates a `set`/`dict` and so has no
defined output order: the suite therefore requires the same number of entries
*and* semantic equivalence — the Rust entry list is rebuilt into an `ASMap` and
must equal the map python produced. A run that differs only in which of two
equally minimal encodings was chosen is reported as a `TIE`, with the diverging
line printed. Ties are expected at roughly 0.2% of maps; a length or semantic
difference is a hard failure.

## Behaviour changes since v0.0.8

The codec was split into `crates/asmap-codec` and five defects were fixed
against the vendored Python reference. Four of those change observable output:

- `decode` with no flags, and `decode --fill`, now emit the collapsed
  overlapping form, matching `asmap-tool.py`. v0.0.8 ignored both flags and
  always emitted the expanded non-overlapping form, so a script that parsed its
  output sees far fewer lines now (410311 vs 741964 on `data/latest_asmap.dat`).
  `decode --nonoverlapping` reproduces the v0.0.8 output byte for byte, and the
  binary re-encoded from either text is identical.
- `--fill` now absorbs unassigned space into a covering prefix, as `asmap.py`
  does; v0.0.8 only collapsed two sibling leaves carrying the same ASN.
- A text prefix with host bits set (`1.2.3.4/8`) is an error instead of being
  silently truncated to `1.0.0.0/8`, matching `net_to_prefix` in `asmap.py`.
  Consensus reports and claim entries are exempt: those come from peers and from
  v0.0.8-era artifacts, so they are masked and logged rather than rejected.
- A text file that fails to parse is now an error. v0.0.8 turned an unparseable
  line into an empty map and wrote a zero-byte binary.

`encode` and `diff` are unchanged. `diff_addrs` prints the same content, but
equal-sized groups are now ordered rather than left in hash order, so repeated
runs produce identical output.

## Binaries

- Default binary: `bitcoin-asmap-quorum`
- Alternate binary: `asmap-quorum`

Both binaries call the same `bitcoin_asmap_quorum::run()` entrypoint.

## ASMap text format

- One mapping per line: `prefix AS<number>`
- Example: `1.2.3.0/24 AS64512`
- `#` inline comments are supported
- IPv4 and IPv6 are both accepted

## CLI reference

General form:

```bash
cargo run -- <subcommand> [options]
# or
cargo run --bin asmap-quorum -- <subcommand> [options]
```

### `encode`

Convert text ASMap to binary format.

```bash
encode [-f|--fill] [infile] [outfile]
```

- `-f, --fill`: fill unassigned ranges during export
- `infile`/`outfile` omitted means stdin/stdout

### `decode`

Convert binary ASMap to text format.

```bash
decode [-f|--fill] [-n|--nonoverlapping] [infile] [outfile]
```

- `-f, --fill`: include unassigned ranges
- `-n, --nonoverlapping`: emit non-overlapping prefixes
- `infile`/`outfile` omitted means stdin/stdout

### `diff`

Compare two ASMap files.

```bash
diff [-i|--ignore-unassigned] infile1 infile2
```

- `-i, --ignore-unassigned`: skip changes from unassigned (`AS0`)

### `diff_addrs` / `diff-addrs`

Compare ASMap assignment changes for address samples.

```bash
diff_addrs [-s|--show-addresses] infile1 infile2 addrs_file
```

- `-s, --show-addresses`: print changed addresses by reassignment bucket
- `addrs_file` must be JSON like `bitcoin-cli getnodeaddresses` output
- only entries with `network == "ipv4"` or `network == "ipv6"` are used

### `import`

Convert one or more snapshot ASMap inputs into signed claim JSON.

```bash
import [--epoch N] [--sender-prefix PREFIX] [--output FILE] snapshot1 [snapshot2...]
```

- default epoch: `1`
- default sender prefix: `snapshot`
- default output: `claims.json`
- for real quorum rounds, choose and publish the epoch before collecting claims

### `replay`

Replay claims offline to produce quorum map + JSON report.

```bash
replay [--threshold N] [--epoch N] [--topic NAME] [--local-peer-id ID] [--output FILE] [--report FILE] claims.json
```

- default threshold: `3`
- default topic: `bitcoin-asmap-quorum`
- default local peer-id: `offline-replay`
- default map output: `asmap.map`
- default report output: `asmap.json`
- pass the agreed epoch explicitly for real rounds; omitting it is mainly for
  offline replays that infer the epoch from the first claim

### `verify`

Validate a JSON consensus report and optionally match a map file.

```bash
verify report.json [mapfile]
```

### `compare`

Compare two JSON consensus reports at prefix level.

```bash
compare report1.json report2.json
```

### `serve`

Run a networked quorum node serving one local ASMap snapshot.

```bash
serve [--threshold N] [--epoch N] [--epoch-secs N] [--topic NAME] [--bootstrap ADDR[,ADDR...]] [--relay ADDR[,ADDR...]] [infile] [outfile]
```

- defaults: threshold `3`, epoch `1`, epoch-secs `60`, topic `bitcoin-asmap-quorum`
- writes consensus map to `outfile` (default `asmap.map`)
- writes matching JSON report beside map with `.json` extension

### `collect`

Run a networked quorum node that periodically fetches RIPE RIS state before publishing claims.

```bash
collect [--threshold N] [--epoch N] [--epoch-secs N] [--refresh-secs N] [--topic NAME] [-n 0,1,2] [--bootstrap ADDR[,ADDR...]] [--relay ADDR[,ADDR...]] [--output FILE]
```

- defaults: threshold `3`, epoch `1`, epoch-secs `60`, refresh-secs `1800`
- default topic: `bitcoin-ris-collection`
- collectors flag aliases: `-n`, `--ripe_collector_number` (long form uses underscores), `--collectors`
- default output map: `ris-asmap.map` (+ `.json` report)

### `download`

Download latest RIPE RIS dumps.

```bash
download [-o OUT] [-n 0,1,2]
```

- `-o, --out`: output directory (default `dump`)
- `-n, --ripe_collector_number`: comma-separated collector ids
- if `-n` is omitted, downloads collectors `0..24`

### `find-bottleneck` / `find_bottleneck`

Extract bottleneck AS mappings from MRT dumps.

```bash
find-bottleneck -d DIR [-o OUT]
```

- `-d, --dir`: input dump directory (required)
- `-o, --out`: output directory; if omitted, writes to stdout
- with `--out`, output file is `bottleneck.<unix-epoch>.txt`

## Typical workflow

```bash
# 1) Convert ASMap text to binary
cargo run -- encode input.txt asmap.map

# 2) Build claims from multiple snapshots
cargo run -- import --epoch 42 --output claims.json snapshot-a.txt snapshot-b.txt

# 3) Replay claims into consensus artifacts
cargo run -- replay --threshold 2 --output consensus.map --report consensus.json claims.json

# 4) Verify report/map consistency
cargo run -- verify consensus.json consensus.map
```
